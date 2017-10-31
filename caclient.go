/*
Copyright: Cognition Foundry. All Rights Reserved.
License: Apache License Version 2.0
*/

package gohfc

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
)

// CAClient is common interface for Certificate authority services.
type CAClient interface {
	// Enroll enrolls user and returns ECert,CSR used for certificate and error
	Enroll(enrollmentId, password string) (*Identity, []byte, error)
	// Register registers new user in fabric-ca server.
	Register(identity *Identity, req *CARegistrationRequest) (*CAResponse, error)
	// Revoke revokes ECert in fabric-ca server.
	Revoke(identity *Identity, req *CARevocationRequest) (*CAResponse, error)
	// ReEnroll create new certificate from old (valid) one.
	ReEnroll(identity *Identity) (*Identity, error)
}

// RegistrationRequest holds all data needed for new registration of new user in Certificate Authority
type CARegistrationRequest struct {
	// EnrolmentId is unique name that identifies identity
	EnrolmentId string `json:"id"`
	// Type defines type of this identity (user,client, auditor etc...)
	Type string `json:"type"`
	// Secret is password that will be used for enrollment. If not provided random password will be generated
	Secret string `json:"secret,omitempty"`
	// MaxEnrollments define maximum number of times that identity can enroll. If not provided or is 0 there is no limit
	MaxEnrollments int `json:"max_enrollments,omitempty"`
	// Affiliation associates identity with particular organisation.
	// for example org1.department1 makes this identity part of organisation `org1` and department `department1`
	Affiliation string `json:"affiliation"`
	// Attrs are attributes associated with this identity
	Attrs []*CARegistrationRequestAttr `json:"attrs"`
}

// CARegistrationRequestAttr holds user attribute used for registration
// for example user may have attr `accountType` with value `premium`
// this attributes can be accessed in chainCode and build business logic on top of them
type CARegistrationRequestAttr struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// CARevocationRequest holds data needed to revoke certificate in fabric-ca
// If AKI and Serial are provided this will revoke specific certificate.
// If EnrolmentID is provided all certificated for this EnrollmentID will be revoked and all his/hers future attempts
// to enroll will fail.
type CARevocationRequest struct {
	// EnrollmentId of the identity whose certificates should be revoked
	// If this field is omitted, then Serial and AKI must be specified.
	EnrollmentId string `json:"id,omitempty"`
	// Serial number of the certificate to be revoked
	// If this is omitted, then EnrollmentId must be specified
	Serial string `json:"serial,omitempty"`
	// AKI (Authority Key Identifier) of the certificate to be revoked
	AKI string `json:"aki,omitempty"`
	// Reason is the reason for revocation.  See https://godoc.org/golang.org/x/crypto/ocsp for
	// valid values.  The default value is 0 (ocsp.Unspecified).
	Reason int `json:"reason,omitempty"`
}

// CAResponse represents response message from fabric-ca server
type CAResponse struct {
	Success  bool                         `json:"success"`
	Result   CARegisterCredentialResponse `json:"result"`
	Errors   []CAResponseErr              `json:"errors"`
	Messages []string                     `json:"messages"`
}

// CARegisterCredentialResponse credentials from fabric-ca server registration request
type CARegisterCredentialResponse struct {
	Secret string `json:"secret"`
}

// CAResponseErr represents error message from fabric-ca server
type CAResponseErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// certificateRequest holds certificate request that must be signed by fabric-ca
type CertificateRequest struct {
	CR string `json:"certificate_request"`
}

// FabricCAClientImpl is client implementation for fabric-ca server
type FabricCAClientImpl struct {
	// Uri is access point for fabric-ca server. Port number and scheme must be provided.
	// for example http://127.0.0.1:7054
	Url string
	// SkipTLSVerification define how connection must handle invalid TLC certificates.
	// if true, all verifications are skipped. This value is overwritten by Transport property, if provided
	SkipTLSVerification bool
	// Crypto is CryptSuite implementation used to sign request for fabric-ca server
	Crypto CryptoSuite
	// Transport define transport rules for communication with fabric-ca server. If nil, default Go setting will be used
	// It is responsibility of the user to provide proper TLS/certificate setting in TLS communication.
	Transport *http.Transport
}

// enrollmentResponse is response from fabric-ca server for enrolment that contains created Ecert
type enrollmentResponse struct {
	Success  bool                     `json:"success"`
	Result   enrollmentResponseResult `json:"result"`
	Errors   []CAResponseErr          `json:"errors"`
	Messages []string                 `json:"messages"`
}

type enrollmentResponseResult struct {
	Cert       string
	ServerInfo enrollmentResponseServerInfo
}

type enrollmentResponseServerInfo struct {
	CAName  string
	CAChain string
}

// Register registers new user in fabric-ca server. In registration request attributes, affiliation and
// max enrolments must be set. On success, password will be in CAResponse.Result.Credential.
// If password is not provided, random secret will be generated.
// It is responsibility of the SDK user to ensure passwords are with big entropy.
// Certificate parameter is certificate for user that makes registration and this user MUST have the role for
// registering new users.
func (f *FabricCAClientImpl) Register(identity *Identity, req *CARegistrationRequest) (*CAResponse, error) {

	if req.EnrolmentId == "" {
		return nil, ErrEnrolmentMissing
	}
	if req.Affiliation == "" {
		return nil, ErrAffiliationMissing
	}
	if req.Type == "" {
		return nil, ErrTypeMissing
	}

	if identity == nil {
		return nil, ErrCertificateEmpty
	}
	reqJson, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/api/v1/register", f.Url)

	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(reqJson))

	httpReq.Header.Set("Content-Type", "application/json")

	token, err := f.createAuthToken(identity, reqJson)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("authorization", token)
	var tr *http.Transport
	if f.Transport == nil {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: f.SkipTLSVerification},
		}
	} else {
		tr = f.Transport
	}
	httpClient := &http.Client{Transport: tr}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	result := new(CAResponse)
	if err := json.Unmarshal(body, result); err != nil {
		return nil, err
	}
	return result, nil
}

// Enroll execute enrollment request for registered user in fabric-ca server.
// On success new Identity with ECert is returned
func (f *FabricCAClientImpl) Enroll(enrollmentId, password string) (*Identity, []byte, error) {
	if len(enrollmentId) < 1 {
		return nil, nil, ErrEnrollmentIdMissing
	}
	// create new cert and send it to CA for signing
	key, err := f.Crypto.GenerateKey()
	if err != nil {
		return nil, nil, err
	}

	csr, err := f.Crypto.CreateCertificateRequest(enrollmentId, key)
	if err != nil {
		return nil, nil, err
	}
	url := fmt.Sprintf("%s/api/v1/enroll", f.Url)

	crm, err := json.Marshal(CertificateRequest{CR: string(csr)})
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(crm))

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(enrollmentId, password)
	var tr *http.Transport
	if f.Transport == nil {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: f.SkipTLSVerification},
		}
	} else {
		tr = f.Transport
	}

	httpClient := &http.Client{Transport: tr}
	resp, err := httpClient.Do(req)
	if err != nil {

		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {

		return nil, nil, err
	}
	enrResp := new(enrollmentResponse)
	if err := json.Unmarshal(body, enrResp); err != nil {

		return nil, nil, err
	}
	if !enrResp.Success {

		return nil, nil, ErrEnrollment
	}
	rawCert, err := base64.StdEncoding.DecodeString(enrResp.Result.Cert)
	if err != nil {

		return nil, nil, err
	}
	a, _ := pem.Decode(rawCert)
	cert, err := x509.ParseCertificate(a.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return &Identity{Certificate: cert, PrivateKey: key}, csr, nil
}

// Revoke revokes ECert in fabric-ca server.
// Note that this request will revoke certificate ONLY in fabric-ca server. Peers (for now) do not know
// about this certificate revocation.
// It is responsibility of the SDK user to update peers and set this certificate in every peer revocation list.
func (f *FabricCAClientImpl) Revoke(identity *Identity, request *CARevocationRequest) (*CAResponse, error) {

	reqJson, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/api/v1/revoke", f.Url)
	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(reqJson))
	httpReq.Header.Set("Content-Type", "application/json")

	token, err := f.createAuthToken(identity, reqJson)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("authorization", token)
	var tr *http.Transport
	if f.Transport == nil {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: f.SkipTLSVerification},
		}
	} else {
		tr = f.Transport
	}
	httpClient := &http.Client{Transport: tr}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	result := new(CAResponse)
	if err := json.Unmarshal(body, result); err != nil {
		return nil, err
	}
	return result, nil
}


// ReEnroll create new certificate from old one. Useful when certificate is about to expire. Attributes are preserved.
func (f *FabricCAClientImpl) ReEnroll(identity *Identity) (*Identity, error) {

	if identity == nil || identity.EnrollmentId() == "" {
		return nil, ErrCertificateEmpty
	}

	// create new cert and send it to CA for signing
	key, err := f.Crypto.GenerateKey()
	if err != nil {
		return nil, err
	}

	csr, err := f.Crypto.CreateCertificateRequest(identity.EnrollmentId(), key)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/api/v1/reenroll", f.Url)

	crm, err := json.Marshal(CertificateRequest{CR: string(csr)})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(crm))

	req.Header.Set("Content-Type", "application/json")
	token, err := f.createAuthToken(identity, crm)
	if err != nil {
		return nil, err
	}
	req.Header.Set("authorization", token)
	var tr *http.Transport
	if f.Transport == nil {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: f.SkipTLSVerification},
		}
	} else {
		tr = f.Transport
	}

	httpClient := &http.Client{Transport: tr}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	enrResp := new(enrollmentResponse)
	if err := json.Unmarshal(body, enrResp); err != nil {
		return nil, err
	}
	if !enrResp.Success {
		return nil, ErrEnrollment
	}
	rawCert, err := base64.StdEncoding.DecodeString(enrResp.Result.Cert)
	if err != nil {
		return nil, err
	}
	a, _ := pem.Decode(rawCert)
	cert, err := x509.ParseCertificate(a.Bytes)
	if err != nil {
		return nil, err
	}

	return &Identity{Certificate: cert, PrivateKey: key}, nil
}

// createAuthToken creates http authorization header token to verify the request.
// it is composed by base64 encoded Cert concatenated by base64 encoded request signed with Cert private key
func (f *FabricCAClientImpl) createAuthToken(identity *Identity, request []byte) (string, error) {

	encPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: identity.Certificate.Raw})
	encCert := base64.StdEncoding.EncodeToString(encPem)
	body := base64.StdEncoding.EncodeToString(request)
	sigString := body + "." + encCert
	sig, err := f.Crypto.Sign([]byte(sigString), identity.PrivateKey)

	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%s", encCert, base64.StdEncoding.EncodeToString(sig)), nil
}

// NewFabricCAClient creates new FabricCAClientImpl
func NewCAClient(path string, transport *http.Transport) (CAClient, error) {
	config,err:=NewCAConfig(path)
	if err!=nil{
		return nil,err
	}

	var crypto CryptoSuite

	switch config.CryptoConfig.Family {
	case "ecdsa":
		crypto, err = NewECCryptSuiteFromConfig(config.CryptoConfig)
		if err != nil {
			return nil, err
		}
	default:
		return nil, ErrInvalidAlgorithmFamily
	}

	return &FabricCAClientImpl{SkipTLSVerification: config.SkipTLSValidation,
		Url:       config.Uri,
		Crypto:    crypto,
		Transport: transport}, nil

}
