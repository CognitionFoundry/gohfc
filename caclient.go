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
	"net/url"
	"strconv"
)

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
	// Hierarchical structure can be created using .(dot). For example org1.dep1 will create dep1 as part of org1
	Affiliation string `json:"affiliation"`
	// Attrs are attributes associated with this identity
	Attrs []CaRegisterAttribute `json:"attrs"`
	// CAName is the name of the CA that should be used. FabricCa support more than one CA server on same endpoint and
	// this names are used to distinguish between them. If empty default CA instance will be used.
	CAName string `json:"caname,omitempty"`
}

// CaRegisterAttribute holds user attribute used for registration
// for example user may have attr `accountType` with value `premium`
// this attributes can be accessed in chainCode and build business logic on top of them
type CaRegisterAttribute struct {
	// Name is the name of the attribute.
	Name string `json:"name"`
	// Value is the value of the attribute. Can be empty string
	Value string `json:"value"`
	// ECert define how this attribute will be included in ECert. If this value is true this attribute will be
	// added to ECert automatically on Enrollment if no attributes are requested on Enrollment request.
	ECert bool `json:"ecert,omitempty"`
}

// CaEnrollmentRequest holds data needed for getting ECert (enrollment) from CA server
type CaEnrollmentRequest struct {
	// EnrollmentId is the unique entity identifies
	EnrollmentId string
	// Secret is the password for this identity
	Secret string
	// Profile define which CA profile to be used for signing. When this profile is empty default profile is used.
	// This is the common situation when issuing and ECert.
	// If request is fo generating TLS certificates then profile must be `tls`
	// If operation is related to parent CA server then profile must be `ca`
	// In FabricCA custom profiles can be created. In this situation use custom profile name.
	Profile string `json:"profile,omitempty"`
	// Label is used for hardware secure modules.
	Label string `json:"label,omitempty"`
	// CAName is the name of the CA that should be used. FabricCa support more than one CA server on same endpoint and
	// this names are used to distinguish between them. If empty default CA instance will be used.
	CAName string `json:"caname,omitempty"`
	// Host is the list of valid host names for this certificate. If empty default hosts will be used
	Hosts []string `json:"hosts"`
	// Attrs are the attributes that must be included in ECert. This is subset of the attributes used in registration.
	Attrs []CaEnrollAttribute `json:"attr_reqs,omitempty"`
}

// CaReEnrollmentRequest holds data needed for getting new ECert from CA server
type CaReEnrollmentRequest struct {
	Identity *Identity
	// Profile define which CA profile to be used for signing. When this profile is empty default profile is used.
	// This is the common situation when issuing and ECert.
	// If request is fo generating TLS certificates then profile must be `tls`
	// If operation is related to parent CA server then profile must be `ca`
	// In FabricCA custom profiles can be created. In this situation use custom profile name.
	Profile string `json:"profile,omitempty"`
	// Label is used for hardware secure modules.
	Label string `json:"label,omitempty"`
	// CAName is the name of the CA that should be used. FabricCa support more than one CA server on same endpoint and
	// this names are used to distinguish between them. If empty default CA instance will be used.
	CAName string `json:"caname,omitempty"`
	// Host is the list of valid host names for this certificate. If empty default hosts will be used
	Hosts []string `json:"hosts"`
	// Attrs are the attributes that must be included in ECert. This is subset of the attributes used in registration.
	Attrs []CaEnrollAttribute `json:"attr_reqs,omitempty"`
}

// CaEnrollAttribute describe attribute that must be included in enrollment request
type CaEnrollAttribute struct {
	// Name is the name of the attribute
	Name string `json:"name"`
	// Optional define behaviour when required attribute is not available to user. If `true` then request will continue,
	// but attribute will not be included in ECert. If `false` and attribute is missing, request will fail.
	// If false and attribute is available, request will continue and attribute will be added in ECert
	Optional bool `json:"optional,omitempty"`
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
	// CAName is the name of the CA that should be used. FabricCa support more than one CA server on same endpoint and
	// this names are used to distinguish between them. If empty default CA instance will be used.
	CAName string `json:"caname,omitempty"`
	// GenCRL specifies whether to generate a CRL. CRL will be returned only when AKI and Serial are provided.
	GenCRL bool `json:"gencrl,omitempty"`
}

// CAGetCertsResponse holds response from `GetCaCertificateChain`
type CAGetCertsResponse struct {
	// RootCertificates is list of pem encoded certificates
	RootCertificates []*pem.Block
	// IntermediateCertificates is list of pem encoded intermediate certificates
	IntermediateCertificates []*pem.Block
	// CAName is the name of the CA server that returns this certificates
	CAName string
	// Version is the version of server that returns this certificates
	Version string
}

// CAAddAffiliationRequest contains needed data for creating new affiliation
type CAAddAffiliationRequest struct {
	// Name is the name of the affiliation. Hierarchical structure is created using .(dot) like `org1.department1`.
	Name string `json:"name"`
	// Force forces creation of missing parent affiliation. If `force` is false and parent/s is missing error will be returned.
	Force bool `json:"force"`
	// CAName is the name of the CA that should be used. FabricCa support more than one CA server on same endpoint and
	// this names are used to distinguish between them. If empty default CA instance will be used.
	CAName string `json:"caname,omitempty"`
}

// CARemoveAffiliationRequest contains needed data for removing existing affiliation
type CARemoveAffiliationRequest struct {
	// Name is the name of the affiliation to be removed. Dot can be used to specify child like `org1.department1`.
	Name string
	// Force will force removal of child affiliations and any identity associated with them
	Force bool
	// CAName is the name of the CA that should be used. FabricCa support more than one CA server on same endpoint and
	// this names are used to distinguish between them. If empty default CA instance will be used.
	CAName string
}

// CAModifyAffiliationRequest holds data needed to update existing affiliation stored in FabricCa server
type CAModifyAffiliationRequest struct {
	// Name is the name of the affiliation to be updated like `org1.department1`.
	Name string
	// New name is the new name of the affiliation.
	NewName string `json:"name"`
	// Force will force identities using old affiliation to use new affiliation.
	Force bool `json:"force"`
	// CAName is the name of the CA that should be used. FabricCa support more than one CA server on same endpoint and
	// this names are used to distinguish between them. If empty default CA instance will be used.
	CAName string `json:"caname,omitempty"`
}

// CAAffiliationResponse holds response for all operations with affiliation.
type CAAffiliationResponse struct {
	CAAffiliationInfo
	CAName string `json:"caname,omitempty"`
}

// CAAffiliationInfo represent affiliation returned from FabricCA
type CAAffiliationInfo struct {
	// Name is the name of the affiliation
	Name string `json:"name"`
	// Affiliations is list of affiliations that are child to current one
	Affiliations []CAAffiliationInfo `json:"affiliations,omitempty"`
}

// CaRevokeResult is holding result from FabricCA revoke
type CaRevokeResult struct {
	// RevokedCertificates is list of revoked certificates
	RevokedCertificates []CaRevokeResultCertificate `json:"RevokedCerts"`
	// CRL is the certificate revocation list from the operation.
	CRL string `json:"CRL"`
}

// CaRevokeResultCertificate identify revoked certificate
type CaRevokeResultCertificate struct {
	// Serial is revoked certificate serial number
	Serial string `json:"Serial"`
	// AKI is revoked certificate AKI
	AKI string `json:"AKI"`
}

// CAListAllIdentitiesResponse hold response for `ListAllIdentities` call
type CAListAllIdentitiesResponse struct {
	// Name is the name of the affiliation
	CAName string `json:"caname"`
	// Affiliations is list of affiliations that are child to current one
	Identities []CaIdentityResponse `json:"identities,omitempty"`
}

// CAGetIdentityResponse holds response from `GetIdentity` call
type CAGetIdentityResponse struct {
	CaIdentityResponse
	// Name is the name of the affiliation
	CAName string `json:"caname"`
}

// CaIdentityResponse represent identity
type CaIdentityResponse struct {
	ID             string                `json:"id"`
	Type           string                `json:"type"`
	Affiliation    string                `json:"affiliation"`
	Attributes     []CaRegisterAttribute `json:"attrs" mapstructure:"attrs"`
	MaxEnrollments int                   `json:"max_enrollments" mapstructure:"max_enrollments"`
}

// CARemoveIdentityRequest contains needed data for removing existing identity
type CARemoveIdentityRequest struct {
	// Name is the id of the identity to be removed.
	Name string
	// Force will force removal of your own identity
	Force bool
	// CAName is the name of the CA that should be used. FabricCa support more than one CA server on same endpoint and
	// this names are used to distinguish between them. If empty default CA instance will be used.
	CAName string
}

// CAModifyIdentityRequest holds data that will be used to update existing identity
type CAModifyIdentityRequest struct {
	ID             string                `json:"-"`
	Type           string                `json:"type"`
	Affiliation    string                `json:"affiliation"`
	Attributes     []CaRegisterAttribute `json:"attrs"`
	MaxEnrollments int                   `json:"max_enrollments"`
	Secret         string                `json:"secret,omitempty"`
	CAName         string                `json:"caname,omitempty"`
}

// FabricCAClient is client implementation for fabric-ca server
type FabricCAClient struct {
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
	// MspId value will be added to Identity in Enrollment and ReEnrollment invocations.
	// This value is not used anywhere in CA implementation, but is need in every call to Fabric and is added here
	// for convenience, because (in general case) FabricCA is serving one MSP
	// User can overwrite this value at any time.
	MspId string
}

// CAResponse represents response message from fabric-ca server
type caResponse struct {
	Success  bool            `json:"success"`
	Errors   []caResponseErr `json:"errors"`
	Messages []string        `json:"messages"`
}

type caRegisterResponse struct {
	caResponse
	Result caRegisterCredentialResponse `json:"result"`
}

// CARegisterCredentialResponse credentials from fabric-ca server registration request
type caRegisterCredentialResponse struct {
	Secret string `json:"secret"`
}

func (c *caRegisterCredentialResponse) UnmarshalJSON(b []byte) error {
	type tmpStruct struct {
		Secret string `json:"secret"`
	}
	if len(b) > 2 {
		r := new(tmpStruct)
		err := json.Unmarshal(b, r)
		if err != nil {
			return err
		}
		c.Secret = r.Secret
	}
	return nil
}

// CAResponseErr represents error message from fabric-ca server
type caResponseErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// enrollmentResponse is response from fabric-ca server for enrolment that contains created Ecert
type enrollmentResponse struct {
	caResponse
	Result enrollmentResponseResult `json:"result"`
}

type enrollmentResponseResult struct {
	Cert       string
	ServerInfo enrollmentResponseServerInfo
	Version    string
}

func (e *enrollmentResponseResult) UnmarshalJSON(b []byte) error {
	type tmpStruct struct {
		Cert       string
		ServerInfo enrollmentResponseServerInfo
		Version    string
	}
	if len(b) > 2 {
		r := new(tmpStruct)
		err := json.Unmarshal(b, r)
		if err != nil {
			return err
		}
		e.Cert = r.Cert
		e.ServerInfo = r.ServerInfo
		e.Version = r.Version
	}
	return nil
}

type caRevokeResponse struct {
	caResponse
	Result CaRevokeResult `json:"result"`
}

type enrollmentResponseServerInfo struct {
	CAName  string
	CAChain string
}

// certificateRequest holds certificate request that must be signed by fabric-ca
type certificateRequest struct {
	CaEnrollmentRequest
	CR string `json:"certificate_request"`
}

type caInfoRequest struct {
	CaName string `json:"caname,omitempty"`
}

type caInfoResponse struct {
	caResponse
	Result caInfoResponseResult `json:"result"`
}

type caInfoResponseResult struct {
	CAName  string `json:"CAName"`
	CAChain string `json:"CAChain"`
	Version string `json:"Version"`
}

type caAffiliationResponse struct {
	caResponse
	Result CAAffiliationResponse `json:"result"`
}

type caListAllIdentities struct {
	caResponse
	Result CAListAllIdentitiesResponse `json:"result"`
}
type caGetIdentity struct {
	caResponse
	Result CAGetIdentityResponse `json:"result"`
}

// We need this because FabricCa is not consistent with returned (JSON) data types.
// It is possible to have response where instead of JSON object we have empty string and default Unmarshal will fail.
func (c *caInfoResponseResult) UnmarshalJSON(b []byte) error {
	type tmpStruct struct {
		CAName  string `json:"CAName"`
		CAChain string `json:"CAChain"`
		Version string `json:"Version"`
	}
	if len(b) > 2 {
		r := new(tmpStruct)
		err := json.Unmarshal(b, r)
		if err != nil {
			return err
		}
		c.CAName = r.CAName
		c.Version = r.Version
		c.CAChain = r.CAChain
	}
	return nil
}

// Register registers new user in fabric-ca server. In registration request attributes, affiliation and
// max enrolments must be set.
// It is responsibility of the SDK user to ensure passwords are with big entropy.
// Identity parameter is certificate for user that makes registration and this user MUST have the role for
// registering new users.
func (f *FabricCAClient) Register(identity *Identity, req *CARegistrationRequest) (string, error) {

	if req.EnrolmentId == "" {
		return "", ErrEnrolmentMissing
	}
	if req.Affiliation == "" {
		return "", ErrAffiliationMissing
	}
	if req.Type == "" {
		return "", ErrTypeMissing
	}

	if identity == nil {
		return "", ErrCertificateEmpty
	}
	reqJson, err := json.Marshal(req)
	if err != nil {
		return "", err
	}

	httpReq, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/register", f.Url), bytes.NewBuffer(reqJson))

	httpReq.Header.Set("Content-Type", "application/json")

	token, err := f.createAuthToken(identity, reqJson)
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("authorization", token)

	httpClient := &http.Client{Transport: f.getTransport()}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		result := new(caRegisterResponse)
		if err := json.Unmarshal(body, result); err != nil {
			return "", err
		}
		if !result.Success {
			return "", concatErrors(result.Errors)
		}
		if len(result.Errors) > 0 {
			return "", concatErrors(result.Errors)
		}
		return result.Result.Secret, nil
	}
	return "", fmt.Errorf("non 200 response: %v message is: %s", resp.StatusCode, string(body))

}

// Enroll execute enrollment request for registered user in FabricCA server.
// On success new Identity with ECert and generated csr are returned.
func (f *FabricCAClient) Enroll(request CaEnrollmentRequest) (*Identity, []byte, error) {

	// create new cert and send it to CA for signing
	key, err := f.Crypto.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	var hosts []string
	if len(request.Hosts) == 0 {
		parsedUrl, err := url.Parse(f.Url)
		if err != nil {
			return nil, nil, err
		}
		hosts = []string{parsedUrl.Host}
	} else {
		hosts = request.Hosts
	}
	csr, err := f.Crypto.CreateCertificateRequest(request.EnrollmentId, key, hosts)
	if err != nil {
		return nil, nil, err
	}

	crm, err := json.Marshal(certificateRequest{CR: string(csr), CaEnrollmentRequest: request})
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/enroll", f.Url), bytes.NewBuffer(crm))

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(request.EnrollmentId, request.Secret)

	httpClient := &http.Client{Transport: f.getTransport()}
	resp, err := httpClient.Do(req)
	if err != nil {

		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		enrResp := new(enrollmentResponse)
		if err := json.Unmarshal(body, enrResp); err != nil {
			return nil, nil, err
		}
		if !enrResp.Success {
			return nil, nil, concatErrors(enrResp.Errors)
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
		return &Identity{Certificate: cert, PrivateKey: key, MspId: f.MspId}, csr, nil
	}
	return nil, nil, fmt.Errorf("non 200 response: %v message is: %s", resp.StatusCode, string(body))
}

// Revoke revokes ECert in fabric-ca server.
// Note that this request will revoke certificate ONLY in FabricCa server. Peers (for now) do not know
// about this certificate revocation.
// It is responsibility of the SDK user to update peers and set this certificate in every peer revocation list.
func (f *FabricCAClient) Revoke(identity *Identity, request *CARevocationRequest) (*CaRevokeResult, error) {

	reqJson, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/revoke", f.Url), bytes.NewBuffer(reqJson))
	httpReq.Header.Set("Content-Type", "application/json")

	token, err := f.createAuthToken(identity, reqJson)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("authorization", token)

	httpClient := &http.Client{Transport: f.getTransport()}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		result := new(caRevokeResponse)
		if err := json.Unmarshal(body, result); err != nil {
			return nil, err
		}
		if !result.Success {
			return nil, concatErrors(result.Errors)
		}
		return &result.Result, nil
	}
	return nil, fmt.Errorf("non 200 response: %v message is: %s", resp.StatusCode, string(body))

}

// ReEnroll create new certificate from old one. Useful when certificate is about to expire.
// Difference with `Enroll` is that `Enroll` require identity with `Registar` role.
// In re-enrolment the old certificate is used to identify the identity.
func (f *FabricCAClient) ReEnroll(request CaReEnrollmentRequest) (*Identity, []byte, error) {

	if request.Identity == nil || request.Identity.EnrollmentId() == "" {
		return nil, nil, ErrCertificateEmpty
	}

	// create new cert and send it to CA for signing
	key, err := f.Crypto.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	var hosts []string
	if len(request.Hosts) == 0 {
		parsedUrl, err := url.Parse(f.Url)
		if err != nil {
			return nil, nil, err
		}
		hosts = []string{parsedUrl.Host}
	} else {
		hosts = request.Hosts
	}
	csr, err := f.Crypto.CreateCertificateRequest(request.Identity.EnrollmentId(), key, hosts)
	if err != nil {
		return nil, nil, err
	}

	crm, err := json.Marshal(certificateRequest{CR: string(csr), CaEnrollmentRequest: CaEnrollmentRequest{
		Attrs:   request.Attrs,
		Profile: request.Profile,
		CAName:  request.CAName,
		Hosts:   request.Hosts,
		Label:   request.Label,
	}})
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/reenroll", f.Url), bytes.NewBuffer(crm))

	req.Header.Set("Content-Type", "application/json")
	token, err := f.createAuthToken(request.Identity, crm)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("authorization", token)

	httpClient := &http.Client{Transport: f.getTransport()}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		enrResp := new(enrollmentResponse)
		if err := json.Unmarshal(body, enrResp); err != nil {
			return nil, nil, err
		}
		if !enrResp.Success {
			return nil, nil, concatErrors(enrResp.Errors)
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

		return &Identity{Certificate: cert, PrivateKey: key, MspId: f.MspId}, csr, nil
	}
	return nil, nil, fmt.Errorf("non 200 response: %v message is: %s", resp.StatusCode, string(body))
}

// GetCaCertificateChain gets root and intermediate certificates used by FabricCA server.
// This certificates must be presented to Fabric entities (peers, orderers) as MSP so they can verify that request
// are from valid entities.
// caName is the name of the CA that should be used. FabricCa support more than one CA server on same endpoint and
// this names are used to distinguish between them. If empty default CA instance will be used.
func (f *FabricCAClient) GetCaCertificateChain(caName string) (*CAGetCertsResponse, error) {
	reqJson, err := json.Marshal(caInfoRequest{CaName: caName})
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/cainfo", f.Url), bytes.NewBuffer(reqJson))
	httpReq.Header.Set("Content-Type", "application/json")

	httpClient := &http.Client{Transport: f.getTransport()}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		result := new(caInfoResponse)
		if err := json.Unmarshal(body, result); err != nil {
			return nil, err
		}

		if !result.Success {
			return nil, concatErrors(result.Errors)
		}

		certs, err := base64.StdEncoding.DecodeString(result.Result.CAChain)
		if err != nil {
			return nil, err
		}

		var root []*pem.Block
		var intermediate []*pem.Block

		for len(certs) > 0 {
			var block *pem.Block
			block, certs = pem.Decode(certs)
			if block == nil {
				break
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("error parsing certificate from ca chain")

			}

			if !cert.IsCA {
				return nil, fmt.Errorf("invalid certificate in ca chain")
			}

			// If authority key id is not present or if it is present and equal to subject key id,
			// then it is a root certificate
			if len(cert.AuthorityKeyId) == 0 || bytes.Equal(cert.AuthorityKeyId, cert.SubjectKeyId) {
				root = append(root, block)
			} else {
				intermediate = append(intermediate, block)
			}
		}
		return &CAGetCertsResponse{
			RootCertificates:         root,
			IntermediateCertificates: intermediate,
			Version:                  result.Result.Version,
			CAName:                   result.Result.CAName}, nil
	}
	return nil, fmt.Errorf("non 200 response: %v message is: %s", resp.StatusCode, string(body))

}

// ListAffiliations get list of all affiliations registered in FabricCa.
// If `path` is specified result will contains only affiliations "bellow" path, else full tree will be returned.
func (f *FabricCAClient) ListAffiliations(identity *Identity, path string, caName string) (*CAAffiliationResponse, error) {

	if identity == nil {
		return nil, ErrCertificateEmpty
	}
	var uri string
	if len(path) > 0 {
		uri = fmt.Sprintf("%s/api/v1/affiliations/%s", f.Url, path)
	} else {
		uri = fmt.Sprintf("%s/api/v1/affiliations", f.Url)
	}

	httpReq, err := http.NewRequest("GET", uri, bytes.NewBuffer(nil))
	token, err := f.createAuthToken(identity, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("authorization", token)

	if len(caName) > 0 {
		uri := httpReq.URL.Query()
		uri.Add("ca", caName)
		httpReq.URL.RawQuery = uri.Encode()
	}

	httpClient := &http.Client{Transport: f.getTransport()}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		result := new(caAffiliationResponse)
		if err := json.Unmarshal(body, result); err != nil {
			return nil, err
		}
		if !result.Success {
			return nil, concatErrors(result.Errors)
		}
		if len(result.Errors) > 0 {
			return nil, concatErrors(result.Errors)
		}
		return &result.Result, nil
	}
	return nil, fmt.Errorf("non 200 response: %v message is: %s", resp.StatusCode, string(body))
}

// AddAffiliation add new affiliation to FabricCa
func (f *FabricCAClient) AddAffiliation(identity *Identity, req CAAddAffiliationRequest) (*CAAffiliationResponse, error) {

	if identity == nil {
		return nil, ErrCertificateEmpty
	}

	if len(req.Name) == 0 {
		return nil, ErrAffiliationNameMissing
	}

	reqJson, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/affiliations", f.Url), bytes.NewBuffer(reqJson))

	httpReq.Header.Set("Content-Type", "application/json")

	token, err := f.createAuthToken(identity, reqJson)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("authorization", token)

	httpClient := &http.Client{Transport: f.getTransport()}

	uri := httpReq.URL.Query()
	uri.Add("force", strconv.FormatBool(req.Force))
	httpReq.URL.RawQuery = uri.Encode()

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		result := new(caAffiliationResponse)
		if err := json.Unmarshal(body, result); err != nil {
			return nil, err
		}
		if !result.Success {
			return nil, concatErrors(result.Errors)
		}
		if len(result.Errors) > 0 {
			return nil, concatErrors(result.Errors)
		}
		return &result.Result, nil
	}
	return nil, fmt.Errorf("non 200 response: %v message is: %s", resp.StatusCode, string(body))
}

// RemoveAffiliation remove affiliation from FabricCa server. FabricCa server must be configured to allows removal of
// affiliations.
func (f *FabricCAClient) RemoveAffiliation(identity *Identity, req CARemoveAffiliationRequest) (*CAAffiliationResponse, error) {

	if identity == nil {
		return nil, ErrCertificateEmpty
	}

	if len(req.Name) == 0 {
		return nil, ErrAffiliationNameMissing
	}

	httpReq, err := http.NewRequest("DELETE",
		fmt.Sprintf("%s/api/v1/affiliations/%s", f.Url, req.Name),
		bytes.NewBuffer(nil))

	httpReq.Header.Set("Content-Type", "application/json")

	token, err := f.createAuthToken(identity, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("authorization", token)

	httpClient := &http.Client{Transport: f.getTransport()}

	uri := httpReq.URL.Query()
	uri.Add("force", strconv.FormatBool(req.Force))
	uri.Add("ca", req.CAName)
	httpReq.URL.RawQuery = uri.Encode()

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		result := new(caAffiliationResponse)
		if err := json.Unmarshal(body, result); err != nil {
			return nil, err
		}
		if !result.Success {
			return nil, concatErrors(result.Errors)
		}
		if len(result.Errors) > 0 {
			return nil, concatErrors(result.Errors)
		}
		return &result.Result, nil
	}
	return nil, fmt.Errorf("non 200 response: %v message is: %s", resp.StatusCode, string(body))

}

// ModifyAffiliation will modify existing affiliation
func (f *FabricCAClient) ModifyAffiliation(identity *Identity, req CAModifyAffiliationRequest) (*CAAffiliationResponse, error) {

	if identity == nil {
		return nil, ErrCertificateEmpty
	}

	if len(req.Name) == 0 {
		return nil, ErrAffiliationNameMissing
	}

	if len(req.NewName) == 0 {
		return nil, ErrAffiliationNewNameMissing
	}

	reqJson, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest("PUT",
		fmt.Sprintf("%s/api/v1/affiliations/%s", f.Url, req.Name),
		bytes.NewBuffer(reqJson))

	httpReq.Header.Set("Content-Type", "application/json")

	token, err := f.createAuthToken(identity, reqJson)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("authorization", token)

	httpClient := &http.Client{Transport: f.getTransport()}

	uri := httpReq.URL.Query()
	uri.Add("force", strconv.FormatBool(req.Force))
	httpReq.URL.RawQuery = uri.Encode()

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		result := new(caAffiliationResponse)
		if err := json.Unmarshal(body, result); err != nil {
			return nil, err
		}
		if !result.Success {
			return nil, concatErrors(result.Errors)
		}
		if len(result.Errors) > 0 {
			return nil, concatErrors(result.Errors)
		}
		return &result.Result, nil
	}
	return nil, fmt.Errorf("non 200 response: %v message is: %s", resp.StatusCode, string(body))
}

// ListAllIdentities get list of all identities from FabricCa server
func (f *FabricCAClient) ListAllIdentities(identity *Identity, caName string) (*CAListAllIdentitiesResponse, error) {

	if identity == nil {
		return nil, ErrCertificateEmpty
	}

	httpReq, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/identities", f.Url), bytes.NewBuffer(nil))
	token, err := f.createAuthToken(identity, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("authorization", token)

	if len(caName) > 0 {
		uri := httpReq.URL.Query()
		uri.Add("ca", caName)
		httpReq.URL.RawQuery = uri.Encode()
	}

	httpClient := &http.Client{Transport: f.getTransport()}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		result := new(caListAllIdentities)
		if err := json.Unmarshal(body, result); err != nil {
			return nil, err
		}
		if !result.Success {
			return nil, concatErrors(result.Errors)
		}
		if len(result.Errors) > 0 {
			return nil, concatErrors(result.Errors)
		}
		return &result.Result, nil
	}
	return nil, fmt.Errorf("non 200 response: %v message is: %s", resp.StatusCode, string(body))
}

// GetIdentity get single identity defined by `id` from FabricCa server
func (f *FabricCAClient) GetIdentity(identity *Identity, id string, caName string) (*CAGetIdentityResponse, error) {

	if identity == nil {
		return nil, ErrCertificateEmpty
	}

	if len(id) == 0 {
		return nil, ErrIdentityNameMissing
	}

	httpReq, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/identities/%s", f.Url, id), bytes.NewBuffer(nil))
	token, err := f.createAuthToken(identity, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("authorization", token)

	if len(caName) > 0 {
		uri := httpReq.URL.Query()
		uri.Add("ca", caName)
		httpReq.URL.RawQuery = uri.Encode()
	}

	httpClient := &http.Client{Transport: f.getTransport()}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		result := new(caGetIdentity)
		if err := json.Unmarshal(body, result); err != nil {
			return nil, err
		}
		if !result.Success {
			return nil, concatErrors(result.Errors)
		}
		if len(result.Errors) > 0 {
			return nil, concatErrors(result.Errors)
		}
		return &result.Result, nil
	}
	return nil, fmt.Errorf("non 200 response: %v message is: %s", resp.StatusCode, string(body))
}

// RemoveIdentity remove identity fromFabricCA. FabricCA must be configured to allow this operation
func (f *FabricCAClient) RemoveIdentity(identity *Identity, req CARemoveIdentityRequest) (*CAGetIdentityResponse, error) {

	if identity == nil {
		return nil, ErrCertificateEmpty
	}

	if len(req.Name) == 0 {
		return nil, ErrAffiliationNameMissing
	}

	httpReq, err := http.NewRequest("DELETE",
		fmt.Sprintf("%s/api/v1/identities/%s", f.Url, req.Name),
		bytes.NewBuffer(nil))

	httpReq.Header.Set("Content-Type", "application/json")

	token, err := f.createAuthToken(identity, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("authorization", token)

	httpClient := &http.Client{Transport: f.getTransport()}

	uri := httpReq.URL.Query()
	uri.Add("force", strconv.FormatBool(req.Force))
	uri.Add("ca", req.CAName)
	httpReq.URL.RawQuery = uri.Encode()

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		result := new(caGetIdentity)
		if err := json.Unmarshal(body, result); err != nil {
			return nil, err
		}
		if !result.Success {
			return nil, concatErrors(result.Errors)
		}
		if len(result.Errors) > 0 {
			return nil, concatErrors(result.Errors)
		}
		return &result.Result, nil
	}
	return nil, fmt.Errorf("non 200 response: %v message is: %s", resp.StatusCode, string(body))

}

// ModifyIdentity will update existing identity
func (f *FabricCAClient) ModifyIdentity(identity *Identity, req CAModifyIdentityRequest) (*CAGetIdentityResponse, error) {

	if identity == nil {
		return nil, ErrCertificateEmpty
	}

	reqJson, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest("PUT",
		fmt.Sprintf("%s/api/v1/identities/%s", f.Url, req.ID),
		bytes.NewBuffer(reqJson))

	httpReq.Header.Set("Content-Type", "application/json")

	token, err := f.createAuthToken(identity, reqJson)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("authorization", token)

	httpClient := &http.Client{Transport: f.getTransport()}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		result := new(caGetIdentity)
		if err := json.Unmarshal(body, result); err != nil {
			return nil, err
		}
		if !result.Success {
			return nil, concatErrors(result.Errors)
		}
		if len(result.Errors) > 0 {
			return nil, concatErrors(result.Errors)
		}
		return &result.Result, nil
	}
	return nil, fmt.Errorf("non 200 response: %v message is: %s", resp.StatusCode, string(body))
}

// createAuthToken creates http authorization header token to verify the request.
// it is composed by base64 encoded Cert concatenated by base64 encoded request signed with Cert private key
func (f *FabricCAClient) createAuthToken(identity *Identity, request []byte) (string, error) {

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

func (f *FabricCAClient) getTransport() *http.Transport {
	var tr *http.Transport
	if f.Transport == nil {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: f.SkipTLSVerification},
		}
	} else {
		tr = f.Transport
	}
	return tr
}

// helper function to concat multiple errors that can be returned from FabricCA as one error
func concatErrors(errs []caResponseErr) (error) {
	errors := ""
	for _, e := range errs {
		errors += e.Message + ": "
	}
	return fmt.Errorf(errors)
}

// NewCaClientFromConfig creates new FabricCAClient from CAConfig
func NewCaClientFromConfig(config CAConfig, transport *http.Transport) (*FabricCAClient, error) {

	var crypto CryptoSuite
	var err error
	switch config.CryptoConfig.Family {
	case "ecdsa":
		crypto, err = NewECCryptSuiteFromConfig(config.CryptoConfig)
		if err != nil {
			return nil, err
		}
	default:
		return nil, ErrInvalidAlgorithmFamily
	}

	return &FabricCAClient{SkipTLSVerification: config.SkipTLSValidation,
		Url: config.Uri,
		Crypto: crypto,
		Transport: transport,
		MspId: config.MspId}, nil
}

// NewFabricCAClient creates new FabricCAClient from configuration file
// path is the file path for configuration file
// transport is the transport that will be used in all requests. If transport is nil default transport will be used.
// It is responsibility of the SDK user to provide correct settings and TLS certificates if custom transport is provided.
func NewCAClient(path string, transport *http.Transport) (*FabricCAClient, error) {
	config, err := NewCAConfig(path)
	if err != nil {
		return nil, err
	}
	return NewCaClientFromConfig(*config, transport)
}
