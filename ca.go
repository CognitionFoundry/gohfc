/*
Copyright Cognition Foundry / Conquex 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package gohfc

import (
	"net/http"
	"fmt"
	"bytes"
	"encoding/json"
	"io/ioutil"
	"encoding/pem"
	"crypto/x509"
	"crypto/tls"
	"encoding/base64"
	"time"
	"math/big"
	"encoding/asn1"
	"crypto/x509/pkix"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
)

// CAClient is common interface for Certificate authority services.
type CAClient interface {
	// Enroll enrolls user and returns ECert
	Enroll(enrollmentId, password string) (*Identity, error)
	// Register registers new user in fabric-ca server.
	Register(certificate *Certificate, req *RegistrationRequest) (*CAResponse, error)
	// Revoke revokes ECert in fabric-ca server.
	Revoke(certificate *Certificate, request *RevocationRequest) (*CAResponse, error)
	// TCerts makes request to ca server for batch creation of TCerts.
	TCerts(certificate *Certificate) ([]*Certificate, error)
}

// FabricCAClientImpl is client implementation for fabric-ca server
type FabricCAClientImpl struct {
	// Url is access point for fabric-ca server
	Url string
	// SkipTLSVerification define how connection must handle invalid TLC certificates.
	// if true, all verifications are skipped. This value is overwritten by Transport property, if provided
	SkipTLSVerification bool
	// Crypto is CryptSuite implementation used to sign request for fabric-ca server
	Crypto CryptSuite
	// Transport define transport rules for communication with fabric-ca server. If nil, default Go setting will be used
	Transport *http.Transport
}

// RegistrationRequestAttr holds user attribute used for registration
// for example user may have attr `accountType` with value `premium`
// this attributes can be accessed in chaincode and build business logic using them
type RegistrationRequestAttr struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

//RegistrationRequest holds all data needed for new registration of new user in Certificate Authority
type RegistrationRequest struct {
	// EnrolmentId is unique name that identifies identity
	EnrolmentId string `json:"id"`
	// Type defines type of this identity (user,client, auditor etc...)
	Type string  `json:"type"`
	// Secret is password that will be used for enrollment. If not provided random password will be generated
	Secret string `json:"secret,omitempty"`
	// MaxEnrollments define maximum number of times that identity can enroll. If not provided or is 0 there is no limit
	MaxEnrollments int `json:"max_enrollments,omitempty"`
	// Affiliation associates identity with particular organisation.
	// for example org1.department1 makes this identity part of organisation `org1` and department `department1`
	Affiliation string `json:"affiliation"`
	// Attrs are attributes associated with this identity
	Attrs []RegistrationRequestAttr `json:"attrs"`
}

type TCertBatchRequest struct {
	// Number of TCerts in the batch.
	Count int `json:"count"`
	// The attribute names whose names and values are to be sealed in the issued TCerts.
	AttrNames []string `json:"attr_names,omitempty"`
	// EncryptAttrs denotes whether to encrypt attribute values or not.
	// When set to true, each issued tCert in the batch will contain encrypted attribute values.
	EncryptAttrs bool `json:"encrypt_attrs,omitempty"`
	// Certificate Validity Period.  If specified, the value used
	// is the minimum of this value and the configured validity period
	// of the tCert manager.
	ValidityPeriod time.Duration `json:"validity_period,omitempty"`
	// The pre-key to be used for key derivation.
	PreKey string `json:"prekey"`
	// DisableKeyDerivation if true, disables key derivation so that a tCert is not
	// cryptographically related to an ECert.  This may be necessary when using an
	// HSM which does not support the tCert's key derivation function.
	DisableKeyDerivation bool `json:"disable_kdf,omitempty"`
}

// CAResponseErr represents error message from fabric-ca server
type CAResponseErr struct {
	Code    int `json:"code"`
	Message string `json:"message"`
}

// CAResponse represents response message from fabric-ca server
type CAResponse struct {
	Success  bool `json:"success"`
	Result   CARegisterCredentialResponse `json:"result"`
	Errors   []CAResponseErr `json:"errors"`
	Messages []string `json:"messages"`
}

// CARegisterCredentialResponse credentials from fabric-ca server registration request
type CARegisterCredentialResponse struct {
	Credential string `json:"credential"`
}

// RevocationRequest holds data needed to revoke certificate in fabric-ca
type RevocationRequest struct {
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

// certificateRequest holds certificate request that must be signed by fabric-ca
type certificateRequest struct {
	CR string `json:"certificate_request"`
}

// enrollmentResponse is response from fabric-ca server for enrolment that contains created Ecert
type enrollmentResponse struct {
	Success     bool `json:"success"`
	RawResponse string `json:"result"`
	Errors      []CAResponseErr `json:"errors"`
	Messages    []string `json:"messages"`
}

// cATCertsResponse represent response for TCerts generations from fabric-ca server
type cATCertsResponse struct {
	Success  bool `json:"success"`
	Result   tCertsBatch `json:"result"`
	Errors   []CAResponseErr `json:"errors"`
	Messages []string `json:"messages"`
}

// tCertsBatch is response from fabric-ca for creating batch of TCerts
type tCertsBatch struct {
	ID     *big.Int  `json:"id"`
	TS     time.Time `json:"ts"`
	Key    []byte    `json:"key"`
	TCerts []tCert   `json:"tcerts"`
}

// tCert represent single TCert returned from fabric-ca for batch TCerts creation
type tCert struct {
	Cert []byte            `json:"cert"`
	Keys map[string][]byte `json:"keys,omitempty"`
}

// Enroll execute enrollment request for registered user in fabric-ca server. Password must be response from
// registration request. On success new Identity with ECert is returned
func (f *FabricCAClientImpl) Enroll(enrollmentId, password string) (*Identity, error) {
	if len(enrollmentId) < 1 {
		Logger.Error(ErrEnrollmentIdMissing)
		return nil, ErrEnrollmentIdMissing
	}
	//create new cert and send it to CA for signing
	key, err := f.Crypto.GenerateKey()
	if err != nil {
		return nil, err
	}

	csr, err := f.Crypto.CreateCertificateRequest(enrollmentId, key)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/api/v1/cfssl/enroll", f.Url)

	crm, err := json.Marshal(certificateRequest{CR: string(csr)})
	if err != nil {
		Logger.Errorf("Error marshal certificate request %s", err)
		return nil, err
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
		Logger.Errorf("Error connecting to CA %s", err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		Logger.Errorf("Error reading enrolment Response %s", err)
		return nil, err
	}
	enrResp := new(enrollmentResponse)
	if json.Unmarshal(body, enrResp) != nil {
		Logger.Errorf("Error unmarshal CA Response %s", err)
		return nil, err
	}
	if !enrResp.Success {
		Logger.Errorf("User enrolment failed %s", enrResp.Errors)
		return nil, ErrEnrollment
	}
	rawCert, err := base64.StdEncoding.DecodeString(enrResp.RawResponse)
	if err != nil {
		Logger.Errorf("Error encode raw certificate %s", err)
		return nil, err
	}
	a, _ := pem.Decode(rawCert)
	cert, err := x509.ParseCertificate(a.Bytes)
	if err != nil {
		Logger.Errorf("Error parce raw certificate %s", err)
		return nil, err
	}

	return &Identity{EnrollmentId: enrollmentId, Certificate: &Certificate{PrivateKey: key, Cert: cert}}, nil
}

// Register registers new user in fabric-ca server. In registration request attributes, affiliation and
// max enrolments must be set. On success, password will be in CAResponse.Result.Credential
// Certificate parameter is certificate for user that makes registration and this user MUST have ability to register new users.
func (f *FabricCAClientImpl) Register(certificate *Certificate, req *RegistrationRequest) (*CAResponse, error) {

	if err := req.Valid(); err != nil {
		Logger.Errorf("Invalid registration request %s", err)
		return nil, err
	}
	if certificate == nil {
		Logger.Error(ErrCertificateEmpty)
		return nil, ErrCertificateEmpty
	}
	reqJson, err := json.Marshal(req)
	if err != nil {
		Logger.Errorf("Error marshal registration request", err)
		return nil, err
	}
	url := fmt.Sprintf("%s/api/v1/cfssl/register", f.Url)

	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(reqJson))

	httpReq.Header.Set("Content-Type", "application/json")

	token, err := f.createAuthToken(certificate, reqJson)
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
		Logger.Errorf("Error connecting to CA %s", err)
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
	result := new(CAResponse)
	if err := json.Unmarshal(body, result); err != nil {
		Logger.Errorf("Error unmarshal CAResponse %s", err)
		return nil, err
	}
	return result, nil
}

// Revoke revokes ECert in fabric-ca server.
// Note that this request will revoke certificate ONLY in fabric-ca server. Peers (for now) do not know
// about this certificate revocation. Additional request to peers must be made, so they will have this certificate
// in their revoke list.
//TODO notify peers for this revocation.
func (f *FabricCAClientImpl) Revoke(certificate *Certificate, request *RevocationRequest) (*CAResponse, error) {

	reqJson, err := json.Marshal(request)
	if err != nil {
		Logger.Errorf("Error marshal Revoke request", err)
		return nil, err
	}
	url := fmt.Sprintf("%s/api/v1/cfssl/revoke", f.Url)

	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(reqJson))

	httpReq.Header.Set("Content-Type", "application/json")

	token, err := f.createAuthToken(certificate, reqJson)
	if err != nil {
		Logger.Errorf("Error %s", err)
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
		Logger.Errorf("Error connecting to CA %s", err)
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	result := new(CAResponse)
	if err := json.Unmarshal(body, result); err != nil {
		Logger.Errorf("Error unmarshal CAResponse %s", err)
		return nil, err
	}
	return result, nil
}

// TCerts make request to fabric-ca server for batch creation of TCerts. TCerts must contain any or none of the identity
// attributes used in registration.
// TCerts are processed to derive their private keys so anonymity is preserved and are not directly linked
// to identity that creates them
func (f *FabricCAClientImpl) TCerts(certificate *Certificate) ([]*Certificate, error) {
	request := TCertBatchRequest{Count: 1, AttrNames: []string{"hf.Registrar.Roles"}, EncryptAttrs: true}
	reqJson, err := json.Marshal(request)
	if err != nil {
		Logger.Errorf("Error marshal registration request", err)
		return nil, err
	}
	url := fmt.Sprintf("%s/api/v1/cfssl/tcert", f.Url)

	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(reqJson))

	httpReq.Header.Set("Content-Type", "application/json")

	token, err := f.createAuthToken(certificate, reqJson)
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
		Logger.Errorf("Error connecting to CA %s", err)
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	result := new(cATCertsResponse)
	if err := json.Unmarshal(body, result); err != nil {
		Logger.Errorf("Error unmarshal CA Response %s", err)
		return nil, err
	}
	if result.Success == false {
		Logger.Errorf("Error creating Tcerts %s", result.Errors[0].Message)
		return nil, ErrCreatingTCerts
	}
	derivedTCerts := make([]*Certificate, 0, len(result.Result.TCerts))
	for _, rawCert := range result.Result.TCerts {
		cc, _ := pem.Decode(rawCert.Cert)
		tmpCert, err := x509.ParseCertificate(cc.Bytes)
		if err != nil {
			Logger.Errorf("Error parcing Tcert %s", err)
			return nil, err
		}
		derived, err := f.deriveTCPK(certificate, tmpCert, result.Result.Key)
		if err != nil {
			return nil, err
		}
		derivedTCerts = append(derivedTCerts, derived)
	}
	return derivedTCerts, nil

}

// deriveTCPK derives TCert private key
func (f *FabricCAClientImpl) deriveTCPK(certificate *Certificate, cert *x509.Certificate, key []byte) (*Certificate, error) {
	tCertEncTCertIndex := asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7}

	var indexCT pkix.Extension
	for _, v := range cert.Extensions {
		if v.Id.Equal(tCertEncTCertIndex) {
			indexCT = v
			break
		}
	}

	mac := hmac.New(sha512.New384, key)
	mac.Write([]byte{1})
	ownerEncKey := mac.Sum(nil)[:32]

	mac = hmac.New(sha512.New384, key)
	mac.Write([]byte{2})
	expansionKey := mac.Sum(nil)

	TCertIndex, err := f.tCertPKDecrypt(ownerEncKey, indexCT.Value)
	if err != nil {
		return nil, err
	}

	ownerPK := certificate.PrivateKey.(*ecdsa.PrivateKey)
	macc := hmac.New(sha512.New384, expansionKey)
	macc.Write(TCertIndex)
	ExpansionValue := macc.Sum(nil)
	derivedPK := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: ownerPK.Curve,
			X:     new(big.Int),
			Y:     new(big.Int),
		},
		D: new(big.Int),
	}

	var k = new(big.Int).SetBytes(ExpansionValue)
	var one = new(big.Int).SetInt64(1)
	n := new(big.Int).Sub(ownerPK.Curve.Params().N, one)
	k.Mod(k, n)
	k.Add(k, one)

	derivedPK.D.Add(ownerPK.D, k)
	derivedPK.D.Mod(derivedPK.D, ownerPK.Params().N)
	return &Certificate{PrivateKey: derivedPK, Cert: cert}, nil

}

// tCertPKDecrypt decrypts asn1.ObjectIdentifier data from TCerts response that is used for private key derivation.
func (f *FabricCAClientImpl) tCertPKDecrypt(key, src []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		Logger.Errorf("Error creating new AES Chipher: %s", err)
		return nil, err
	}

	if len(src) < aes.BlockSize {
		Logger.Errorf("Chipher length: %d is lover than block size: %d", len(src), aes.BlockSize)
		return nil, ErrCipherLengthShort
	}
	iv := src[:aes.BlockSize]
	src = src[aes.BlockSize:]

	if len(src)%aes.BlockSize != 0 {
		Logger.Errorf("Chipher length: %d is not multiple of block size: %d", len(src), aes.BlockSize)
		return nil, ErrCipherIncorrectLength
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(src, src)
	//remove padding
	length := len(src)
	unPadLength := int(src[length-1])
	if unPadLength > aes.BlockSize || unPadLength == 0 {
		Logger.Error(ErrCipherIncorrectPadding)
		return nil, ErrCipherIncorrectPadding
	}

	pad := src[length-unPadLength:]
	for i := 0; i < unPadLength; i++ {
		if pad[i] != byte(unPadLength) {
			Logger.Error(ErrCipherIncorrectPadding)
			return nil, ErrCipherIncorrectPadding
		}
	}
	return src[:(length - unPadLength)], nil
}

// createAuthToken creates http authorization header token to verify the request.
// it is composed by base64 encoded Cert concatenated by base64 encoded request signed with Cert private key
func (f *FabricCAClientImpl) createAuthToken(certificate *Certificate, request []byte) (string, error) {

	encPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Cert.Raw})
	encCert := base64.StdEncoding.EncodeToString(encPem)
	body := base64.StdEncoding.EncodeToString(request)

	sigString := body + "." + encCert

	sig, err := f.Crypto.CASign([]byte(sigString), certificate.PrivateKey)

	if err != nil {
		Logger.Errorf("Error creating CA token %s", err)
		return "", err
	}
	return fmt.Sprintf("%s.%s", encCert, base64.StdEncoding.EncodeToString(sig)), nil
}

// Valid validates registration request
func (r *RegistrationRequest) Valid() error {
	if r.EnrolmentId == "" {
		return ErrEnrolmentMissing
	}
	if r.Affiliation == "" {
		return ErrAffiliationMissing
	}
	if r.Type == "" {
		return ErrTypeMissing
	}
	return nil
}

// NewFabricCAClientFromConfig creates new FabricCAClientImpl
func NewFabricCAClientFromConfig(config *CAServerConf, crypto CryptSuite, transport *http.Transport) (*FabricCAClientImpl, error) {
	if config.URL == "" {
		Logger.Error("Error creating NewFabricCAClientFromConfig.URL is empty")
		return nil, ErrCAURLMissing
	}
	if crypto == nil {
		Logger.Error("Error creating NewFabricCAClientFromConfig.crypto is nil")
		return nil, ErrCryptoNil
	}
	return &FabricCAClientImpl{SkipTLSVerification: config.SkipTLSValidation,
		Url:                                    config.URL,
		Crypto:                                 crypto,
		Transport:                              transport}, nil
}
