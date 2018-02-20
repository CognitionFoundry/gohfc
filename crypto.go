/*
Copyright: Cognition Foundry. All Rights Reserved.
License: Apache License Version 2.0
*/
package gohfc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"golang.org/x/crypto/sha3"
	"hash"
	"math/big"
	"net"
	"net/mail"
)

// CryptSuite defines common interface for different crypto implementations.
// Currently Hyperledger Fabric supports only Elliptic curves.
type CryptoSuite interface {
	// GenerateKey returns PrivateKey.
	GenerateKey() (interface{}, error)
	// CreateCertificateRequest will create CSR request. It takes enrolmentId and Private key
	CreateCertificateRequest(enrollmentId string, key interface{}, hosts []string) ([]byte, error)
	// Sign signs message. It takes message to sign and Private key
	Sign(msg []byte, key interface{}) ([]byte, error)
	// Hash computes Hash value of provided data. Hash function will be different in different crypto implementations.
	Hash(data []byte) []byte
}

var (
	// precomputed curves half order values for efficiency
	ecCurveHalfOrders = map[elliptic.Curve]*big.Int{
		elliptic.P224(): new(big.Int).Rsh(elliptic.P224().Params().N, 1),
		elliptic.P256(): new(big.Int).Rsh(elliptic.P256().Params().N, 1),
		elliptic.P384(): new(big.Int).Rsh(elliptic.P384().Params().N, 1),
		elliptic.P521(): new(big.Int).Rsh(elliptic.P521().Params().N, 1),
	}
)

// ECCryptSuite implements Ecliptic curve crypto suite
type ECCryptSuite struct {
	curve        elliptic.Curve
	sigAlgorithm x509.SignatureAlgorithm
	key          *ecdsa.PrivateKey
	hashFunction func() hash.Hash
}

type eCDSASignature struct {
	R, S *big.Int
}

func (c *ECCryptSuite) GenerateKey() (interface{}, error) {
	key, err := ecdsa.GenerateKey(c.curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (c *ECCryptSuite) CreateCertificateRequest(enrollmentId string, key interface{}, hosts []string) ([]byte, error) {
	if enrollmentId == "" {
		return nil, ErrEnrollmentIdMissing
	}
	subj := pkix.Name{
		CommonName: enrollmentId,
	}
	rawSubj := subj.ToRDNSequence()

	asn1Subj, err := asn1.Marshal(rawSubj)
	if err != nil {
		return nil, err
	}

	ipAddr := make([]net.IP, 0)
	emailAddr := make([]string, 0)
	dnsAddr := make([]string, 0)

	for i := range hosts {
		if ip := net.ParseIP(hosts[i]); ip != nil {
			ipAddr = append(ipAddr, ip)
		} else if email, err := mail.ParseAddress(hosts[i]); err == nil && email != nil {
			emailAddr = append(emailAddr, email.Address)
		} else {
			dnsAddr = append(dnsAddr, hosts[i])
		}
	}

	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: c.sigAlgorithm,
		IPAddresses:        ipAddr,
		EmailAddresses:     emailAddr,
		DNSNames:           dnsAddr,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return nil, err
	}
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	return csr, nil
}

func (c *ECCryptSuite) Sign(msg []byte, k interface{}) ([]byte, error) {
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, ErrInvalidKeyType
	}
	var h []byte
	h = c.Hash(msg)
	R, S, err := ecdsa.Sign(rand.Reader, key, h)
	if err != nil {
		return nil, err
	}
	c.preventMalleability(key, S)
	sig, err := asn1.Marshal(eCDSASignature{R, S})
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// ECDSA signature can be "exploited" using symmetry of S values.
// Fabric (by convention) accepts only signatures with lowS values
// If result of a signature is high-S value we have to subtract S from curve.N
// For more details https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
func (c *ECCryptSuite) preventMalleability(k *ecdsa.PrivateKey, S *big.Int) {
	halfOrder := ecCurveHalfOrders[k.Curve]
	if S.Cmp(halfOrder) == 1 {
		S.Sub(k.Params().N, S)
	}
}

func (c *ECCryptSuite) Hash(data []byte) []byte {
	h := c.hashFunction()
	h.Write(data)
	return h.Sum(nil)
}

// NewECCryptSuite creates new Elliptic curve crypto suite from config
func NewECCryptSuiteFromConfig(config CryptoConfig) (CryptoSuite, error) {
	var suite *ECCryptSuite
	switch config.Algorithm {
	case "P256-SHA256":
		suite = &ECCryptSuite{curve: elliptic.P256(), sigAlgorithm: x509.ECDSAWithSHA256}
	case "P384-SHA384":
		suite = &ECCryptSuite{curve: elliptic.P384(), sigAlgorithm: x509.ECDSAWithSHA384}
	case "P521-SHA512":
		suite = &ECCryptSuite{curve: elliptic.P521(), sigAlgorithm: x509.ECDSAWithSHA512}
	default:
		return nil, ErrInvalidAlgorithm
	}

	switch config.Hash {

	case "SHA2-256":
		suite.hashFunction = sha256.New
	case "SHA2-384":
		suite.hashFunction = sha512.New384
	case "SHA3-256":
		suite.hashFunction = sha3.New256
	case "SHA3-384":
		suite.hashFunction = sha3.New384
	default:
		return nil, ErrInvalidHash
	}
	return suite, nil
}
