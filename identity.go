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
	"crypto/x509"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/pem"
	"encoding/base64"
	"encoding/json"
)

// Identity is participant identity
type Identity struct {
	*Certificate
	// Identity unique identification
	EnrollmentId string
}

// Certificate contains ECert ot TCert with appropriate private key
type Certificate struct {
	Cert       *x509.Certificate
	PrivateKey interface{}
}

// MarshalIdentity marshal identity to string
func MarshalIdentity(i *Identity) (string, error) {

	var pk, cert string
	switch i.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		cast := i.PrivateKey.(*ecdsa.PrivateKey)
		b, err := x509.MarshalECPrivateKey(cast)
		if err != nil {
			Logger.Errorf("Error marshal private key %s", err)
			return "", err
		}
		block := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
		pk = base64.RawStdEncoding.EncodeToString(block)

	case *rsa.PrivateKey:
		cast := i.PrivateKey.(*rsa.PrivateKey)
		b := x509.MarshalPKCS1PrivateKey(cast)
		block := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: b})
		pk = base64.RawStdEncoding.EncodeToString(block)
	default:
		Logger.Error("Invalid private key")
		return "", ErrInvalidKeyType
	}
	cert = base64.RawStdEncoding.EncodeToString(i.Cert.Raw)
	str, err := json.Marshal(map[string]string{"enrolmentid": i.EnrollmentId, "cert": cert, "pk": pk})
	if err != nil {
		Logger.Errorf("Error marsal identity %s", err)
		return "", err
	}
	return string(str), nil
}

// UnmarshalIdentity unmarshal identity from string
func UnmarshalIdentity(data string) (*Identity, error) {
	var raw map[string]string
	if err := json.Unmarshal([]byte(data), &raw); err != nil {
		Logger.Errorf("Error unmarshal identity %s", err)
		return nil, err
	}
	//check do we have all keys
	if _, ok := raw["enrolmentid"]; !ok || len(raw["enrolmentid"]) < 1 {
		Logger.Error(ErrInvalidDataForParcelIdentity)
		return nil, ErrInvalidDataForParcelIdentity
	}
	if _, ok := raw["cert"]; !ok || len(raw["cert"]) < 1 {
		Logger.Error(ErrInvalidDataForParcelIdentity)
		return nil, ErrInvalidDataForParcelIdentity
	}
	if _, ok := raw["pk"]; !ok || len(raw["pk"]) < 1 {
		Logger.Error(ErrInvalidDataForParcelIdentity)
		return nil, ErrInvalidDataForParcelIdentity
	}

	certRaw, err := base64.RawStdEncoding.DecodeString(raw["cert"])
	if err != nil {
		Logger.Errorf("Error decoding certificate %s", err)
		return nil, err
	}
	cert, err := x509.ParseCertificate(certRaw)
	if err != nil {
		Logger.Errorf("Error parsing certificate %s", err)
		return nil, err
	}

	keyRaw, err := base64.RawStdEncoding.DecodeString(raw["pk"])
	if err != nil {
		Logger.Errorf("Error decoding private key %s", err)
		return nil, err
	}
	keyPem, _ := pem.Decode(keyRaw)
	if keyPem == nil {
		Logger.Errorf("Error parsing private key %s", err)
		return nil, ErrInvalidDataForParcelIdentity
	}
	var pk interface{}
	switch keyPem.Type {
	case "EC PRIVATE KEY":
		pk, err = x509.ParseECPrivateKey(keyPem.Bytes)
		if err != nil {
			Logger.Errorf("Invalid private key %s", err)
			return nil, ErrInvalidDataForParcelIdentity
		}
	case "RSA PRIVATE KEY":
		pk, err = x509.ParsePKCS1PrivateKey(keyPem.Bytes)
		if err != nil {
			Logger.Errorf("Invalid private key %s", err)
			return nil, ErrInvalidDataForParcelIdentity
		}
	default:
		Logger.Errorf("Invalid private key %s", err)
		return nil, ErrInvalidDataForParcelIdentity
	}

	identity := &Identity{EnrollmentId: raw["enrolmentid"], Certificate: &Certificate{Cert: cert, PrivateKey: pk}}
	return identity, nil

}
