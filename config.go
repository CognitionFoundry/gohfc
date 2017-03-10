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
	"os"
	"encoding/json"
)

// CAServerConf is configuration for CA server
type CAServerConf struct {
	URL               string `json:"url"`
	SkipTLSValidation bool `json:"skipTLSValidation"`
}

// OrdererConf is configuration for single orderer
type OrdererConf struct {
	// URL is access point for orderer
	URL string `json:"url"`
	// Name is arbitrary name. Must be unique in all orderers
	Name string `json:"name"`
	// Insecure defines how communication to orderer must be executed. If value is true all TLS validations will be skipped
	Insecure bool `json:"insecure"`
}

// PeerConf is configuration for single peer
type PeerConf struct {
	// URL is access point for peer
	URL string `json:"url"`
	// Name is arbitrary name. Must be unique in all peers
	Name string `json:"name"`
	// Insecure defines how communication to peer must be executed. If value is true all TLS validations will be skipped
	Insecure bool `json:"insecure"`
}

// CryptConfig is configuration CryptSuite
type CryptConfig struct {
	// AsymmetricAlgoFamily define crypto family that will be used (ECDSA, RSA)
	AsymmetricAlgoFamily string `json:"asymmetricAlgoFamily"`
	// AsymmetricAlgo is "algorihm" that wil lbe used (P256-SHA256,P384-SHA384...)
	AsymmetricAlgo string `json:"asymmetricAlgo"`
	// HashFamily defines hash algorithm (SHA2,SHA3)
	HashFamily string `json:"hashFamily"`
	// HashLevel hash level (256,384)
	HashLevel int `json:"hashLevel"`
}

// Config combines configurations for CA,Crypto,Peers,Orderers and Events
type Config struct {
	CAServer  CAServerConf `json:"caServer"`
	Orderers  []OrdererConf `json:"orderers"`
	Peers     []PeerConf `json:"peers"`
	EventPeer PeerConf `json:"eventPeer"`
	Crypt     CryptConfig `json:"crypt"`
}

// NewConfigFromJSON creates new Config from json file
func NewConfigFromJSON(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(file)
	config := new(Config)
	err = decoder.Decode(config)
	if err != nil {
		return nil, err
	}
	return config, nil
}
