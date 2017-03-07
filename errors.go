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

import "errors"

var (
	ErrInvalidAlgorithm             = errors.New("Invalid algorithm for ECDSA")
	ErrInvalidHash                  = errors.New("Invalid hash algorithm")
	ErrInvalidKeyType               = errors.New("Invalid key type is provided")
	ErrEnrollment                   = errors.New("User enrollment failed")
	ErrEnrollmentIdMissing          = errors.New("Enrollment id is empty")
	ErrCryptoNil                    = errors.New("Crypto suite cannot be nil")
	ErrEnrolmentMissing             = errors.New("Enrollment ID is missing")
	ErrAffiliationMissing           = errors.New("Affiliation is missing")
	ErrTypeMissing                  = errors.New("Type is missing")
	ErrNoValidEndorsementFound      = errors.New("Invocation was not endorced")
	ErrChannelNameEmpty             = errors.New("Channel name cannot be empty")
	ErrChainCodeNameEmpty           = errors.New("Chaincode name cannot be empty")
	ErrMspIdEmpty                   = errors.New("Msp Id  cannot be empty")
	ErrCertificateEmpty             = errors.New("Certificate cannot be nil")
	ErrInvalidDataForParcelIdentity = errors.New("Invalid data for parsing identity")
	ErrCAURLMissing                 = errors.New("CA url cannot be empty")
	ErrInvalidChaincodeType         = errors.New("Invalid chancode type")
	ErrChaincodeVersionEmpty        = errors.New("Chaincode version cannot be empty")
	ErrChaincodeNamespaceEmpty      = errors.New("Namespace cannot be empty")
	ErrChaincodeSrcEmpty            = errors.New("Chaincode source cannot be empty")
	ErrReadChaincodeSrc             = errors.New("Error reading source")
	ErrChaincodeSrcNotDir           = errors.New("Chaincode source must be directory")
	ErrInstallRequestNil            = errors.New("Install request cannot be nil")
	ErrBadTransactionStatus         = errors.New("Transaction status is not 200")
	ErrCipherLengthShort            = errors.New("Cipher lenght is lower than block size")
	ErrCipherIncorrectLength        = errors.New("Cipher lenght is not mutiple of block size")
	ErrCipherIncorrectPadding       = errors.New("Cipher has incorect padding")
	ErrCreatingTCerts               = errors.New("Error creating Tcerts")
)
