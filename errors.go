/*
Copyright: Cognition Foundry. All Rights Reserved.
License: Apache License Version 2.0
*/
package gohfc

import "errors"

var (
	ErrInvalidAlgorithmFamily       = errors.New("invalid algorithm family")
	ErrInvalidAlgorithm             = errors.New("invalid algorithm for ECDSA")
	ErrInvalidHash                  = errors.New("invalid hash algorithm")
	ErrInvalidKeyType               = errors.New("invalid key type is provided")
	ErrEnrollmentIdMissing          = errors.New("enrollment id is empty")
	ErrEnrolmentMissing             = errors.New("enrollment ID is missing")
	ErrAffiliationMissing           = errors.New("affiliation is missing")
	ErrTypeMissing                  = errors.New("type is missing")
	ErrCertificateEmpty             = errors.New("certificate cannot be nil")
	ErrInvalidDataForParcelIdentity = errors.New("invalid data for parsing identity")
	ErrInvalidOrdererName           = errors.New("orderer with this name is not found")
	ErrOrdererTimeout               = errors.New("orderer response timeout")
	ErrBadTransactionStatus         = errors.New("transaction status is not 200")
	ErrEndorsementsDoNotMatch       = errors.New("endorsed responses are different")
	ErrNoValidEndorsementFound      = errors.New("invocation was not endorsed")
	ErrPeerNameNotFound             = errors.New("peer name is not found")
	ErrUnsupportedChaincodeType     = errors.New("this chainCode type is not currently supported")
	ErrMspMissing                   = errors.New("mspid cannot be empty")
	ErrCollectionNameMissing        = errors.New("collection must have name")
	ErrCollectionNameExists         = errors.New("collection name must be unique")
	ErrRequiredPeerCountNegative    = errors.New("required peers count cannot be negative")
	ErrMaxPeerCountNegative         = errors.New("required peers count cannot be negative")
	ErrMaxPeerCountLestThanMinimum  = errors.New("maximum peers count cannot be lower than minimum")
	ErrAtLeastOneOrgNeeded          = errors.New("at least one organization is needed")
	ErrOrganizationNameMissing        = errors.New("organization must have name")
	ErrAffiliationNameMissing        = errors.New("affiliation must have name")
	ErrAffiliationNewNameMissing        = errors.New("affiliation must have new name")
	ErrIdentityNameMissing        = errors.New("identity must have  name")
)
