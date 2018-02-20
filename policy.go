/*
Copyright: Cognition Foundry. All Rights Reserved.
License: Apache License Version 2.0
*/
package gohfc

import (
	"fmt"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/msp"
	"github.com/golang/protobuf/proto"
	"sort"
)

func defaultPolicy(mspid string) (*common.SignaturePolicyEnvelope, error) {
	if len(mspid) == 0 {
		return nil, ErrMspMissing
	}
	memberRole, err := proto.Marshal(&msp.MSPRole{Role: msp.MSPRole_MEMBER, MspIdentifier: mspid})
	if err != nil {
		return nil, fmt.Errorf("Error marshal MSPRole: %s", err)
	}
	onePrn := &msp.MSPPrincipal{
		PrincipalClassification: msp.MSPPrincipal_ROLE,
		Principal:               memberRole,
	}
	signedBy := &common.SignaturePolicy{Type: &common.SignaturePolicy_SignedBy{SignedBy: 0}}
	oneOfone := &common.SignaturePolicy{
		Type: &common.SignaturePolicy_NOutOf_{
			NOutOf: &common.SignaturePolicy_NOutOf{
				N: 1, Rules: []*common.SignaturePolicy{signedBy},
			},
		},
	}
	p := &common.SignaturePolicyEnvelope{
		Version:    0,
		Rule:       oneOfone,
		Identities: []*msp.MSPPrincipal{onePrn},
	}
	return p, nil
}

func CollectionConfigToPolicy(col []CollectionConfig) ([]*common.CollectionConfig, error) {
	// validation. Same names are not allowed, min/max peer count must be =>0, at least one org
	collectionNames := make(map[string]bool)
	for _, c := range col {
		if len(c.Name) < 1 {
			return nil, ErrCollectionNameMissing
		}
		if _, ok := collectionNames[c.Name]; ok {
			return nil, ErrCollectionNameExists
		}

		if c.RequiredPeersCount < 0 {
			return nil, ErrRequiredPeerCountNegative
		}

		if c.MaximumPeersCount < 0 {
			return nil, ErrMaxPeerCountNegative
		}

		if c.MaximumPeersCount < c.RequiredPeersCount {
			return nil, ErrMaxPeerCountLestThanMinimum
		}
		if len(c.Organizations) == 0 {
			return nil, ErrAtLeastOneOrgNeeded
		}

		for _, org := range c.Organizations {
			if len(org) == 0 {
				return nil, ErrOrganizationNameMissing
			}
		}
		collectionNames[c.Name] = true
	}

	result := make([]*common.CollectionConfig, 0, len(col))
	for _, c := range col {
		sig, err := signedByAnyOfGivenRole(msp.MSPRole_MEMBER, c.Organizations)
		if err != nil {
			return nil, err
		}
		collection := &common.CollectionConfig{
			Payload: &common.CollectionConfig_StaticCollectionConfig{
				StaticCollectionConfig: &common.StaticCollectionConfig{
					Name:              c.Name,
					RequiredPeerCount: c.RequiredPeersCount,
					MaximumPeerCount:  c.MaximumPeersCount,
					MemberOrgsPolicy: &common.CollectionPolicyConfig{
						Payload: &common.CollectionPolicyConfig_SignaturePolicy{
							SignaturePolicy: sig,
						},
					},
				},
			},
		}
		result = append(result, collection)
	}
	return result, nil
}

func signedByAnyOfGivenRole(role msp.MSPRole_MSPRoleType, ids []string) (*common.SignaturePolicyEnvelope, error) {
	sort.Strings(ids)
	principals := make([]*msp.MSPPrincipal, len(ids))
	sigspolicy := make([]*common.SignaturePolicy, len(ids))
	for i, id := range ids {
		marshalPrincipal, err := proto.Marshal(&msp.MSPRole{Role: role, MspIdentifier: id})
		if err != nil {
			return nil, err
		}
		principals[i] = &msp.MSPPrincipal{
			PrincipalClassification: msp.MSPPrincipal_ROLE,
			Principal:               marshalPrincipal}
		sigspolicy[i] = &common.SignaturePolicy{
			Type: &common.SignaturePolicy_SignedBy{
				SignedBy: int32(i),
			},
		}
	}
	p := &common.SignaturePolicyEnvelope{
		Version: 0,
		Rule: &common.SignaturePolicy{
			Type: &common.SignaturePolicy_NOutOf_{
				NOutOf: &common.SignaturePolicy_NOutOf{
					N:     1,
					Rules: sigspolicy,
				},
			},
		},
		Identities: principals,
	}
	return p, nil
}
