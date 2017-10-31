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
)

func defaultPolicy(mspid string) (*common.SignaturePolicyEnvelope, error) {
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
