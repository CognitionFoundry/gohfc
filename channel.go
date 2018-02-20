/*
Copyright: Cognition Foundry. All Rights Reserved.
License: Apache License Version 2.0
*/
package gohfc

import (
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/protos/common"
	"io/ioutil"
	"fmt"
)

const LSCC = "lscc"
const QSCC = "qscc"
const CSCC = "cscc"

// QueryChannelsResponse holds the result from querying which channels peer is currently joined
type QueryChannelsResponse struct {
	PeerName string
	Error    error
	Channels []string
}

// QueryChannelInfoResponse hold the response for querying channel info from particular peer
type QueryChannelInfoResponse struct {
	PeerName string
	Error    error
	Info     *common.BlockchainInfo
}
// decodeChannelFromFs reads channel.tx file from file system and decode it in Envelope structure
func decodeChannelFromFs(path string) (*common.Envelope, error) {
	channel, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	envelope := new(common.Envelope)
	if err := proto.Unmarshal(channel, envelope); err != nil {
		return nil, err
	}
	return envelope, nil
}

// buildAndSignChannelConfig take channel config payload and prepare the structure need for join transaction
func buildAndSignChannelConfig(identity Identity, configPayload []byte, crypto CryptoSuite,channelId string) (*common.Envelope, error) {

	pl := &common.Payload{}
	if err := proto.Unmarshal(configPayload, pl); err != nil {
		return nil, fmt.Errorf("envelope does not carry a valid payload: %s", err)
	}

	configUpdateEnvelope := &common.ConfigUpdateEnvelope{}
	err := proto.Unmarshal(pl.GetData(), configUpdateEnvelope)
	if err != nil {
		return nil, err
	}
	creator, err := marshalProtoIdentity(identity)
	if err != nil {
		return nil, err
	}
	txId, err := newTransactionId(creator)
	if err != nil {
		return nil, err
	}

	sigHeaderBytes, err := signatureHeader(creator, txId)
	if err != nil {
		return nil, err
	}

	sig, err := crypto.Sign(append(sigHeaderBytes, configUpdateEnvelope.GetConfigUpdate()...), identity.PrivateKey)
	if err != nil {
		return nil, err
	}

	configSignature := new(common.ConfigSignature)
	configSignature.SignatureHeader = sigHeaderBytes
	configSignature.Signature = sig
	configUpdateEnvelope.Signatures = append(configUpdateEnvelope.GetSignatures(), configSignature)

	channelHeaderBytes, err := channelHeader(common.HeaderType_CONFIG_UPDATE, txId, channelId,0,nil)
	header := header(sigHeaderBytes, channelHeaderBytes)

	envelopeBytes, err := proto.Marshal(configUpdateEnvelope)
	if err != nil {
		return nil, err
	}
	commonPayload, err := payload(header, envelopeBytes)
	if err != nil {
		return nil, err
	}
	signedCommonPayload, err := crypto.Sign(commonPayload, identity.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &common.Envelope{Payload: commonPayload, Signature: signedCommonPayload }, nil
}
