/*
Copyright: Cognition Foundry. All Rights Reserved.
License: Apache License Version 2.0
*/
package gohfc

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"time"

	"encoding/json"

	"context"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/msp"
	"github.com/hyperledger/fabric/protos/peer"
)

// TransactionId represents transaction identifier. TransactionId is the unique transaction number.
type TransactionId struct {
	Nonce         []byte
	TransactionId string
	Creator       []byte
}

// QueryResponse represent result from query operation
type QueryResponse struct {
	PeerName string
	Error    error
	Response *peer.ProposalResponse
}

// InvokeResponse represent result from invoke operation. Please note that this is the result of simulation,
// not the result of actual block commit.
type InvokeResponse struct {
	Status common.Status
	// TxID is transaction id. This id can be used to track transactions and their status
	TxID string
}

// QueryTransactionResponse holds data from `client.QueryTransaction`
type QueryTransactionResponse struct {
	PeerName string
	Error    error
	Status   int32
	Message  string
	Payload  json.RawMessage
}

type transactionProposal struct {
	proposal      []byte
	transactionId string
}

// marshalProtoIdentity creates SerializedIdentity from certificate and MSPid
func marshalProtoIdentity(identity Identity) ([]byte, error) {
	if len(identity.MspId) < 1 {
		return nil, ErrMspMissing
	}
	creator, err := proto.Marshal(&msp.SerializedIdentity{
		Mspid:   identity.MspId,
		IdBytes: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: identity.Certificate.Raw})})
	if err != nil {
		return nil, err
	}
	return creator, nil
}

// signatureHeader creates and marshal new signature header proto from creator and transaction nonce
func signatureHeader(creator []byte, tx *TransactionId) ([]byte, error) {
	sh := new(common.SignatureHeader)
	sh.Creator = creator
	sh.Nonce = tx.Nonce
	shBytes, err := proto.Marshal(sh)
	if err != nil {
		return nil, err
	}
	return shBytes, nil
}

// header creates new common.header from signature header and channel header
func header(signatureHeader, channelHeader []byte) *common.Header {
	header := new(common.Header)
	header.SignatureHeader = signatureHeader
	header.ChannelHeader = channelHeader
	return header
}

func channelHeader(headerType common.HeaderType, tx *TransactionId, channelId string, epoch uint64, extension *peer.ChaincodeHeaderExtension) ([]byte, error) {
	ts, err := ptypes.TimestampProto(time.Now())
	if err != nil {
		return nil, err
	}
	var channelName string

	if len(channelId) > 0 {
		channelName = channelId
	}
	payloadChannelHeader := &common.ChannelHeader{
		Type:      int32(headerType),
		Version:   1,
		Timestamp: ts,
		ChannelId: channelName,
		Epoch:     epoch,
		TxId:      tx.TransactionId,
	}
	if extension != nil {
		serExt, err := proto.Marshal(extension)
		if err != nil {
			return nil, err
		}
		payloadChannelHeader.Extension = serExt
	}
	return proto.Marshal(payloadChannelHeader)
}

// payload creates new common.payload from commonHeader and envelope data
func payload(header *common.Header, data []byte) ([]byte, error) {
	p := new(common.Payload)
	p.Header = header
	p.Data = data
	return proto.Marshal(p)
}

// newTransactionId generate new transaction id from creator and random bytes
func newTransactionId(creator []byte) (*TransactionId, error) {
	nonce, err := generateRandomBytes(24)
	if err != nil {
		return nil, err
	}
	id := generateTxId(nonce, creator)
	return &TransactionId{Creator: creator, Nonce: nonce, TransactionId: id}, nil
}

// generateRandomBytes get random bytes from crypto/random
func generateRandomBytes(len int) ([]byte, error) {
	b := make([]byte, len)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// sha256 is hardcoded in hyperledger
func generateTxId(nonce, creator []byte) string {
	f := sha256.New()
	f.Write(append(nonce, creator...))
	return hex.EncodeToString(f.Sum(nil))
}

func chainCodeInvocationSpec(chainCode ChainCode) ([]byte, error) {

	invocation := &peer.ChaincodeInvocationSpec{
		ChaincodeSpec: &peer.ChaincodeSpec{
			Type: peer.ChaincodeSpec_Type(chainCode.Type),
			ChaincodeId: &peer.ChaincodeID{
				Name:    chainCode.Name,
				Version: chainCode.Version,
			},
			Input: &peer.ChaincodeInput{Args: chainCode.toChainCodeArgs()},
		},
	}
	invocationBytes, err := proto.Marshal(invocation)
	if err != nil {
		return nil, err
	}
	return invocationBytes, nil
}

func proposal(header, payload []byte) ([]byte, error) {
	prop := new(peer.Proposal)
	prop.Header = header
	prop.Payload = payload

	propBytes, err := proto.Marshal(prop)
	if err != nil {
		return nil, err
	}
	return propBytes, nil
}

func signedProposal(prop []byte, identity Identity, crypt CryptoSuite) (*peer.SignedProposal, error) {
	sb, err := crypt.Sign(prop, identity.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &peer.SignedProposal{ProposalBytes: prop, Signature: sb}, nil
}

// sendToPeers send proposal to all peers in the list for endorsement asynchronously and wait for there response.
// there is no difference in what order results will e returned and is `p.Endorse()` guarantee that there will be
// response, so no need of complex synchronisation and wait groups
func sendToPeers(ctx context.Context, peers []*Peer, prop *peer.SignedProposal) []*PeerResponse {
	ch := make(chan *PeerResponse)
	l := len(peers)
	resp := make([]*PeerResponse, 0, l)
	for _, p := range peers {
		go p.Endorse(ctx, ch, prop)
	}
	for i := 0; i < l; i++ {
		resp = append(resp, <-ch)
	}
	close(ch)
	return resp
}

func createTransactionProposal(identity Identity, cc ChainCode) (*transactionProposal, error) {
	spec, err := chainCodeInvocationSpec(cc)
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

	extension := &peer.ChaincodeHeaderExtension{
		ChaincodeId: &peer.ChaincodeID{
			Name:    cc.Name,
			Version: cc.Version,
		},
	}
	channelHeader, err := channelHeader(common.HeaderType_ENDORSER_TRANSACTION, txId, cc.ChannelId, 0, extension)
	if err != nil {
		return nil, err
	}
	signatureHeader, err := signatureHeader(creator, txId)
	if err != nil {
		return nil, err
	}

	proposalPayload, err := proto.Marshal(&peer.ChaincodeProposalPayload{Input: spec, TransientMap: cc.TransientMap})
	if err != nil {
		return nil, err
	}

	header, err := proto.Marshal(header(signatureHeader, channelHeader))
	if err != nil {
		return nil, err
	}

	proposal, err := proposal(header, proposalPayload)
	if err != nil {
		return nil, err
	}
	return &transactionProposal{proposal: proposal, transactionId: txId.TransactionId}, nil
}

func decodeChainCodeQueryResponse(data []byte) ([]*peer.ChaincodeInfo, error) {
	response := new(peer.ChaincodeQueryResponse)
	err := proto.Unmarshal(data, response)
	if err != nil {
		return nil, err
	}
	return response.GetChaincodes(), nil
}

func createTransaction(proposal []byte, endorsement []*PeerResponse) ([]byte, error) {
	var propResp *peer.ProposalResponse
	var pl []byte
	mEndorsements := make([]*peer.Endorsement, 0, len(endorsement))
	for _, e := range endorsement {
		if e.Err == nil && e.Response.Response.Status == 200 {
			propResp = e.Response
			mEndorsements = append(mEndorsements, e.Response.Endorsement)
			if pl == nil {
				pl = e.Response.Payload
			}
		} else {
			if e.Err != nil {
				return nil, e.Err
			}
			return nil, ErrBadTransactionStatus
		}
		if bytes.Compare(pl, e.Response.Payload) != 0 {
			return nil, ErrEndorsementsDoNotMatch
		}
	}

	// at least one is OK
	if len(mEndorsements) < 1 {
		return nil, ErrNoValidEndorsementFound
	}

	originalProposal, err := getProposal(proposal)
	if err != nil {
		return nil, err
	}

	originalProposalHeader, err := getHeader(originalProposal.Header)
	if err != nil {
		return nil, err
	}

	originalProposalPayload, err := getChainCodeProposalPayload(originalProposal.Payload)
	if err != nil {
		return nil, err
	}

	// create actual invocation

	proposedPayload, err := proto.Marshal(&peer.ChaincodeProposalPayload{Input: originalProposalPayload.Input, TransientMap: nil})
	if err != nil {
		return nil, err
	}

	payload, err := proto.Marshal(&peer.ChaincodeActionPayload{
		Action: &peer.ChaincodeEndorsedAction{
			ProposalResponsePayload: propResp.Payload,
			Endorsements:            mEndorsements,
		},
		ChaincodeProposalPayload: proposedPayload,
	})
	if err != nil {
		return nil, err
	}

	sTransaction, err := proto.Marshal(&peer.Transaction{
		Actions: []*peer.TransactionAction{{Header: originalProposalHeader.SignatureHeader, Payload: payload}},
	})
	if err != nil {
		return nil, err
	}

	propBytes, err := proto.Marshal(&common.Payload{Header: originalProposalHeader, Data: sTransaction})
	if err != nil {
		return nil, err
	}
	return propBytes, nil
}

func getProposal(data []byte) (*peer.Proposal, error) {
	prop := new(peer.Proposal)
	err := proto.Unmarshal(data, prop)
	if err != nil {
		return nil, err
	}
	return prop, nil
}

func getHeader(bytes []byte) (*common.Header, error) {
	h := &common.Header{}
	err := proto.Unmarshal(bytes, h)
	if err != nil {
		return nil, err
	}
	return h, err
}

func getChainCodeProposalPayload(bytes []byte) (*peer.ChaincodeProposalPayload, error) {
	cpp := &peer.ChaincodeProposalPayload{}
	err := proto.Unmarshal(bytes, cpp)
	if err != nil {
		return nil, err
	}
	return cpp, err
}

func decodeTransaction(payload []byte) (*peer.Response, error) {
	transaction := new(peer.ProcessedTransaction)
	err := proto.Unmarshal(payload, transaction)
	if err != nil {
		return nil, err
	}
	p := new(common.Payload)
	err = proto.Unmarshal(transaction.GetTransactionEnvelope().GetPayload(), p)
	if err != nil {
		return nil, err
	}
	tx := new(peer.Transaction)
	err = proto.Unmarshal(p.Data, tx)
	if err != nil {
		return nil, err
	}
	chainCodeActionPayload := new(peer.ChaincodeActionPayload)
	err = proto.Unmarshal(tx.Actions[0].GetPayload(), chainCodeActionPayload)
	if err != nil {
		return nil, err
	}
	propRespPayload := new(peer.ProposalResponsePayload)
	err = proto.Unmarshal(chainCodeActionPayload.GetAction().GetProposalResponsePayload(), propRespPayload)
	if err != nil {
		return nil, err
	}
	caPayload := new(peer.ChaincodeAction)
	err = proto.Unmarshal(propRespPayload.GetExtension(), caPayload)
	if err != nil {
		return nil, err
	}

	return caPayload.GetResponse(), nil
}
