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
	"github.com/hyperledger/fabric/protos/peer"
	"encoding/pem"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/msp"
	"encoding/hex"
	"google.golang.org/grpc"
	"context"
	"crypto/sha256"
	"github.com/hyperledger/fabric/protos/orderer"
	"os"
)

// Chain implements main chaincode operations to peers and orderers.
type Chain struct {
	// ChannelName is channel name over which operations will be executed.
	ChannelName string
	// ChainCodeName is name of tha chaincode that will be executed.
	ChainCodeName string
	// MspId identify which member service in peer must be used to verify operation.
	// Default MspId in peers is DEFAULT (case sensitive)
	MspId string
	// ChaincodeType identifies language of the chaincode (go, java...)
	ChaincodeType peer.ChaincodeSpec_Type
	// Crypto is CryptSuite implementation used to sign and verify transactions to peers and orderers.
	Crypto CryptSuite
}

// PeerResponse is response from peer transaction request
type PeerResponse struct {
	Response *peer.ProposalResponse
	Err      error
}

// TransactionProposal holds needed data to make transaction proposal to peer
type TransactionProposal struct {
	Header   *common.Header
	Proposal *peer.SignedProposal
	Payload  []byte
	Input    []string
	Ccis     []byte
	// TxId is transaction id. This id can be used to track transactions and their status
	TxId string
}

// ProposalTransactionResponse is peer response from transaction request
type ProposalTransactionResponse struct {
	Payload           []byte
	Input             []string
	Ccis              []byte
	TxId              string
	Header            *common.Header
	EndorsersResponse []*PeerResponse
}

// InvokeResponse is response from endorsed transaction sent to orderer
type InvokeResponse struct {
	Status common.Status
	// TxID is transaction id. This id can be used to track transactions and their status
	TxID string
}

// InstallRequest holds data needed to make new chaincode installation
type InstallRequest struct {
	// ChaincodeName is the name of the chaincode that will be installed.
	// This name will be used later on all requests to this chaincode
	ChaincodeName string
	// ChaincodeVersion is version of the chaincode.
	ChaincodeVersion string
	// ChannelName is name of existing channel on which chaincode will be installed.
	ChannelName string
	// Namespace is go package indentifier.
	// For example github.com/hyperledger/fabric/examples/chaincode/go/chaincode_example02
	//TODO this must be revisited when installation of Java chaincode is supported in this SDK
	Namespace string
	// SrcPath is physical path where chaincode is located and from where will be read and packet by SDK
	SrcPath string
	// Args are arguments used in instantiation of chaincode
	Args []string
}

// CreateTransactionProposal generates and signs transaction proposal.
// Note that this method does not send transaction. It only prepares it.
func (c *Chain) CreateTransactionProposal(certificate *Certificate, args []string) (*TransactionProposal, error) {
	if certificate == nil {
		Logger.Error(ErrCertificateEmpty)
		return nil, ErrCertificateEmpty
	}

	chaincodeSpec := new(peer.ChaincodeSpec)
	chaincodeSpec.Type = c.ChaincodeType
	chaincodeSpec.ChaincodeId = &peer.ChaincodeID{Name: c.ChainCodeName}
	chaincodeSpec.Input = &peer.ChaincodeInput{Args: toChaincodeArgs(args)}

	chainHeader := &common.ChannelHeader{Type: int32(common.HeaderType_ENDORSER_TRANSACTION),
		Version:                           1,
		ChannelId:                         c.ChannelName}
	nonce, err := GenerateRandomBytes(24)
	if err != nil {
		Logger.Errorf("Error generating nonce %s", err)
		return nil, err
	}
	creator, err := proto.Marshal(&msp.SerializedIdentity{
		Mspid:   c.MspId,
		IdBytes: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Cert.Raw})})
	if err != nil {
		Logger.Errorf("Error marshal SerializedIdentity %s", err)
		return nil, err
	}

	chainHeader.TxId = c.GenerateTxId(nonce, creator)

	serExt, err := proto.Marshal(&peer.ChaincodeHeaderExtension{ChaincodeId: &peer.ChaincodeID{Name: c.ChainCodeName}})
	if err != nil {
		Logger.Errorf("Error marshal ChaincodeHeaderExtension %s", err)
		return nil, err
	}
	chainHeader.Extension = serExt
	header := new(common.Header)
	signatureHeader, err := proto.Marshal(&common.SignatureHeader{Creator: creator, Nonce: nonce})
	if err != nil {
		Logger.Errorf("Error marshal SignatureHeader %s", err)
		return nil, err
	}
	mChainHeader, err := proto.Marshal(chainHeader)
	if err != nil {
		Logger.Errorf("Error marshal chainHeader %s", err)
		return nil, err
	}
	header.SignatureHeader = signatureHeader
	header.ChannelHeader = mChainHeader

	ccis, err := proto.Marshal(&peer.ChaincodeInvocationSpec{ChaincodeSpec: chaincodeSpec})
	if err != nil {
		Logger.Errorf("Error marshal ChaincodeInvocationSpec %s", err)
		return nil, err
	}

	spropPayload, err := proto.Marshal(&peer.ChaincodeProposalPayload{Input: ccis})
	if err != nil {
		Logger.Errorf("Error marshal ChaincodeProposalPayload %s", err)
		return nil, err
	}

	sheader, err := proto.Marshal(header)
	if err != nil {
		Logger.Errorf("Error marshal header %s", err)
		return nil, err
	}
	sprop, err := proto.Marshal(&peer.Proposal{Header: sheader, Payload: spropPayload})
	if err != nil {
		Logger.Errorf("Error marshal Proposal %s", err)
		return nil, err
	}
	sig, err := c.Crypto.Sign(sprop, certificate.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &TransactionProposal{
		Header:   header,
		TxId:     chainHeader.TxId,
		Payload:  spropPayload,
		Input:    args,
		Ccis:     ccis,
		Proposal: &peer.SignedProposal{ProposalBytes: sprop, Signature: sig}}, nil

}

// CreateInstallProposal creates and signs new installation proposal.
// Note that this method does not send transaction. It only prepares it.
func (c *Chain) CreateInstallProposal(certificate *Certificate, req *InstallRequest) (*TransactionProposal, error) {
	if req == nil {
		Logger.Error(ErrInstallRequestNil)
		return nil, ErrInstallRequestNil
	}
	if err := req.Validate(); err != nil {
		Logger.Errorf("Error validating install request: %s", err)
		return nil, err
	}
	specs := new(peer.ChaincodeSpec)
	specs.ChaincodeId = &peer.ChaincodeID{Name: req.ChaincodeName, Path: req.Namespace, Version: req.ChaincodeVersion}
	specs.Type = peer.ChaincodeSpec_GOLANG

	var packageBytes []byte
	var err error
	packageBytes, err = gzipGoSource(req.SrcPath)
	if err != nil {
		Logger.Errorf("Error packing src: %s", err)
		return nil, err
	}
	chaincodeDeploymentSpec := new(peer.ChaincodeDeploymentSpec)
	chaincodeDeploymentSpec.ChaincodeSpec = specs
	chaincodeDeploymentSpec.CodePackage = packageBytes

	depSpec, err := proto.Marshal(chaincodeDeploymentSpec)
	if err != nil {
		Logger.Errorf("Error marshal peer.ChaincodeDeploymentSpec: %s", err)
		return nil, err
	}

	lcccSpec := &peer.ChaincodeInvocationSpec{
		ChaincodeSpec: &peer.ChaincodeSpec{
			Type:        peer.ChaincodeSpec_GOLANG,
			ChaincodeId: &peer.ChaincodeID{Name: "lccc"},
			Input:       &peer.ChaincodeInput{Args: [][]byte{[]byte("install"), depSpec}}}}
	trans, err := c.prepareInstallInstantiateTransaction(certificate, req, lcccSpec)
	if err != nil {
		return nil, err
	}
	//we overwrite Ccis with ChaincodeDeploymentSpec
	trans.Ccis = depSpec
	return trans, nil
}

// CreateInstantiateProposal creates and signs new Instantiate proposal.
// Note that this method does not send transaction. It only prepares it.
func (c *Chain) CreateInstantiateProposal(certificate *Certificate, req *InstallRequest, policy *common.SignaturePolicyEnvelope) (*TransactionProposal, error) {
	if req == nil {
		Logger.Error(ErrInstallRequestNil)
		return nil, ErrInstallRequestNil
	}
	if err := req.Validate(); err != nil {
		Logger.Errorf("Error validating install request: %s", err)
		return nil, err
	}
	specs := new(peer.ChaincodeSpec)
	specs.ChaincodeId = &peer.ChaincodeID{Name: req.ChaincodeName, Path: req.Namespace, Version: req.ChaincodeVersion}
	specs.Type = peer.ChaincodeSpec_GOLANG
	specs.Input = &peer.ChaincodeInput{Args: toChaincodeArgs(req.Args)}
	chaincodeDeploymentSpec := new(peer.ChaincodeDeploymentSpec)
	chaincodeDeploymentSpec.ChaincodeSpec = specs

	depSpec, err := proto.Marshal(chaincodeDeploymentSpec)
	if err != nil {
		Logger.Errorf("Error marshal chaincodeDeploymentSpec: %s", err)
		return nil, err
	}

	marshPolicy, err := proto.Marshal(policy)
	if err != nil {
		Logger.Errorf("Error marshal policy: %s", err)
		return nil, err
	}

	lcccSpec := &peer.ChaincodeInvocationSpec{
		ChaincodeSpec: &peer.ChaincodeSpec{
			Type:        peer.ChaincodeSpec_GOLANG,
			ChaincodeId: &peer.ChaincodeID{Name: "lccc"},
			Input: &peer.ChaincodeInput{Args: [][]byte{[]byte("deploy"),
								   []byte(c.ChainCodeName), depSpec, marshPolicy, []byte("escc"), []byte("vscc")}}}}

	trans, err := c.prepareInstallInstantiateTransaction(certificate, req, lcccSpec)
	if err != nil {
		return nil, err
	}
	cisBytes, err := proto.Marshal(lcccSpec)
	if err != nil {
		Logger.Errorf("Error marshal lcccSpec: %s", err)
		return nil, err
	}
	//we overwrite Ccis for instantiate ChaincodeInvocationSpec
	trans.Ccis = cisBytes
	return trans, nil
}

// SendTransactionProposal sends transaction proposal to one or more peers.
func (c *Chain) SendTransactionProposal(proposal *TransactionProposal, peers []*Peer) *ProposalTransactionResponse {
	resp := c.sendToPeers(peers, proposal)

	return &ProposalTransactionResponse{
		EndorsersResponse: resp,
		Header:            proposal.Header,
		Input:             proposal.Input,
		Payload:           proposal.Payload,
		Ccis:              proposal.Ccis,
		TxId:              proposal.TxId}

}

// SendTransaction sends endorsed transaction to orderers for execution.
// Note that transaction is sent only to first orderer in provided slice of orderers.
// When Fabric releases stable version this behaviour will be revisited.
func (c *Chain) SendTransaction(certificate *Certificate, transactionProp *ProposalTransactionResponse, orderers []*Orderer) (*InvokeResponse, error) {
	var propResp *peer.ProposalResponse
	mEndorsements := make([]*peer.Endorsement, 0, len(transactionProp.EndorsersResponse))
	for _, e := range transactionProp.EndorsersResponse {
		if e.Err == nil && e.Response.Response.Status == 200 {
			propResp = e.Response
			mEndorsements = append(mEndorsements, e.Response.Endorsement)
		}
		//TODO validate that all responses payload is same
	}

	//at least one is OK
	if len(mEndorsements) < 1 {
		Logger.Debugf("Transaction %s was not endorced", transactionProp.TxId)
		return nil, ErrNoValidEndorsementFound
	}
	//create actual invocation
	chaincodeEndorsedAction := new(peer.ChaincodeEndorsedAction)
	chaincodeEndorsedAction.ProposalResponsePayload = propResp.Payload
	chaincodeEndorsedAction.Endorsements = mEndorsements

	chaincodeActionPayload := new(peer.ChaincodeActionPayload)
	chaincodeActionPayload.Action = chaincodeEndorsedAction

	pl1, err := proto.Marshal(&peer.ChaincodeProposalPayload{Input: transactionProp.Ccis, TransientMap: nil})
	if err != nil {
		Logger.Errorf("Error marshal peer.ChaincodeProposalPayload: %s", err)
		return nil, err
	}

	chaincodeActionPayload.ChaincodeProposalPayload = pl1

	sPayload, err := proto.Marshal(chaincodeActionPayload)
	if err != nil {
		Logger.Errorf("Error marshal peer.ChaincodeActionPayload: %s", err)
		return nil, err
	}

	transaction := new(peer.Transaction)
	transaction.Actions = []*peer.TransactionAction{{Header: transactionProp.Header.SignatureHeader, Payload: sPayload}}
	sTransaction, err := proto.Marshal(transaction)
	if err != nil {
		Logger.Errorf("Error marshal peer.Transaction: %s", err)
		return nil, err
	}

	propBytes, err := proto.Marshal(&common.Payload{Header: transactionProp.Header, Data: sTransaction})
	if err != nil {
		Logger.Errorf("Error marshal common.Payload: %s", err)
		return nil, err
	}

	psig, err := c.Crypto.Sign(propBytes, certificate.PrivateKey)

	if err != nil {
		return nil, err
	}
	//TODO if there are more than one orderer and connection to one fails try another.
	reply, err := orderers[0].Deliver(&common.Envelope{Payload:propBytes,Signature:psig})
	if err != nil {
		Logger.Errorf("Error recv Response from orderer %s: %s", orderers[0].Name, err)
		return nil, err
	}
	return &InvokeResponse{Status: reply.Status, TxID: transactionProp.TxId}, nil
}

//TODO probably TransactionProposal is not proper fot this
func (c *Chain) CreateSeekProposal(certificate *Certificate, peers []*Peer, pOrderer *Orderer, channelName string, position uint64) (*TransactionProposal, error) {
	seekInfo := &orderer.SeekInfo{
		Start:    &orderer.SeekPosition{Type: &orderer.SeekPosition_Oldest{Oldest: &orderer.SeekOldest{}}},
		Stop:     &orderer.SeekPosition{Type: &orderer.SeekPosition_Specified{Specified: &orderer.SeekSpecified{Number: position}}},
		Behavior: orderer.SeekInfo_BLOCK_UNTIL_READY,
	}
	mSeekInfo, err := proto.Marshal(seekInfo)
	if err != nil {
		Logger.Errorf("Error marshal orderer.SeekInfo: %s", err)
		return nil, err
	}
	//header
	nonce, err := GenerateRandomBytes(24)
	if err != nil {
		Logger.Errorf("Error generating nonce %s", err)
		return nil, err
	}
	creator, err := proto.Marshal(&msp.SerializedIdentity{
		Mspid:   c.MspId,
		IdBytes: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Cert.Raw})})
	if err != nil {
		Logger.Errorf("Error marshal SerializedIdentity %s", err)
		return nil, err
	}
	txId := c.GenerateTxId(nonce, creator)
	channelHeader := &common.ChannelHeader{Type: int32(common.HeaderType_DELIVER_SEEK_INFO),
		Version:                             1, ChannelId: channelName, TxId: txId}
	comHeader, err := proto.Marshal(channelHeader)
	if err != nil {
		Logger.Errorf("Error marshal common.ChannelHeader: %s", err)
		return nil, err
	}
	sigHeader, err := proto.Marshal(&common.SignatureHeader{Creator: creator, Nonce: nonce})
	if err != nil {
		Logger.Errorf("Error marshal common.SignatureHeader: %s", err)
		return nil, err
	}

	header := &common.Header{ChannelHeader: comHeader, SignatureHeader: sigHeader}

	payload, err := proto.Marshal(&common.Payload{Data: mSeekInfo, Header: header})
	if err != nil {
		Logger.Errorf("Error marshal common.Payload: %s", err)
		return nil, err
	}
	sig, err := c.Crypto.Sign(payload, certificate.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &TransactionProposal{
		Header:   header,
		TxId:     txId,
		Payload:  payload,
		Proposal: &peer.SignedProposal{ProposalBytes: payload, Signature: sig}}, nil

}

// GenerateTxId generates transaction id for transaction.
func (c *Chain) GenerateTxId(nonce, creator []byte) string {
	//TODO !!!sha256 is hardcoded in hyperledger!!!! Change it when they update it!!!!
	f := sha256.New()
	f.Write(append(nonce, creator...))
	return hex.EncodeToString(f.Sum(nil))
	//return hex.EncodeToString(c.Crypto.Hash(append(nonce, creator...)))
}

// sendToPeers sends transaction to one or more peers using go routines and combines result of all executions in one response
func (c *Chain) sendToPeers(peers []*Peer, prop *TransactionProposal) []*PeerResponse {
	ch := make(chan *PeerResponse)
	l := len(peers)
	resp := make([]*PeerResponse, 0, l)
	for _, p := range peers {
		go c.sendToEndorser(ch, prop.Proposal, p)
	}
	for i := 0; i < l; i++ {
		resp = append(resp, <-ch)
	}
	close(ch)
	return resp
}

// sendToEndorser sends single transaction to single peer.
func (c *Chain) sendToEndorser(resp chan *PeerResponse, prop *peer.SignedProposal, p *Peer) {
	conn, err := grpc.Dial(p.Url, p.Opts...)
	if err != nil {
		Logger.Errorf("Error connecting to peer %s: %s", p.Name, err)
		resp <- &PeerResponse{Response: nil, Err: err}
		return
	}
	defer conn.Close()
	client := peer.NewEndorserClient(conn)
	proposalResp, err := client.ProcessProposal(context.Background(), prop)
	if err != nil {
		Logger.Errorf("Error getting response from peer %s: %s", p.Name, err)
		resp <- &PeerResponse{Response: nil, Err: err}
		return
	}
	resp <- &PeerResponse{Response: proposalResp, Err: nil}
	return
}

// prepareInstallInstantiateTransaction creates protobuffer request for new chaincode installation or
// instantiation of already installed chaincode.
func (c *Chain) prepareInstallInstantiateTransaction(certificate *Certificate, req *InstallRequest, spec *peer.ChaincodeInvocationSpec) (*TransactionProposal, error) {
	nonce, err := GenerateRandomBytes(24)
	creator, err := proto.Marshal(&msp.SerializedIdentity{
		Mspid:   c.MspId,
		IdBytes: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Cert.Raw})})
	if err != nil {
		Logger.Errorf("Error marshal msp.SerializedIdentity: %s", err)
		return nil, err
	}

	txId := c.GenerateTxId(nonce, creator)
	ccHdrExt := &peer.ChaincodeHeaderExtension{ChaincodeId: spec.ChaincodeSpec.ChaincodeId}
	ccHdrExtBytes, err := proto.Marshal(ccHdrExt)
	if err != nil {
		Logger.Errorf("Error marshal peer.ChaincodeHeaderExtension: %s", err)
		return nil, err
	}
	cisBytes, err := proto.Marshal(spec)
	if err != nil {
		Logger.Errorf("Error marshal peer.ChaincodeInvocationSpec: %s", err)
		return nil, err
	}
	ccPropPayload := &peer.ChaincodeProposalPayload{Input: cisBytes, TransientMap: nil}
	ccPropPayloadBytes, err := proto.Marshal(ccPropPayload)
	if err != nil {
		Logger.Errorf("Error marshal peer.ChaincodeProposalPayload: %s", err)
		return nil, err
	}

	sigHeader, err := proto.Marshal(&common.SignatureHeader{Nonce: nonce, Creator: creator})
	if err != nil {
		Logger.Errorf("Error marshal common.SignatureHeader: %s", err)
		return nil, err
	}
	comHeader, err := proto.Marshal(&common.ChannelHeader{
		Type:      int32(common.HeaderType_ENDORSER_TRANSACTION),
		TxId:      txId,
		ChannelId: req.ChannelName,
		Extension: ccHdrExtBytes})
	if err != nil {
		Logger.Errorf("Error marshal common.ChannelHeader: %s", err)
		return nil, err
	}

	header := &common.Header{ChannelHeader: comHeader, SignatureHeader: sigHeader}

	hdrBytes, err := proto.Marshal(header)
	if err != nil {
		Logger.Errorf("Error marshal common.Header: %s", err)
		return nil, err
	}

	sprop, err := proto.Marshal(&peer.Proposal{Header: hdrBytes, Payload: ccPropPayloadBytes})
	if err != nil {
		Logger.Errorf("Error marshal peer.Proposal: %s", err)
		return nil, err
	}
	sig, err := c.Crypto.Sign(sprop, certificate.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &TransactionProposal{
		Header:   header,
		TxId:     txId,
		Payload:  ccPropPayloadBytes,
		Input:    req.Args,
		Proposal: &peer.SignedProposal{ProposalBytes: sprop, Signature: sig}}, nil
}

// Validate validates Install request
func (i *InstallRequest) Validate() error {
	if i.ChaincodeName == "" {
		return ErrChainCodeNameEmpty
	}
	if i.ChaincodeVersion == "" {
		return ErrChaincodeVersionEmpty
	}
	if i.ChannelName == "" {
		return ErrChannelNameEmpty
	}
	if i.Namespace == "" {
		return ErrChaincodeNamespaceEmpty
	}
	if i.SrcPath == "" {
		return ErrChaincodeSrcEmpty
	}

	fi, err := os.Stat(i.SrcPath)
	if err != nil {
		Logger.Errorf("Error reading source: %s", err)
		return ErrReadChaincodeSrc
	}
	switch mode := fi.Mode(); {
	case mode.IsDir():
		return nil
	case mode.IsRegular():
		return ErrChaincodeSrcNotDir
	default:
		return ErrReadChaincodeSrc
	}

}

// NewChain creates new Chain
func NewChain(channelName, chainCodeName, mspId string, chaincodeType peer.ChaincodeSpec_Type, crypto CryptSuite) (*Chain, error) {

	if mspId == "" {
		mspId = "DEFAULT"
	}
	if _, ok := peer.ChaincodeSpec_Type_name[int32(chaincodeType)]; ok != true {
		return nil, ErrInvalidChaincodeType
	}
	if crypto == nil {
		return nil, ErrCryptoNil
	}
	return &Chain{MspId: mspId, ChannelName: channelName, ChainCodeName: chainCodeName, ChaincodeType: chaincodeType, Crypto: crypto}, nil
}
