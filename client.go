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
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/peer"
	"github.com/golang/protobuf/proto"
	"encoding/hex"
)

//TODO create channel
//TODO joinChannel
//TODO queryInfo
//TODO queryBlockByHash
//TODO queryBlock
//TODO queryTransaction

// GohfcClient provides higher level API to execute different transactions and operations to fabric
type GohfcClient struct {
	Crypt    CryptSuite
	KVStore  KeyValueStore
	CAClient CAClient
	Peers    []*Peer
	Orderers []*Orderer
}

// QueryResponse is response from query transaction
type QueryResponse struct {
	// TxId is transaction id
	TxId string
	// Input is a slice of parameters used for this query
	Input []string
	// Response is query response from one or more peer
	Response []*PeerResponse
}

// InstallResponse is response from Install request
type InstallResponse struct {
	// TxId is transaction id
	TxId string
	// Response is response from one or more peers
	Response []*PeerResponse
}

// Enroll enrolls already registered user and gets ECert. Request is executed over CAClient implementation
// Note that if enrollmentID is found in key-Value store no request will be executed and data from
// Key-Value store will be returned. This is true even when ECert is revoked. It is a responsibility of developers
// to "clean" Key-Value store.
func (c *GohfcClient) Enroll(enrollmentId, password string) (*Identity, error) {
	prevCert, ok, err := c.KVStore.Get(enrollmentId)
	if err != nil {
		return nil, err
	}
	//return Identity if enrollmentId was found in kv store
	if len(prevCert) > 1 && ok {
		identity, err := UnmarshalIdentity(prevCert)
		if err != nil {
			return nil, err
		}
		return identity, nil
	}

	identity, err := c.CAClient.Enroll(enrollmentId, password)
	if err != nil {
		return nil, err
	}
	marsh, err := MarshalIdentity(identity)

	if err != nil {
		return identity, err
	}

	if err := c.KVStore.Set(enrollmentId, marsh); err != nil {
		return identity, err
	}
	return identity, nil
}

// Register registers new user using CAClient implementation.
func (c *GohfcClient) Register(certificate *Certificate, req *RegistrationRequest) (*CAResponse, error) {
	return c.CAClient.Register(certificate, req)
}

// Query executes query operation over one or many peers.
// Note that this invocation will NOT execute chaincode on ledger and will NOT change height of block-chain.
// Result will be from peers local block-chain data copy. It is very fast and scalable approach but in some rare cases
// peers can be out of sync and return different result from data in actual ledger.
func (c *GohfcClient) Query(certificate *Certificate, chain *Chain, peers []*Peer, args []string) (*QueryResponse, error) {
	prop, err := chain.CreateTransactionProposal(certificate, args)
	if err != nil {
		return nil, err
	}
	r := chain.SendTransactionProposal(prop, peers)
	return &QueryResponse{Input: r.Input, Response: r.EndorsersResponse, TxId: r.TxId}, nil
}

// Invoke prepares transaction proposal, sends this transaction proposal to peers for endorsement and sends endorsed
// transaction to orderer for execution. This operation will change block-chain and ledger states.
// Note that this operation is asynchronous. Even if this method returns successful execution this does not guaranty
// that actual ledger and block-chain operations are finished and/or are successful.
// Events must be used to listen for block events and compare transaction id (TxId) from this method
// to transaction ids  from events.
func (c *GohfcClient) Invoke(certificate *Certificate, chain *Chain, peers []*Peer, orderers []*Orderer, args []string) (*InvokeResponse, error) {
	prop, err := chain.CreateTransactionProposal(certificate, args)
	if err != nil {
		return nil, err
	}
	r := chain.SendTransactionProposal(prop, peers)
	result, err := chain.SendTransaction(certificate, r, orderers)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Install will install chaincode to provided peers.
// Note that in this version only Go chaincode is supported for installation.
func (c *GohfcClient) Install(certificate *Certificate, chain *Chain, peers []*Peer, req *InstallRequest) (*InstallResponse, error) {
	prop, err := chain.CreateInstallProposal(certificate, req)
	if err != nil {
		return nil, err
	}
	r := chain.SendTransactionProposal(prop, peers)
	return &InstallResponse{TxId: r.TxId, Response: r.EndorsersResponse}, nil
}

// GetChannels returns a list of channels that peer has joined.
func (c *GohfcClient) GetChannels(certificate *Certificate, qPeer *Peer, mspId string) (*peer.ChannelQueryResponse, error) {
	chain, err := NewChain("", "cscc", mspId, peer.ChaincodeSpec_GOLANG, c.Crypt)
	prop, err := chain.CreateTransactionProposal(certificate, []string{"GetChannels"})
	if err != nil {
		return nil, err
	}
	r := chain.SendTransactionProposal(prop, []*Peer{qPeer})
	if r.EndorsersResponse[0].Err != nil {
		return nil, r.EndorsersResponse[0].Err
	}
	if r.EndorsersResponse[0].Response.Response.Status != 200 {
		return nil, ErrBadTransactionStatus
	}
	ch := new(peer.ChannelQueryResponse)
	if err := proto.Unmarshal(r.EndorsersResponse[0].Response.Response.Payload, ch); err != nil {
		return nil, err
	}
	return ch, nil
}

// GetInstalledChainCodes returns list of chaincodes that are installed on peer.
// Note that this list contains only chaincodes that are installed but not instantiated.
func (c *GohfcClient) GetInstalledChainCodes(certificate *Certificate, qPeer *Peer, mspId string) (*peer.ChaincodeQueryResponse, error) {
	chain, err := NewChain("", "lccc", mspId, peer.ChaincodeSpec_GOLANG, c.Crypt)
	prop, err := chain.CreateTransactionProposal(certificate, []string{"getinstalledchaincodes"})
	if err != nil {
		return nil, err
	}
	r := chain.SendTransactionProposal(prop, []*Peer{qPeer})
	if r.EndorsersResponse[0].Err != nil {
		return nil, r.EndorsersResponse[0].Err
	}
	if r.EndorsersResponse[0].Response.Response.Status != 200 {
		return nil, ErrBadTransactionStatus
	}
	ch := new(peer.ChaincodeQueryResponse)
	if err := proto.Unmarshal(r.EndorsersResponse[0].Response.Response.Payload, ch); err != nil {
		return nil, err
	}
	return ch, nil
}

// GetChannelChainCodes returns list of chaincodes that are instantiated on peer.
// Note that this list contains only chaincodes that are instantiated.
func (c *GohfcClient) GetChannelChainCodes(certificate *Certificate, qPeer *Peer, channelName string, mspId string) (*peer.ChaincodeQueryResponse, error) {
	chain, err := NewChain(channelName, "lccc", mspId, peer.ChaincodeSpec_GOLANG, c.Crypt)
	prop, err := chain.CreateTransactionProposal(certificate, []string{"getchaincodes"})
	if err != nil {
		return nil, err
	}
	r := chain.SendTransactionProposal(prop, []*Peer{qPeer})
	if r.EndorsersResponse[0].Err != nil {
		return nil, r.EndorsersResponse[0].Err
	}
	if r.EndorsersResponse[0].Response.Response.Status != 200 {
		return nil, ErrBadTransactionStatus
	}
	ch := new(peer.ChaincodeQueryResponse)
	if err := proto.Unmarshal(r.EndorsersResponse[0].Response.Response.Payload, ch); err != nil {
		return nil, err
	}
	return ch, nil
}

// QueryTransaction will execute query over transaction id. If transaction is not found error is returned.
// Note that this operation is executed on peer not on orderer.
func (c *GohfcClient) QueryTransaction(certificate *Certificate, qPeer *Peer, channelName, txid string, mspId string) (*peer.ProcessedTransaction, *common.Payload, error) {
	chain, err := NewChain("", "qscc", mspId, peer.ChaincodeSpec_GOLANG, c.Crypt)
	prop, err := chain.CreateTransactionProposal(certificate, []string{"GetTransactionByID", channelName, txid})
	if err != nil {
		return nil, nil, err
	}
	r := chain.SendTransactionProposal(prop, []*Peer{qPeer})
	if r.EndorsersResponse[0].Err != nil {
		return nil, nil, r.EndorsersResponse[0].Err
	}
	if r.EndorsersResponse[0].Response.Response.Status != 200 {
		return nil, nil, ErrBadTransactionStatus
	}
	transaction := new(peer.ProcessedTransaction)
	payload := new(common.Payload)
	if err := proto.Unmarshal(r.EndorsersResponse[0].Response.Response.Payload, transaction); err != nil {
		return nil, nil, err
	}
	if err := proto.Unmarshal(transaction.TransactionEnvelope.Payload, payload); err != nil {
		return nil, nil, err
	}
	return transaction, payload, nil
}

// Instantiate instantiates already installed chaincode.
func (c *GohfcClient) Instantiate(certificate *Certificate, chain *Chain, peer *Peer, orderer *Orderer, req *InstallRequest, policy *common.SignaturePolicyEnvelope) (*InvokeResponse, error) {

	prop, err := chain.CreateInstantiateProposal(certificate, req, policy)
	if err != nil {
		return nil, err
	}
	rbb := chain.SendTransactionProposal(prop, []*Peer{peer})

	result, err := chain.SendTransaction(certificate, rbb, []*Orderer{orderer})
	if result != nil {
		return nil, err
	}
	return result, nil
}

// RevokeCert revokes ECert on CA
func (c *GohfcClient) RevokeCert(identity *Identity, reason int) (*CAResponse, error) {
	aki := string(hex.EncodeToString(identity.Cert.AuthorityKeyId))
	serial := identity.Cert.SerialNumber.String()
	return c.CAClient.Revoke(identity.Certificate, &(RevocationRequest{AKI: aki, EnrollmentId: identity.EnrollmentId, Serial: serial, Reason: reason}))
}

// JoinChannel will join peers from peers slice to channel. If peer is already in channel error will be returned for
// this particular peer, others will join channel.
func (c *GohfcClient) JoinChannel(certificate *Certificate, channelName string,mspId string, peers []*Peer, pOrderer *Orderer) (*ProposalTransactionResponse, error) {
	chain, err := NewChain("", "cscc", mspId, peer.ChaincodeSpec_GOLANG, c.Crypt)
	if err != nil {
		Logger.Errorf("Error creating new chain: %s", err)
		return nil, err
	}
	prop, err := chain.CreateSeekProposal(certificate, peers, pOrderer, channelName, 0)
	if err != nil {
		return nil, err
	}
	block,err:=pOrderer.GetBlock(&common.Envelope{Payload:prop.Payload,Signature:prop.Proposal.Signature})
	if err != nil {
		return nil, err
	}
	//send proposal with block to peers
	blockData, err := proto.Marshal(block.Block)
	if err != nil {
		Logger.Errorf("Error marshal orderer.DeliverResponse_Block: %s", err)
		return nil, err
	}

	proposal, err := chain.CreateTransactionProposal(certificate, []string{"JoinChain", string(blockData)})
	if err != nil {
		return nil, err
	}
	r := chain.SendTransactionProposal(proposal, peers)
	return r, nil
}

// NewClientFromJSONConfig creates new GohfcClient from json config
func NewClientFromJSONConfig(path string, kvStore KeyValueStore) (*GohfcClient, error) {
	config, err := NewConfigFromJSON(path)
	if err != nil {
		return nil, err
	}
	crypto, err := NewECCryptSuite(&config.Crypt)
	if err != nil {
		return nil, err
	}
	caClient, err := NewFabricCAClientFromConfig(&config.CAServer, crypto, nil)
	if err != nil {
		return nil, err
	}

	peers := make([]*Peer, 0, len(config.Peers))
	for _, peer := range config.Peers {
		peers = append(peers, NewPeerFromConfig(&peer))
	}

	orderers := make([]*Orderer, 0, len(config.Orderers))
	for _, orderer := range config.Orderers {
		orderers = append(orderers, NewOrdererFromConfig(&orderer))
	}
	return &GohfcClient{Crypt: crypto, KVStore: kvStore, CAClient: caClient, Peers: peers, Orderers: orderers}, nil
}
