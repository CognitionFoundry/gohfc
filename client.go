/*
Copyright: Cognition Foundry. All Rights Reserved.
License: Apache License Version 2.0
*/
package gohfc

import (
	"github.com/hyperledger/fabric/protos/common"
	"errors"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/protos/peer"
	"github.com/hyperledger/fabric/protos/orderer"
	"context"
	"fmt"
)

// FabricClient expose API's to work with Hyperledger Fabric
type FabricClient struct {
	Crypto     CryptoSuite
	Peers      map[string]*Peer
	Orderers   map[string]*Orderer
	EventPeers map[string]*Peer
}

// CreateUpdateChannel read channel config generated (usually) from configtxgen and send it to orderer
// This step is needed before any peer is able to join the channel and before any future updates of the channel.
func (c *FabricClient) CreateUpdateChannel(identity Identity, path string, channelId string, orderer string) (error) {

	ord, ok := c.Orderers[orderer]
	if !ok {
		return ErrInvalidOrdererName
	}

	envelope, err := decodeChannelFromFs(path)
	if err != nil {
		return err
	}
	ou, err := buildAndSignChannelConfig(identity, envelope.GetPayload(), c.Crypto, channelId)
	if err != nil {
		return err
	}
	replay, err := ord.Broadcast(ou)
	if err != nil {
		return err
	}
	if replay.GetStatus() != common.Status_SUCCESS {
		return errors.New("error creating new channel. See orderer logs for more details")
	}
	return nil
}

// JoinChannel send transaction to one or many Peers to join particular channel.
// Channel must be created before this operation using `CreateUpdateChannel` or manually using CLI interface.
// Orderers must be aware of this channel, otherwise operation will fail.
func (c *FabricClient) JoinChannel(identity Identity, channelId string, peers []string, orderer string) ([]*PeerResponse, error) {
	ord, ok := c.Orderers[orderer]
	if !ok {
		return nil, ErrInvalidOrdererName
	}

	execPeers := c.getPeers(peers)
	if len(peers) != len(execPeers) {
		return nil, ErrPeerNameNotFound
	}

	block, err := ord.getGenesisBlock(identity, c.Crypto, channelId)

	if err != nil {
		return nil, err
	}

	blockBytes, err := proto.Marshal(block)
	if err != nil {
		return nil, err
	}

	chainCode := ChainCode{Name: CSCC,
		Type: ChaincodeSpec_GOLANG,
		Args: []string{"JoinChain"},
		ArgBytes: blockBytes}

	invocationBytes, err := chainCodeInvocationSpec(chainCode)
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
	ext := &peer.ChaincodeHeaderExtension{ChaincodeId: &peer.ChaincodeID{Name: CSCC}}
	channelHeaderBytes, err := channelHeader(common.HeaderType_ENDORSER_TRANSACTION, txId, "", 0, ext)
	if err != nil {
		return nil, err
	}

	sigHeaderBytes, err := signatureHeader(creator, txId)
	if err != nil {
		return nil, err
	}

	header := header(sigHeaderBytes, channelHeaderBytes)
	headerBytes, err := proto.Marshal(header)
	if err != nil {
		return nil, err
	}
	chainCodePropPl := new(peer.ChaincodeProposalPayload)
	chainCodePropPl.Input = invocationBytes

	chainCodePropPlBytes, err := proto.Marshal(chainCodePropPl)
	if err != nil {
		return nil, err
	}

	proposalBytes, err := proposal(headerBytes, chainCodePropPlBytes)
	if err != nil {
		return nil, err
	}

	proposal, err := signedProposal(proposalBytes, identity, c.Crypto)
	if err != nil {
		return nil, err
	}
	return sendToPeers(execPeers, proposal), nil
}

// InstallChainCode install chainCode to one or many peers. Peer must be in the channel where chaincode will be installed.
func (c *FabricClient) InstallChainCode(identity Identity, req *InstallRequest, peers []string) ([]*PeerResponse, error) {
	execPeers := c.getPeers(peers)
	if len(peers) != len(execPeers) {
		return nil, ErrPeerNameNotFound
	}
	prop, err := createInstallProposal(identity, req)
	if err != nil {
		return nil, err
	}
	proposal, err := signedProposal(prop.proposal, identity, c.Crypto)
	if err != nil {
		return nil, err
	}
	return sendToPeers(execPeers, proposal), nil

}

// InstantiateChainCode run installed chainCode to particular peer in particular channel.
// Chaincode must be installed using InstallChainCode or CLI interface before this operation.
// If this is first time running the chaincode operation must be `deploy`
// If this operation update existing chaincode operation must be `upgrade`
// collectionsConfig is configuration for private collections in versions >= 1.1. If not provided no private collections
// will be created. collectionsConfig can be specified when chaincode is upgraded.
func (c *FabricClient) InstantiateChainCode(identity Identity, req *ChainCode, peers []string, orderer string,
	operation string, collectionsConfig []CollectionConfig) (*orderer.BroadcastResponse, error) {
	ord, ok := c.Orderers[orderer]
	if !ok {
		return nil, ErrInvalidOrdererName
	}

	execPeers := c.getPeers(peers)
	if len(peers) != len(execPeers) {
		return nil, ErrPeerNameNotFound
	}
	var collConfigBytes []byte
	if len(collectionsConfig) > 0 {
		collectionPolicy, err := CollectionConfigToPolicy(collectionsConfig)
		if err != nil {
			return nil, err
		}
		collConfigBytes, err = proto.Marshal(&common.CollectionConfigPackage{Config: collectionPolicy})
		if err != nil {
			return nil, err
		}
	}

	prop, err := createInstantiateProposal(identity, req, operation, collConfigBytes)
	if err != nil {
		return nil, err
	}

	proposal, err := signedProposal(prop.proposal, identity, c.Crypto)
	if err != nil {
		return nil, err
	}

	transaction, err := createTransaction(prop.proposal, sendToPeers(execPeers, proposal))
	if err != nil {
		return nil, err
	}

	signedTransaction, err := c.Crypto.Sign(transaction, identity.PrivateKey)
	if err != nil {
		return nil, err
	}

	reply, err := ord.Broadcast(&common.Envelope{Payload: transaction, Signature: signedTransaction})
	if err != nil {
		return nil, err
	}
	return reply, nil
}

// QueryInstalledChainCodes get all chainCodes that are installed but not instantiated in one or many peers
func (c *FabricClient) QueryInstalledChainCodes(identity Identity, peers []string) ([]*ChainCodesResponse, error) {
	execPeers := c.getPeers(peers)
	if len(peers) != len(execPeers) {
		return nil, ErrPeerNameNotFound
	}
	if len(identity.MspId) == 0 {
		return nil, ErrMspMissing
	}
	chainCode := ChainCode{
		Name: LSCC,
		Type: ChaincodeSpec_GOLANG,
		Args: []string{"getinstalledchaincodes"},
	}

	prop, err := createTransactionProposal(identity, chainCode)
	if err != nil {
		return nil, err
	}

	proposal, err := signedProposal(prop.proposal, identity, c.Crypto)
	if err != nil {
		return nil, err
	}
	r := sendToPeers(execPeers, proposal)

	response := make([]*ChainCodesResponse, len(r))
	for idx, p := range r {
		ic := ChainCodesResponse{PeerName: p.Name, Error: p.Err}
		if p.Err != nil {
			ic.Error = p.Err
		} else {
			dec, err := decodeChainCodeQueryResponse(p.Response.Response.GetPayload())
			if err != nil {
				ic.Error = err
			}
			ic.ChainCodes = dec
		}
		response[idx] = &ic
	}
	return response, nil
}

// QueryInstantiatedChainCodes get all chainCodes that are running (instantiated) "inside" particular channel in peer
func (c *FabricClient) QueryInstantiatedChainCodes(identity Identity, channelId string, peers []string) ([]*ChainCodesResponse, error) {
	execPeers := c.getPeers(peers)
	if len(peers) != len(execPeers) {
		return nil, ErrPeerNameNotFound
	}

	prop, err := createTransactionProposal(identity, ChainCode{
		ChannelId: channelId,
		Name:      LSCC,
		Type:      ChaincodeSpec_GOLANG,
		Args:      []string{"getchaincodes"},
	})
	if err != nil {
		return nil, err
	}
	proposal, err := signedProposal(prop.proposal, identity, c.Crypto)
	if err != nil {
		return nil, err
	}
	r := sendToPeers(execPeers, proposal)
	response := make([]*ChainCodesResponse, len(r))
	for idx, p := range r {
		ic := ChainCodesResponse{PeerName: p.Name, Error: p.Err}
		if p.Err != nil {
			ic.Error = p.Err
		} else {
			dec, err := decodeChainCodeQueryResponse(p.Response.Response.GetPayload())
			if err != nil {
				ic.Error = err
			}
			ic.ChainCodes = dec
		}
		response[idx] = &ic
	}
	return response, nil
}

// QueryChannels returns a list of channels that peer/s has joined
func (c *FabricClient) QueryChannels(identity Identity, peers []string) ([]*QueryChannelsResponse, error) {
	execPeers := c.getPeers(peers)
	if len(peers) != len(execPeers) {
		return nil, ErrPeerNameNotFound
	}

	chainCode := ChainCode{
		Name: CSCC,
		Type: ChaincodeSpec_GOLANG,
		Args: []string{"GetChannels"},
	}

	prop, err := createTransactionProposal(identity, chainCode)
	if err != nil {
		return nil, err
	}
	proposal, err := signedProposal(prop.proposal, identity, c.Crypto)
	if err != nil {
		return nil, err
	}
	r := sendToPeers(execPeers, proposal)
	response := make([]*QueryChannelsResponse, 0, len(r))
	for _, pr := range r {
		peerResponse := QueryChannelsResponse{PeerName: pr.Name}
		if pr.Err != nil {
			peerResponse.Error = err
		} else {
			channels := new(peer.ChannelQueryResponse)
			if err := proto.Unmarshal(pr.Response.Response.Payload, channels); err != nil {
				peerResponse.Error = err

			} else {
				peerResponse.Channels = make([]string, 0, len(channels.Channels))
				for _, ci := range channels.Channels {
					peerResponse.Channels = append(peerResponse.Channels, ci.ChannelId)
				}
			}
		}
		response = append(response, &peerResponse)
	}
	return response, nil
}

// QueryChannelInfo get current block height, current hash and prev hash about particular channel in peer/s
func (c *FabricClient) QueryChannelInfo(identity Identity, channelId string, peers []string) ([]*QueryChannelInfoResponse, error) {
	execPeers := c.getPeers(peers)
	if len(peers) != len(execPeers) {
		return nil, ErrPeerNameNotFound
	}
	chainCode := ChainCode{
		ChannelId: channelId,
		Name:      QSCC,
		Type:      ChaincodeSpec_GOLANG,
		Args:      []string{"GetChainInfo", channelId},
	}

	prop, err := createTransactionProposal(identity, chainCode)
	if err != nil {
		return nil, err
	}
	proposal, err := signedProposal(prop.proposal, identity, c.Crypto)
	if err != nil {
		return nil, err
	}
	r := sendToPeers(execPeers, proposal)

	response := make([]*QueryChannelInfoResponse, 0, len(r))
	for _, pr := range r {
		peerResponse := QueryChannelInfoResponse{PeerName: pr.Name}
		if pr.Err != nil {
			peerResponse.Error = err
		} else {
			bci := new(common.BlockchainInfo)
			if err := proto.Unmarshal(pr.Response.Response.Payload, bci); err != nil {
				peerResponse.Error = err

			} else {
				peerResponse.Info = bci
			}
		}
		response = append(response, &peerResponse)
	}
	return response, nil

}

// Query execute chainCode to one or many peers and return there responses without sending
// them to orderer for transaction - ReadOnly operation.
// Because is expected all peers to be in same state this function allows very easy horizontal scaling by
// distributing query operations between peers.
func (c *FabricClient) Query(identity Identity, chainCode ChainCode, peers []string) ([]*QueryResponse, error) {
	execPeers := c.getPeers(peers)
	if len(peers) != len(execPeers) {
		return nil, ErrPeerNameNotFound
	}
	prop, err := createTransactionProposal(identity, chainCode)
	if err != nil {
		return nil, err
	}
	proposal, err := signedProposal(prop.proposal, identity, c.Crypto)
	if err != nil {
		return nil, err
	}
	r := sendToPeers(execPeers, proposal)
	response := make([]*QueryResponse, len(r))
	for idx, p := range r {
		ic := QueryResponse{PeerName: p.Name, Error: p.Err}
		if p.Err != nil {
			ic.Error = p.Err
		} else {
			ic.Response = p.Response
		}
		response[idx] = &ic
	}
	return response, nil
}

// Invoke execute chainCode for ledger update. Peers that simulate the chainCode must be enough to satisfy the policy.
// When Invoke returns with success this is not granite that ledger was update. Invoke will return `transactionId`.
// This ID will be transactionId in events.
// It is responsibility of SDK user to build logic that handle successful and failed commits.
// If chaincode call `shim.Error` or simulation fails for other reasons this is considered as simulation failure.
// In such case Invoke will return the error and transaction will NOT be send to orderer. This transaction will NOT be
// committed to blockchain.
func (c *FabricClient) Invoke(identity Identity, chainCode ChainCode, peers []string, orderer string) (*InvokeResponse, error) {
	ord, ok := c.Orderers[orderer]
	if !ok {
		return nil, ErrInvalidOrdererName
	}
	execPeers := c.getPeers(peers)
	if len(peers) != len(execPeers) {
		return nil, ErrPeerNameNotFound
	}
	prop, err := createTransactionProposal(identity, chainCode)
	if err != nil {
		return nil, err
	}
	proposal, err := signedProposal(prop.proposal, identity, c.Crypto)
	if err != nil {
		return nil, err
	}
	transaction, err := createTransaction(prop.proposal, sendToPeers(execPeers, proposal))
	if err != nil {
		return nil, err
	}
	signedTransaction, err := c.Crypto.Sign(transaction, identity.PrivateKey)
	if err != nil {
		return nil, err
	}
	reply, err := ord.Broadcast(&common.Envelope{Payload: transaction, Signature: signedTransaction})
	if err != nil {
		return nil, err
	}
	return &InvokeResponse{Status: reply.Status, TxID: prop.transactionId}, nil
}

// QueryTransaction get data for particular transaction.
// TODO for now it only returns status of the transaction, and not the whole data (payload, endorsement etc)
func (c *FabricClient) QueryTransaction(identity Identity, channelId string, txId string, peers []string) ([]*QueryTransactionResponse, error) {
	execPeers := c.getPeers(peers)
	if len(peers) != len(execPeers) {
		return nil, ErrPeerNameNotFound
	}
	chainCode := ChainCode{
		ChannelId: channelId,
		Name:      QSCC,
		Type:      ChaincodeSpec_GOLANG,
		Args:      []string{"GetTransactionByID", channelId, txId}}

	prop, err := createTransactionProposal(identity, chainCode)
	if err != nil {
		return nil, err
	}
	proposal, err := signedProposal(prop.proposal, identity, c.Crypto)
	if err != nil {
		return nil, err
	}
	r := sendToPeers(execPeers, proposal)
	fmt.Println(r)
	response := make([]*QueryTransactionResponse, len(r))
	for idx, p := range r {
		qtr := QueryTransactionResponse{PeerName: p.Name, Error: p.Err}
		if p.Err != nil {
			qtr.Error = p.Err
		} else {
			dec, err := decodeTransaction(p.Response.Response.GetPayload())
			if err != nil {
				qtr.Error = err
			}
			qtr.StatusCode = dec
		}
		response[idx] = &qtr
	}
	return response, nil
}

// ListenForFullBlock will listen for events when new block is committed to blockchain and will return block height,
// list of all transactions in this block, there statuses and events associated with them.
// Listener is per channel, so user must create a new listener for every channel of interest.
// This event listener will start listen from newest block, and actual (raw) block data will NOT be returned.
// If user wants fo start listening from different blocks or want to receive full block bytes
// he/she must construct the listener manually and provide proper seek and block options.
// User must provide channel where events will be send and is responsibility for the user to read this channel.
// To cancel listening provide context with cancellation option and call cancel.
// User can listen for same events in same channel in multiple peers for redundancy using same `chan<- EventBlockResponse`
// In this case every peer will send its events, so identical events may appear more than once in channel.
func (c *FabricClient) ListenForFullBlock(ctx context.Context, identity Identity, eventPeer, channelId string, response chan<- EventBlockResponse) (error) {
	ep, ok := c.EventPeers[eventPeer]
	if !ok {
		return ErrPeerNameNotFound
	}
	listener, err := NewEventListener(ctx, c.Crypto, identity, *ep, channelId, EventTypeFullBlock)
	if err != nil {
		return err
	}
	err = listener.SeekNewest()
	if err != nil {
		return err
	}
	listener.Listen(response)
	return nil
}

// ListenForFilteredBlock listen for events in blockchain. Difference with `ListenForFullBlock` is that event names
// will be returned but NOT events data. Also full block data will not be available.
// Other options are same as `ListenForFullBlock`.
func (c *FabricClient) ListenForFilteredBlock(ctx context.Context, identity Identity, eventPeer, channelId string, response chan<- EventBlockResponse) (error) {
	ep, ok := c.EventPeers[eventPeer]
	if !ok {
		return ErrPeerNameNotFound
	}
	listener, err := NewEventListener(ctx, c.Crypto, identity, *ep, channelId, EventTypeFiltered)
	if err != nil {
		return err
	}
	err = listener.SeekNewest()
	if err != nil {
		return err
	}
	listener.Listen(response)
	return nil
}


// NewFabricClientFromConfig create a new FabricClient from ClientConfig
func NewFabricClientFromConfig(config ClientConfig) (*FabricClient, error) {
	var crypto CryptoSuite
	var err error
	switch config.CryptoConfig.Family {
	case "ecdsa":
		crypto, err = NewECCryptSuiteFromConfig(config.CryptoConfig)
		if err != nil {
			return nil, err
		}
	default:
		return nil, ErrInvalidAlgorithmFamily
	}

	peers := make(map[string]*Peer)
	for name, p := range config.Peers {
		newPeer, err := NewPeerFromConfig(p)
		if err != nil {
			return nil, err
		}
		newPeer.Name = name
		peers[name] = newPeer

	}

	eventPeers := make(map[string]*Peer)
	for name, p := range config.EventPeers {
		newEventPeer, err := NewPeerFromConfig(p)
		if err != nil {
			return nil, err
		}
		newEventPeer.Name = name
		eventPeers[name] = newEventPeer
	}

	orderers := make(map[string]*Orderer)
	for name, o := range config.Orderers {
		newOrderer, err := NewOrdererFromConfig(o)
		if err != nil {
			return nil, err
		}
		newOrderer.Name = name
		orderers[name] = newOrderer
	}
	client := FabricClient{Peers: peers, EventPeers: eventPeers, Orderers: orderers, Crypto: crypto}
	return &client, nil
}

// NewFabricClient creates new client from provided config file.
func NewFabricClient(path string) (*FabricClient, error) {
	config, err := NewClientConfig(path)
	if err != nil {
		return nil, err
	}
	return NewFabricClientFromConfig(*config)
}

func (c FabricClient) getPeers(names []string) []*Peer {
	res := make([]*Peer, 0, len(names))
	for _, p := range names {
		if fp, ok := c.Peers[p]; ok {
			res = append(res, fp)
		}
	}
	return res
}

func (c FabricClient) getEventPeers(names []string) []*Peer {
	res := make([]*Peer, 0, len(names))
	for _, p := range names {
		if fp, ok := c.EventPeers[p]; ok {
			res = append(res, fp)
		}
	}
	return res
}
