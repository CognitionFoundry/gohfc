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
)

// FabricClient expose API's to work with Hyperledger Fabric
type FabricClient struct {
	Crypto     CryptoSuite
	Peers      map[string]*Peer
	Orderers   map[string]*Orderer
	EventPeers map[string]*Peer
}

// CreateChannel read channel config generated from configtxgen and send it to orderer
// This step is needed before any peer is able to join the channel.
func (c *FabricClient) CreateChannel(identity *Identity, path string, channel *Channel, orderer string) (error) {

	ord, ok := c.Orderers[orderer]
	if !ok {
		return ErrInvalidOrdererName
	}

	envelope, err := decodeChannelFromFs(path)
	if err != nil {
		return err
	}
	ou, err := buildAndSignChannelConfig(identity, envelope.GetPayload(), c.Crypto, channel)
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
// Channel must be created before this operation using CreateChannel or manually using CLI interface.
// Orderers must be aware of this channel, otherwise operation will fail.
func (c *FabricClient) JoinChannel(identity *Identity, channel *Channel, peers []string, orderer string) ([]*PeerResponse, error) {
	ord, ok := c.Orderers[orderer]
	if !ok {
		return nil, ErrInvalidOrdererName
	}

	execPeers := c.getPeers(peers)
	if len(peers) != len(execPeers) {
		return nil, ErrPeerNameNotFound
	}

	block, err := ord.getGenesisBlock(identity, c.Crypto, channel)

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

	invocationBytes, err := chainCodeInvocationSpec(&chainCode)
	if err != nil {
		return nil, err
	}
	creator, err := marshalProtoIdentity(identity, channel)
	if err != nil {
		return nil, err
	}
	txId, err := newTransactionId(creator)
	if err != nil {
		return nil, err
	}
	ext := &peer.ChaincodeHeaderExtension{ChaincodeId: &peer.ChaincodeID{Name: CSCC}}
	channelHeaderBytes, err := channelHeader(common.HeaderType_ENDORSER_TRANSACTION, txId, nil, 0, ext)
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

// InstallChainCode install chainCode to one or many peers. Peer must be join the channel where chaincode will be installed.
func (c *FabricClient) InstallChainCode(identity *Identity, req *InstallRequest, peers []string) ([]*PeerResponse, error) {
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
// operation parameter can be `deploy` or `upgrade`.
func (c *FabricClient) InstantiateChainCode(identity *Identity, req *ChainCode, peers []string, orderer string,operation string) (*orderer.BroadcastResponse, error) {
	ord, ok := c.Orderers[orderer]
	if !ok {
		return nil, ErrInvalidOrdererName
	}

	execPeers := c.getPeers(peers)
	if len(peers) != len(execPeers) {
		return nil, ErrPeerNameNotFound
	}

	prop, err := createInstantiateProposal(identity, req,operation)
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
func (c *FabricClient) QueryInstalledChainCodes(identity *Identity, mspId string, peers []string) ([]*ChainCodesResponse, error) {
	execPeers := c.getPeers(peers)
	if len(peers) != len(execPeers) {
		return nil, ErrPeerNameNotFound
	}

	chainCode := ChainCode{
		Channel: &Channel{MspId: mspId},
		Name:    LSCC,
		Type:    ChaincodeSpec_GOLANG,
		Args:    []string{"getinstalledchaincodes"},
	}

	prop, err := createTransactionProposal(identity, &chainCode)
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
func (c *FabricClient) QueryInstantiatedChainCodes(identity *Identity, channel *Channel, peers []string) ([]*ChainCodesResponse, error) {
	execPeers := c.getPeers(peers)
	if len(peers) != len(execPeers) {
		return nil, ErrPeerNameNotFound
	}

	prop, err := createTransactionProposal(identity, &ChainCode{
		Channel: channel,
		Name:    LSCC,
		Type:    ChaincodeSpec_GOLANG,
		Args:    []string{"getchaincodes"},
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
func (c *FabricClient) QueryChannels(identity *Identity, mspId string, peers []string) ([]*QueryChannelsResponse, error) {
	execPeers := c.getPeers(peers)
	if len(peers) != len(execPeers) {
		return nil, ErrPeerNameNotFound
	}

	chainCode := ChainCode{
		Channel: &Channel{MspId: mspId},
		Name:    CSCC,
		Type:    ChaincodeSpec_GOLANG,
		Args:    []string{"GetChannels"},
	}

	prop, err := createTransactionProposal(identity, &chainCode)
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
func (c *FabricClient) QueryChannelInfo(identity *Identity, channel *Channel, peers []string) ([]*QueryChannelInfoResponse, error) {
	execPeers := c.getPeers(peers)
	if len(peers) != len(execPeers) {
		return nil, ErrPeerNameNotFound
	}
	chainCode := ChainCode{
		Channel: channel,
		Name:    QSCC,
		Type:    ChaincodeSpec_GOLANG,
		Args:    []string{"GetChainInfo", channel.ChannelName},
	}

	prop, err := createTransactionProposal(identity, &chainCode)
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
func (c *FabricClient) Query(identity *Identity, chainCode *ChainCode, peers []string) ([]*QueryResponse, error) {
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
// When Invoke returns with success this is not granite that ledger was update. Event with `transaction_id`
// returned from Invoke will be send when actual block is committed.
// It is responsibility of SDK user to build logic that handle successful and failed commits.
// If chaincode execute `shim.Error` or simulation fails for other reasons this is considered as simulation failure.
// In such case Invoke will return the error and transaction will NOT be send to orderer.
func (c *FabricClient) Invoke(identity *Identity, chainCode *ChainCode, peers []string, orderer string) (*InvokeResponse, error) {
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
func (c *FabricClient) QueryTransaction(identity *Identity, channel *Channel, txId string, peers []string) ([]*QueryTransactionResponse, error) {
	execPeers := c.getPeers(peers)
	if len(peers) != len(execPeers) {
		return nil, ErrPeerNameNotFound
	}
	chainCode := ChainCode{Channel: channel, Name: QSCC, Type: ChaincodeSpec_GOLANG,
		Args: []string{"GetTransactionByID", channel.ChannelName, txId}}

	prop, err := createTransactionProposal(identity, &chainCode)
	if err != nil {
		return nil, err
	}
	proposal, err := signedProposal(prop.proposal, identity, c.Crypto)
	if err != nil {
		return nil, err
	}
	r := sendToPeers(execPeers, proposal)
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

// Listen start listening for block events on particular peer and return all transactions from committed block.
// Function is non blocking and events will be send using channel. No data is filtered/omitted.
// To stop listen provide context.WithCancel and execute cancel.
// The caller is responsible to read the channel, otherwise Listen will block until channel is read or overflow occurs.
// Every message will represent single transaction in a block including its status, if event/s are sent from chaincode
// they will be available in event response `CCEvents`.
// SDK user can call Listen multiple times on different event peers. This is useful to have redundancy. If one peer fails,
// events from other peers will be received. All Listen calls can share same channel.
// In such scenarios every peer will send its own transactions from blocks. It is SDK user responsibility to
// handle multiple identical events in same channel.
func (c *FabricClient) Listen(ctx context.Context, identity *Identity, eventPeer, mspId string, response chan<- BlockEventResponse) (error) {
	ep, ok := c.EventPeers[eventPeer]
	if !ok {
		return ErrPeerNameNotFound
	}
	return newEventListener(ctx, response, c.Crypto, identity, mspId, ep)
}

// NewFabricClient creates new client from provided config file.
func NewFabricClient(path string) (*FabricClient, error) {
	config, err := NewClientConfig(path)
	if err != nil {
		return nil, err
	}

	var crypto CryptoSuite
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
		newPeer.Name = name
		if err != nil {
			return nil, err
		}
		peers[name] = newPeer

	}

	eventPeers := make(map[string]*Peer)
	for name, p := range config.EventPeers {
		newEventPeer, err := NewPeerFromConfig(p)
		newEventPeer.Name = name
		if err != nil {
			return nil, err
		}
		eventPeers[name] = newEventPeer
	}

	orderers := make(map[string]*Orderer)
	for name, o := range config.Orderers {
		newOrderer, err := NewOrdererFromConfig(o)
		newOrderer.Name = name
		if err != nil {
			return nil, err
		}
		orderers[name] = newOrderer
	}
	client := FabricClient{Peers: peers, EventPeers: eventPeers, Orderers: orderers, Crypto: crypto}
	return &client, nil
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
