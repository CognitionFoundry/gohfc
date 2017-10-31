/*
Copyright: Cognition Foundry. All Rights Reserved.
License: Apache License Version 2.0
*/
package gohfc

import (
	"context"
	"google.golang.org/grpc"
	"github.com/hyperledger/fabric/protos/peer"
	"github.com/golang/protobuf/proto"
	"encoding/pem"
	"github.com/hyperledger/fabric/protos/msp"
	"io"
	"github.com/hyperledger/fabric/protos/common"
)

// BlockEventResponse holds event response when block is committed to peer.
type BlockEventResponse struct {
	// Error is error message.
	Error error
	// TxId is transaction id that generates this event
	TxID             string
	ChannelName      string
	ChainCodeName    string
	ChainCodeVersion string
	Status           int32
	CCEvents         []*CCEvent
}

// CCEvent represent custom event send from chaincode using `stub.SetEvent`
type CCEvent struct {
	EventName    string
	EventPayload []byte
}

type eventHub struct {
	connection *grpc.ClientConn
	client     peer.Events_ChatClient
}

func (e *eventHub) connect(ctx context.Context, p *Peer) (error) {
	p.Opts = append(p.Opts, grpc.WithBlock())
	conn, err := grpc.Dial(p.Uri, p.Opts...)
	if err != nil {
		return err
	}
	e.connection = conn
	event := peer.NewEventsClient(conn)
	cl, err := event.Chat(ctx)
	if err != nil {
		return err
	}
	e.client = cl
	return nil
}

func (e *eventHub) register(mspId string, identity *Identity, crypto CryptoSuite) (error) {
	creator, err := proto.Marshal(&msp.SerializedIdentity{
		Mspid:   mspId,
		IdBytes: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: identity.Certificate.Raw})})
	if err != nil {
		return err
	}

	interest := &peer.Event{Event: &peer.Event_Register{Register: &peer.Register{
		Events: []*peer.Interest{
			{EventType: peer.EventType_BLOCK},
		}}}, Creator: creator}
	evtBytes, err := proto.Marshal(interest)
	if err != nil {
		return err
	}

	sb, err := crypto.Sign(evtBytes, identity.PrivateKey)
	if err != nil {
		return err
	}
	sigEvent := peer.SignedEvent{EventBytes: evtBytes, Signature: sb}
	if err = e.client.Send(&sigEvent); err != nil {
		return err
	}
	return nil
}

func (e *eventHub) disconnect() {
	e.client.CloseSend()
	e.connection.Close()
}

func newEventListener(ctx context.Context, response chan<- BlockEventResponse, crypto CryptoSuite, identity *Identity, mspId string, p *Peer) (error) {
	hub := new(eventHub)
	err := hub.connect(ctx, p)
	if err != nil {
		return err
	}
	err = hub.register(mspId, identity, crypto)
	if err != nil {
		return err
	}
	go hub.readBlock(response)
	return nil
}

func (e *eventHub) readBlock(response chan<- BlockEventResponse) {
	for {
		in, err := e.client.Recv()
		if err == io.EOF {
			e.disconnect()
			return
		}
		if err != nil {
			response <- BlockEventResponse{Error: err}
			e.disconnect()
			return
		}

		switch in.Event.(type) {
		case *peer.Event_Block:
			meta := in.GetBlock().Metadata.Metadata
			for i, bd := range in.GetBlock().Data.Data {
				response <- decodeEventBlock(bd, i, meta)
			}

		}
	}
}

func decodeEventBlock(pl []byte, idx int, metadata [][]byte) (BlockEventResponse) {
	response := BlockEventResponse{}
	envelope := new(common.Envelope)
	payload := new(common.Payload)
	header := new(common.ChannelHeader)
	ex := &peer.ChaincodeHeaderExtension{}
	if err := proto.Unmarshal(pl, envelope); err != nil {
		response.Error = err
		return response
	}
	if err := proto.Unmarshal(envelope.Payload, payload); err != nil {
		response.Error = err
	}
	if err := proto.Unmarshal(payload.Header.ChannelHeader, header); err != nil {
		response.Error = err
		return response
	}
	if err := proto.Unmarshal(header.Extension, ex); err != nil {
		response.Error = err
		return response
	}

	response.TxID = header.TxId
	response.ChannelName = header.ChannelId
	response.ChainCodeName = ex.ChaincodeId.Name
	response.ChainCodeVersion = ex.ChaincodeId.Version
	response.Status = int32(metadata[2][idx])

	if common.HeaderType(header.Type) == common.HeaderType_ENDORSER_TRANSACTION {
		tx := &peer.Transaction{}
		err := proto.Unmarshal(payload.Data, tx)
		if err != nil {
			response.Error = err
			return response
		}

		chainCodeActionPayload := &peer.ChaincodeActionPayload{}
		err = proto.Unmarshal(tx.Actions[0].Payload, chainCodeActionPayload)
		if err != nil {
			response.Error = err
			return response
		}

		propRespPayload := &peer.ProposalResponsePayload{}
		err = proto.Unmarshal(chainCodeActionPayload.Action.ProposalResponsePayload, propRespPayload)
		if err != nil {
			response.Error = err
			return response
		}

		caPayload := &peer.ChaincodeAction{}
		err = proto.Unmarshal(propRespPayload.Extension, caPayload)
		if err != nil {
			response.Error = err
			return response
		}
		ccEvent := &peer.ChaincodeEvent{}
		err = proto.Unmarshal(caPayload.Events, ccEvent)
		if err != nil {
			response.Error = err
			return response
		}
		if ccEvent != nil {
			response.CCEvents=append(response.CCEvents,&CCEvent{EventName:ccEvent.EventName,EventPayload:ccEvent.Payload})
		}
	}
	return response
}
