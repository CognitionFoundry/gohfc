/*
Copyright: Cognition Foundry. All Rights Reserved.
License: Apache License Version 2.0
*/
package gohfc

import (
	"context"
	"google.golang.org/grpc"
	"time"
	"fmt"
	"github.com/hyperledger/fabric/protos/orderer"
	"math"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/protos/peer"
)

const (
	EventTypeFullBlock = iota
	EventTypeFiltered
)

const (
	maxRecvMsgSize = 100 * 1024 * 1024
	maxSendMsgSize = 100 * 1024 * 1024
)

var (
	oldest  = &orderer.SeekPosition{Type: &orderer.SeekPosition_Oldest{Oldest: &orderer.SeekOldest{}}}
	newest  = &orderer.SeekPosition{Type: &orderer.SeekPosition_Newest{Newest: &orderer.SeekNewest{}}}
	maxStop = &orderer.SeekPosition{Type: &orderer.SeekPosition_Specified{Specified: &orderer.SeekSpecified{Number: math.MaxUint64}}}
)

type deliveryClient interface {
	Send(*common.Envelope) error
	Recv() (*peer.DeliverResponse, error)
}

type EventListener struct {
	Peer         Peer
	Context      context.Context
	Identity     Identity
	Crypto       CryptoSuite
	ChannelId    string
	ListenerType int
	FullBlock    bool
	connection   *grpc.ClientConn
	client       deliveryClient
}

type EventBlockResponse struct {
	Error        error
	ChannelId    string
	BlockHeight  uint64
	Transactions []EventBlockResponseTransaction
	RawBlock     []byte
}

type EventBlockResponseTransaction struct {
	Id          string
	Type        string
	Status      string
	ChainCodeId string
	Events      []EventBlockResponseTransactionEvent
}

type EventBlockResponseTransactionEvent struct {
	Name  string
	Value []byte
}

func (e *EventListener) newConnection() error {



	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	conn, err := grpc.DialContext(ctx, e.Peer.Uri, e.Peer.Opts...)
	if err != nil {
		return fmt.Errorf("cannot make new connection to: %s err: %v", e.Peer.Uri, err)
	}
	e.connection = conn
	switch e.ListenerType {
	case EventTypeFiltered:
		client, err := peer.NewDeliverClient(e.connection).DeliverFiltered(e.Context)
		if err != nil {
			return err
		}
		e.client = client
	case EventTypeFullBlock:
		client, err := peer.NewDeliverClient(e.connection).Deliver(e.Context)
		if err != nil {
			return err
		}
		e.client = client
	default:
		return fmt.Errorf("invalid listener type provided")
	}
	return nil
}

func (e *EventListener) SeekNewest() error {
	if e.connection == nil || e.client == nil {
		return fmt.Errorf("cannot seek no connection or client")
	}
	seek, err := e.createSeekEnvelope(newest, maxStop)
	if err != nil {
		return err
	}
	return e.client.Send(seek)
}

func (e *EventListener) SeekOldest() error {
	if e.connection == nil || e.client == nil {
		return fmt.Errorf("cannot seek no connection or client")
	}
	seek, err := e.createSeekEnvelope(oldest, maxStop)
	if err != nil {
		return err
	}
	return e.client.Send(seek)
}

func (e *EventListener) SeekSingle(num uint64) error {
	if e.connection == nil || e.client == nil {
		return fmt.Errorf("cannot seek no connection or client")
	}
	pos := &orderer.SeekPosition{Type: &orderer.SeekPosition_Specified{Specified: &orderer.SeekSpecified{Number: num}}}
	seek, err := e.createSeekEnvelope(pos, pos)
	if err != nil {
		return err
	}
	return e.client.Send(seek)
}

func (e *EventListener) SeekRange(start, end uint64) error {
	if e.connection == nil || e.client == nil {
		return fmt.Errorf("cannot seek no connection or client")
	}
	if start > end {
		return fmt.Errorf("start: %d cannot be bigger than end: %d", start, end)
	}
	startPos := &orderer.SeekPosition{Type: &orderer.SeekPosition_Specified{Specified: &orderer.SeekSpecified{Number: start}}}
	endPos := &orderer.SeekPosition{Type: &orderer.SeekPosition_Specified{Specified: &orderer.SeekSpecified{Number: end}}}
	seek, err := e.createSeekEnvelope(startPos, endPos)
	if err != nil {
		return err
	}
	return e.client.Send(seek)
}

func (e *EventListener) Listen(response chan<- EventBlockResponse) {
	go func() {
		for {
			msg, err := e.client.Recv()
			if err != nil {
				response <- EventBlockResponse{Error: fmt.Errorf("error receiving data:%v", err)}
				return
			}
			switch t := msg.Type.(type) {
			case *peer.DeliverResponse_Block:
				response <- *e.parseFullBlock(t, e.FullBlock)
			case *peer.DeliverResponse_FilteredBlock:
				response <- *e.parseFilteredBlock(t, e.FullBlock)
			}
		}
	}()
}

func (e *EventListener) parseFilteredBlock(block *peer.DeliverResponse_FilteredBlock, fullBlock bool) (*EventBlockResponse) {

	response := &EventBlockResponse{
		ChannelId:    block.FilteredBlock.ChannelId,
		BlockHeight:  block.FilteredBlock.Number,
		Transactions: make([]EventBlockResponseTransaction, len(block.FilteredBlock.FilteredTransactions)),
	}
	if fullBlock {
		m, err := proto.Marshal(block.FilteredBlock)
		if err != nil {
			response.Error = err
			return response
		}
		response.RawBlock = m
	}

	for _, t := range block.FilteredBlock.FilteredTransactions {
		transaction := EventBlockResponseTransaction{
			Type:   common.HeaderType_name[int32(t.Type)],
			Id:     t.Txid,
			Status: peer.TxValidationCode_name[int32(t.TxValidationCode)],
		}

		if t.Type != common.HeaderType_ENDORSER_TRANSACTION {
			continue
		}
		switch data := t.Data.(type) {
		case *peer.FilteredTransaction_TransactionActions:
			if len(data.TransactionActions.ChaincodeActions) > 0 {
				transaction.ChainCodeId = data.TransactionActions.ChaincodeActions[0].ChaincodeEvent.ChaincodeId
				for _, e := range data.TransactionActions.ChaincodeActions {
					transaction.Events = append(transaction.Events, EventBlockResponseTransactionEvent{
						Name: e.ChaincodeEvent.EventName,
					})
				}
			}
			response.Transactions = append(response.Transactions, transaction)
		default:
			response.Error = fmt.Errorf("filterd actions are with unknown type: %T", t.Data)
			return response
		}
	}
	return response
}

func (e *EventListener) parseFullBlock(block *peer.DeliverResponse_Block, fullBlock bool) (*EventBlockResponse) {

	response := &EventBlockResponse{
		BlockHeight: block.Block.Header.Number,
	}
	if fullBlock {
		m, err := proto.Marshal(block.Block)
		if err != nil {
			response.Error = err
			return response
		}
		response.RawBlock = m
	}
	for idx, pl := range block.Block.Data.Data {
		transaction := EventBlockResponseTransaction{}
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

		response.ChannelId = header.ChannelId
		transaction.Id = header.TxId

		transaction.Status = peer.TxValidationCode_name[int32(block.Block.Metadata.Metadata[2][idx])]
		transaction.Type = common.HeaderType_name[header.Type]
		if common.HeaderType(header.Type) == common.HeaderType_ENDORSER_TRANSACTION {
			transaction.ChainCodeId = ex.ChaincodeId.Name
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
				transaction.Events = append(transaction.Events,
					EventBlockResponseTransactionEvent{Name: ccEvent.EventName, Value: ccEvent.Payload})
			}
		}
		response.Transactions = append(response.Transactions, transaction)
	}

	return response
}

func (e *EventListener) createSeekEnvelope(start *orderer.SeekPosition, stop *orderer.SeekPosition) (*common.Envelope, error) {

	marshaledIdentity, err := marshalProtoIdentity(e.Identity)
	if err != nil {
		return nil, err
	}
	nonce, err := generateRandomBytes(24)
	if err != nil {
		return nil, err
	}

	channelHeader, err := proto.Marshal(&common.ChannelHeader{
		Type:    int32(common.HeaderType_DELIVER_SEEK_INFO),
		Version: 0,
		Timestamp: &timestamp.Timestamp{
			Seconds: time.Now().Unix(),
			Nanos:   0,
		},
		ChannelId: e.ChannelId,
		Epoch:     0,
		// TlsCertHash:[]
	})
	if err != nil {
		return nil, err
	}

	sigHeader, err := proto.Marshal(&common.SignatureHeader{
		Creator: marshaledIdentity,
		Nonce:   nonce,
	})
	if err != nil {
		return nil, err
	}

	data, err := proto.Marshal(&orderer.SeekInfo{
		Start:    start,
		Stop:     stop,
		Behavior: orderer.SeekInfo_BLOCK_UNTIL_READY,
	})
	if err != nil {
		return nil, err
	}

	payload, err := proto.Marshal(&common.Payload{
		Header: &common.Header{
			ChannelHeader:   channelHeader,
			SignatureHeader: sigHeader,
		},
		Data: data,
	})
	if err != nil {
		return nil, err
	}

	sig, err := e.Crypto.Sign(payload, e.Identity.PrivateKey)
	if err != nil {
		return nil, err
	}

	return &common.Envelope{Payload: payload, Signature: sig}, nil
}

func NewEventListener(ctx context.Context, crypto CryptoSuite, identity Identity, p Peer, channelId string, listenerType int) (*EventListener, error) {
	if crypto == nil {
		return nil, fmt.Errorf("cryptoSuite cannot be nil")
	}

	listener := EventListener{
		Context:      ctx,
		Peer:         p,
		Identity:     identity,
		ChannelId:    channelId,
		Crypto:       crypto,
		ListenerType: listenerType,
		FullBlock:    false,
	}

	if err := listener.newConnection(); err != nil {
		return nil, err
	}

	return &listener, nil
}