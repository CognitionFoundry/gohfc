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
	"fmt"
	"io"
	"google.golang.org/grpc"
	"github.com/hyperledger/fabric/protos/peer"
	"context"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/protos/common"
	"github.com/hyperledger/fabric/protos/orderer"
)

// Peer represents a single peer
type Peer struct {
	// Name is name of the peer. It must be unique in all peers
	Name string
	// Url is access point for this peer
	Url string
	// Opts are grpc.DialOption that manage TlS verification, certificates and communication rules
	Opts []grpc.DialOption
}

type Orderer struct {
	// Name is name of the orderer. It must be unique in all orderers
	Name string
	// Url is access point for this orderer
	Url string
	// Opts are grpc.DialOption that manage TlS verification, certificates and communication rules
	Opts []grpc.DialOption
}

// Deliver delivers envelope to orderer for execution.
// Note that this method return only result of the connection and sending the envelope. Actual result depends by
// actual envelope and most of the times result will be send back as event.
func (o *Orderer) Deliver(envelope *common.Envelope) (*orderer.BroadcastResponse,error){
	conn, err := grpc.Dial(o.Url, o.Opts...)
	if err != nil {
		Logger.Errorf("Error connecting to orderer %s: %s", o.Name, err)
		return nil, err
	}
	defer conn.Close()
	client := orderer.NewAtomicBroadcastClient(conn)
	bk, err := client.Broadcast(context.Background())
	if err != nil {
		Logger.Errorf("Error sendig transaction to orderer %s: %s", o.Name, err)
		return nil, err
	}
	bk.Send(envelope)
	reply, err := bk.Recv()
	if err != nil {
		Logger.Errorf("Error recv Response from orderer %s: %s", o.Name, err)
		return nil, err
	}
	return reply,nil
}

// GetBlock gets block data for particular block. Actual block number and channel are defined in envelope message.
// Note that this method blocks until all block data is received or error occurs.
func (o *Orderer) GetBlock(envelope *common.Envelope) (*orderer.DeliverResponse_Block,error){
	conn, err := grpc.Dial(o.Url, o.Opts...)
	if err != nil {
		Logger.Errorf("Error connecting to orderer %s: %s", o.Name, err)
		return nil, err
	}
	defer conn.Close()
	client, err := orderer.NewAtomicBroadcastClient(conn).Deliver(context.TODO())
	if err != nil {
		Logger.Errorf("Error connecting orderer %s error: %s", o.Name, err)
		return nil, err
	}

	client.Send(envelope)
	var block *orderer.DeliverResponse_Block
L:
	for {
		msg, err := client.Recv()
		if err != nil {
			Logger.Errorf("Error recv data from orderer %s error: %s", o.Name, err)
			return nil, err
		}

		switch t := msg.Type.(type) {
		case *orderer.DeliverResponse_Status:
			if t.Status != common.Status_SUCCESS {
				Logger.Errorf("Delivery status from orderer %s is not 200: %s", o.Name, t.Status)
				return nil, ErrBadTransactionStatus
			}
			continue
		case *orderer.DeliverResponse_Block:
			block = t
			break L
		}
	}
	return block,nil
}

// EventResponse is response from Event
//TODO Only one event that is working for now is Block. When fabric fix this revisit this structure.
type EventResponse struct {
	// Error is error message.
	Error error
	// TxId is transaction id that generates this event
	TxID string
}

// NewPeerFromConfig creates new Peer from PeerConf
func NewPeerFromConfig(conf *PeerConf) *Peer {
	if conf.Insecure {
		return &Peer{Name: conf.Name, Url: conf.URL, Opts: []grpc.DialOption{grpc.WithInsecure()}}
	}
	return &Peer{Name: conf.Name, Url: conf.URL}
}

// NewOrdererFromConfig creates new orderer from OrdererConf
func NewOrdererFromConfig(conf *OrdererConf) *Orderer {
	if conf.Insecure {
		return &Orderer{Name: conf.Name, Url: conf.URL, Opts: []grpc.DialOption{grpc.WithInsecure()}}
	}
	return &Orderer{Name: conf.Name, Url: conf.URL}
}

// Event connects to event peer and listens for events sent from this peer.
// Note that all peers will send same events so it makes no sense to listen for events in more than one peer.
// If value is sent through doneChan channel, connection to peer will be closed and eventChan channel will be closed.
//TODO fabric send events only for Block.
func (p *Peer) Event(eventChan chan *EventResponse, doneChan chan bool) error {

	conn, err := grpc.Dial(p.Url, p.Opts...)

	if err != nil {
		return err
	}
	event := peer.NewEventsClient(conn)
	cl, err := event.Chat(context.Background())
	if err != nil {
		return err

	}
	interest := &peer.Event{Event: &peer.Event_Register{Register: &peer.Register{
		Events: []*peer.Interest{
			{EventType: peer.EventType_REJECTION},
			{EventType: peer.EventType_REGISTER},
			{EventType: peer.EventType_CHAINCODE},
			{EventType: peer.EventType_BLOCK},

		}}}}
	if err = cl.Send(interest); err != nil {
		return err
	}
	//will close connection so blocking Recv will unblock with error and return
	go func() {
		select {
		case <-doneChan:
			conn.Close()
			return
		}
	}()
	go func() {
		for {
			in, err := cl.Recv()
			if err == io.EOF {
				close(eventChan)
				return
			}
			if err != nil {
				close(eventChan)
				return
			}
			switch in.Event.(type) {
			case *peer.Event_Block:
				eventChan <- func() *EventResponse {
					//TODO multiple Data?
					envelope := new(common.Envelope)
					payload := new(common.Payload)
					response := new(EventResponse)
					header := new(common.ChannelHeader)
					if err := proto.Unmarshal(in.GetBlock().Data.Data[0], envelope); err != nil {
						response.Error = err
						return response
					}
					if err := proto.Unmarshal(envelope.Payload, payload); err != nil {
						response.Error = err
						return response
					}
					if err := proto.Unmarshal(payload.Header.ChannelHeader, header); err != nil {
						response.Error = err
						return response
					}
					response.TxID = header.TxId
					return response
				}()
			case *peer.Event_Rejection:
				fmt.Println("Rejection")
			case *peer.Event_Register:
				fmt.Println("Register")
			case *peer.Event_ChaincodeEvent:
				fmt.Println("Chaincode")
			}
		}
	}()
	return nil
}
