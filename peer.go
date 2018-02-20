/*
Copyright: Cognition Foundry. All Rights Reserved.
License: Apache License Version 2.0
*/
package gohfc

import (
	"google.golang.org/grpc"
	"github.com/hyperledger/fabric/protos/peer"
	"context"
	"fmt"
	"google.golang.org/grpc/credentials"
	"time"
	"google.golang.org/grpc/keepalive"
)

// Peer expose API's to communicate with peer
type Peer struct {
	Name   string
	Uri    string
	MspId  string
	Opts   []grpc.DialOption
	caPath string
	conn   *grpc.ClientConn
	client peer.EndorserClient
}

// PeerResponse is response from peer transaction request
type PeerResponse struct {
	Response *peer.ProposalResponse
	Err      error
	Name     string
}

// Endorse sends single transaction to single peer.
func (p *Peer) Endorse(resp chan *PeerResponse, prop *peer.SignedProposal) {
	if p.conn == nil {
		conn, err := grpc.Dial(p.Uri, p.Opts...)
		if err != nil {
			resp <- &PeerResponse{Response: nil, Err: err, Name: p.Name}
			return
		}
		p.conn = conn
		p.client = peer.NewEndorserClient(p.conn)
	}

	proposalResp, err := p.client.ProcessProposal(context.Background(), prop)
	if err != nil {
		resp <- &PeerResponse{Response: nil, Name: p.Name, Err: err}
		return
	}
	resp <- &PeerResponse{Response: proposalResp, Name: p.Name, Err: nil}
}

// NewPeerFromConfig creates new peer from provided config
func NewPeerFromConfig(conf PeerConfig) (*Peer, error) {
	p := Peer{Uri: conf.Host, caPath: conf.TlsPath}
	if !conf.UseTLS {
		p.Opts = []grpc.DialOption{grpc.WithInsecure()}
	} else if p.caPath != "" {
		creds, err := credentials.NewClientTLSFromFile(p.caPath, "")
		if err != nil {
			return nil, fmt.Errorf("cannot read peer %s credentials err is: %v", p.Name, err)
		}
		p.Opts = append(p.Opts, grpc.WithTransportCredentials(creds))
	}

	p.Opts = append(p.Opts,
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                time.Duration(1) * time.Minute,
			Timeout:             time.Duration(20) * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.WithBlock(),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(maxRecvMsgSize),
			grpc.MaxCallSendMsgSize(maxSendMsgSize)))
	return &p, nil
}
