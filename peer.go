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
)

// Peer expose API's to communicate with peer
type Peer struct {
	Name string
	Uri  string
	Opts []grpc.DialOption
	caPath string
	Conn *grpc.ClientConn
}

// PeerResponse is response from peer transaction request
type PeerResponse struct {
	Response *peer.ProposalResponse
	Err      error
	Name     string
}

// Endorse sends single transaction to single peer.
func (p *Peer) Endorse(resp chan *PeerResponse, prop *peer.SignedProposal) {
	if p.Conn==nil{
		p.Opts=append(p.Opts,grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(GRPC_MAX_SIZE),
			grpc.MaxCallSendMsgSize(GRPC_MAX_SIZE)))
		conn, err := grpc.Dial(p.Uri, p.Opts...)
		if err != nil {
			resp <- &PeerResponse{Response: nil, Err: err,Name:p.Name}
			return
		}
		p.Conn=conn
	}
	proposalResp, err := peer.NewEndorserClient(p.Conn).ProcessProposal(context.Background(), prop)
	if err != nil {
		resp <- &PeerResponse{Response: nil, Name: p.Name, Err: err}
		return
	}
	resp <- &PeerResponse{Response: proposalResp, Name: p.Name, Err: nil}
	return
}

// NewPeerFromConfig creates new peer from provided config
func NewPeerFromConfig(conf PeerConfig) (*Peer,error) {
	p := Peer{Uri: conf.Host,caPath:conf.TlsPath}
	if conf.Insecure {
		p.Opts = []grpc.DialOption{grpc.WithInsecure()}
	} else if p.caPath != "" {
		creds, err := credentials.NewClientTLSFromFile(p.caPath, "")
		if err != nil {
			return nil, fmt.Errorf("cannot read peer %s credentials err is: %v", p.Name, err)
		}
		p.Opts = append(p.Opts, grpc.WithTransportCredentials(creds))
	}
	p.Opts = append(p.Opts, grpc.WithBlock())
	p.Opts = append(p.Opts, grpc.WithTimeout(3*time.Second))
	return &p,nil
}
