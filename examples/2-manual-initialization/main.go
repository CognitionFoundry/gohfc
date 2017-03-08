package main

import (
	"github.com/CognitionFoundry/gohfc"
	"fmt"
	"os"
	"google.golang.org/grpc"
)

func main() {
	kvStore, err := gohfc.NewFileKeyValue("./kvstore")
	if err != nil {
		fmt.Printf("Error creating kvstore %s\n", err)
		os.Exit(1)
	}
	//Crypto
	cryptoConfig := &gohfc.CryptConfig{AsymmetricAlgo: "P256-SHA256",
		AsymmetricAlgoFamily:                     "ecdsa",
		HashFamily:                               "SHA2",
		HashLevel:                                256}
	crypto, err := gohfc.NewECCryptSuite(cryptoConfig)
	if err != nil {
		fmt.Printf("Error creating crypto suite %s\n", err)
		os.Exit(1)
	}

	//CA
	// Here user can add custom http.Transport options
	caClient := &gohfc.FabricCAClientImpl{SkipTLSVerification: true,
		Url:                                              "http://localhost:7054",
		Crypto:                                           crypto,
		Transport:                                        nil}

	//peers and orderers
	//Here user can provide other grpc options
	peer0 := &gohfc.Peer{Name: "peer0", Url: "localhost:7051", Opts: []grpc.DialOption{grpc.WithInsecure()}}
	peer1 := &gohfc.Peer{Name: "peer1", Url: "localhost:7052", Opts: []grpc.DialOption{grpc.WithInsecure()}}
	orderer0 := &gohfc.Orderer{Name: "orderer0", Url: "localhost:7050", Opts: []grpc.DialOption{grpc.WithInsecure()}}
	peers := []*gohfc.Peer{peer0, peer1}
	orderers := []*gohfc.Orderer{orderer0}
	client := &gohfc.GohfcClient{Crypt: crypto, KVStore: kvStore, CAClient: caClient, Peers: peers, Orderers: orderers}
	client.Enroll("admin", "adminpw")
	/////

}
