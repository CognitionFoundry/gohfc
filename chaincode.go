/*
Copyright: Cognition Foundry. All Rights Reserved.
License: Apache License Version 2.0
*/
package gohfc

import (
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/protos/peer"
	"github.com/hyperledger/fabric/protos/common"
	"path/filepath"
	"strings"
	"os"
	"io"
	"bytes"
	"compress/gzip"
	"archive/tar"
	"path"
	"github.com/golang/protobuf/ptypes/timestamp"
	"time"
	"fmt"
)

type ChainCodeType int32

const (
	ChaincodeSpec_UNDEFINED ChainCodeType = 0
	ChaincodeSpec_GOLANG    ChainCodeType = 1
	ChaincodeSpec_NODE      ChainCodeType = 2
	ChaincodeSpec_CAR       ChainCodeType = 3
	ChaincodeSpec_JAVA      ChainCodeType = 4
)

// ChainCode the fields necessary to execute operation over chaincode.
type ChainCode struct {
	ChannelId    string
	Name         string
	Version      string
	Type         ChainCodeType
	Args         []string
	ArgBytes     []byte
	TransientMap map[string][]byte
	rawArgs      [][]byte
}

func (c *ChainCode) toChainCodeArgs() ([][]byte) {
	if len(c.rawArgs) > 0 {
		return c.rawArgs
	}
	args := make([][]byte, len(c.Args))
	for i, arg := range c.Args {
		args[i] = []byte(arg)
	}
	if len(c.ArgBytes) > 0 {
		args = append(args, c.ArgBytes)
	}
	return args
}

// InstallRequest holds fields needed to install chaincode
type InstallRequest struct {
	ChannelId        string
	ChainCodeName    string
	ChainCodeVersion string
	ChainCodeType    ChainCodeType
	Namespace        string
	SrcPath          string
	Libraries        []ChaincodeLibrary
}

type CollectionConfig struct {
	Name               string
	RequiredPeersCount int32
	MaximumPeersCount  int32
	Organizations      []string
}

type ChaincodeLibrary struct {
	Namespace string
	SrcPath   string
}

// ChainCodesResponse is the result of queering installed and instantiated chaincodes
type ChainCodesResponse struct {
	PeerName   string
	Error      error
	ChainCodes []*peer.ChaincodeInfo
}

// createInstallProposal read chaincode from provided source and namespace, pack it and generate install proposal
// transaction. Transaction is not send from this func
func createInstallProposal(identity Identity, req *InstallRequest) (*transactionProposal, error) {

	var packageBytes []byte
	var err error

	switch req.ChainCodeType {
	case ChaincodeSpec_GOLANG:
		packageBytes, err = packGolangCC(req.Namespace, req.SrcPath, req.Libraries)
		if err != nil {
			return nil, err
		}
	default:
		return nil, ErrUnsupportedChaincodeType
	}
	now := time.Now()
	depSpec, err := proto.Marshal(&peer.ChaincodeDeploymentSpec{
		ChaincodeSpec: &peer.ChaincodeSpec{
			ChaincodeId: &peer.ChaincodeID{Name: req.ChainCodeName, Path: req.Namespace, Version: req.ChainCodeVersion},
			Type:        peer.ChaincodeSpec_Type(req.ChainCodeType),
		},
		CodePackage:   packageBytes,
		EffectiveDate: &timestamp.Timestamp{Seconds: int64(now.Second()), Nanos: int32(now.Nanosecond())},
	})
	if err != nil {
		return nil, err
	}

	spec, err := chainCodeInvocationSpec(ChainCode{Type: req.ChainCodeType,
		Name: LSCC,
		Args: []string{"install"},
		ArgBytes: depSpec,
	})

	creator, err := marshalProtoIdentity(identity)
	if err != nil {
		return nil, err
	}
	txId, err := newTransactionId(creator)
	if err != nil {
		return nil, err
	}
	ccHdrExt := &peer.ChaincodeHeaderExtension{ChaincodeId: &peer.ChaincodeID{Name: LSCC}}

	channelHeaderBytes, err := channelHeader(common.HeaderType_ENDORSER_TRANSACTION, txId, req.ChannelId, 0, ccHdrExt)
	if err != nil {
		return nil, err
	}

	ccPropPayloadBytes, err := proto.Marshal(&peer.ChaincodeProposalPayload{
		Input:        spec,
		TransientMap: nil,
	})
	if err != nil {
		return nil, err
	}

	sigHeader, err := signatureHeader(creator, txId)
	if err != nil {
		return nil, err
	}
	header := header(sigHeader, channelHeaderBytes)

	hdrBytes, err := proto.Marshal(header)
	if err != nil {
		return nil, err
	}
	proposal, err := proposal(hdrBytes, ccPropPayloadBytes)
	if err != nil {
		return nil, err
	}
	return &transactionProposal{proposal: proposal, transactionId: txId.TransactionId}, nil

}

// createInstantiateProposal creates instantiate proposal transaction for already installed chaincode.
// transaction is not send from this func
func createInstantiateProposal(identity Identity, req *ChainCode, operation string, collectionConfig []byte) (*transactionProposal, error) {
	if operation != "deploy" && operation != "upgrade" {
		return nil, fmt.Errorf("install proposall accept only 'deploy' and 'upgrade' operations")
	}

	depSpec, err := proto.Marshal(&peer.ChaincodeDeploymentSpec{
		ChaincodeSpec: &peer.ChaincodeSpec{
			ChaincodeId: &peer.ChaincodeID{Name: req.Name, Version: req.Version},
			Type:        peer.ChaincodeSpec_Type(req.Type),
			Input:       &peer.ChaincodeInput{Args: req.toChainCodeArgs()},
		},
	})
	if err != nil {
		return nil, err
	}

	policy, err := defaultPolicy(identity.MspId)
	if err != nil {
		return nil, err
	}
	marshPolicy, err := proto.Marshal(policy)
	if err != nil {
		return nil, err
	}

	args := [][]byte{
		[]byte(operation),
		[]byte(req.ChannelId),
		depSpec,
		marshPolicy,
		[]byte("escc"),
		[]byte("vscc"),
	}
	if len(collectionConfig) > 0 {
		args = append(args, collectionConfig)
	}

	spec, err := chainCodeInvocationSpec(ChainCode{
		Type:    req.Type,
		Name:    LSCC,
		rawArgs: args,
	})

	creator, err := marshalProtoIdentity(identity)
	if err != nil {
		return nil, err
	}
	txId, err := newTransactionId(creator)
	if err != nil {
		return nil, err
	}
	headerExtension := &peer.ChaincodeHeaderExtension{ChaincodeId: &peer.ChaincodeID{Name: LSCC}}

	channelHeaderBytes, err := channelHeader(common.HeaderType_ENDORSER_TRANSACTION, txId, req.ChannelId, 0, headerExtension)
	if err != nil {
		return nil, err
	}
	payloadBytes, err := proto.Marshal(&peer.ChaincodeProposalPayload{Input: spec, TransientMap: req.TransientMap})
	if err != nil {
		return nil, err
	}
	signatureHeader, err := signatureHeader(creator, txId)
	if err != nil {
		return nil, err
	}
	headerBytes, err := proto.Marshal(header(signatureHeader, channelHeaderBytes))
	if err != nil {
		return nil, err
	}

	proposal, err := proposal(headerBytes, payloadBytes)
	if err != nil {
		return nil, err
	}
	return &transactionProposal{proposal: proposal, transactionId: txId.TransactionId}, nil

}

// packGolangCC read provided src expecting Golang source code, repackage it in provided namespace, and compress it
func packGolangCC(namespace, source string, libs []ChaincodeLibrary) ([]byte, error) {

	twBuf := new(bytes.Buffer)
	tw := tar.NewWriter(twBuf)

	var gzBuf bytes.Buffer
	zw := gzip.NewWriter(&gzBuf)

	concatLibs := append(libs, ChaincodeLibrary{SrcPath: source, Namespace: namespace})

	for _, s := range concatLibs {
		_, err := os.Stat(s.SrcPath)
		if err != nil {
			return nil, err
		}
		baseDir := path.Join("/src", s.Namespace)
		err = filepath.Walk(s.SrcPath,
			func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				header, err := tar.FileInfoHeader(info, "")
				if err != nil {
					return err
				}

				header.Mode = 0100000
				if baseDir != "" {
					header.Name = filepath.Join(baseDir, strings.TrimPrefix(path, s.SrcPath))
				}
				if header.Name == baseDir {
					return nil
				}

				if err := tw.WriteHeader(header); err != nil {
					return err
				}

				if info.IsDir() {
					return nil
				}

				file, err := os.Open(path)
				if err != nil {
					return err
				}
				defer file.Close()
				_, err = io.Copy(tw, file)

				return err
			})
		if err != nil {
			tw.Close()
			return nil, err
		}
	}
	_, err := zw.Write(twBuf.Bytes())
	if err != nil {
		return nil, err
	}
	tw.Close()
	zw.Close()
	return gzBuf.Bytes(), nil
}
