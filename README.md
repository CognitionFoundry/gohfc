# GOHFC - Golang Hyperledger Fabric Client

This is SDK for Hyperledger Fabric written in pure Golang using minimum requirements.
This is not official SDK and does not follow official SDK API guidelines provided by Hyperledger team.
For the list of official SDK's refer to the official Hyperledger documentation.

It is designed to be easy to use and to be fast as possible. Currently, it outperforms the official Go SDK by far.

We are using it in our production applications, but no guarantees are provided.

This version will be updated and supported, so pull requests and reporting any issues are more than welcome.

## Dependency

```
go get -u golang.org/x/crypto/sha3
go get -u google.golang.org/grpc
go get -u github.com/golang/protobuf/{proto,protoc-gen-go}
go get -u gopkg.in/yaml.v2

```

## Fabric sample config
```

---
crypto:
  family: ecdsa
  algorithm: P256-SHA256
  hash: SHA2-256
orderers:
  orderer0:
    host: orderer.example.com:7050
    insecure: false
    tlsPath: ./crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/tls/server.crt
peers:
  peer0:
    host: peer0.org1.example.com:7051
    insecure: false
    tlsPath: ./crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/server.crt
  peer1:
    host: peer1.org1.example.com:8051
    insecure: false
    tlsPath: ./crypto-config/peerOrganizations/org1.example.com/peers/peer1.org1.example.com/tls/server.crt
eventPeers:
  peer0:
    host: peer0.org1.example.com:7053
    insecure: false
    tlsPath: ./crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/server.crt

```

## Fabric-ca sample config
```

---
url: http://127.0.0.1:7054
skipTLSValidation: true
crypto:
  family: ecdsa
  algorithm: P256-SHA256
  hash: SHA2-256

```

### Available cryptographic algorithms
| Family   | Algorithm   | Description                                      | 
|:--------:|:-----------:|--------------------------------------------------| 
| ecdsa    | P256-SHA256 | Elliptic curve is P256 and signature uses SHA256 |
| ecdsa    | P384-SHA384 | Elliptic curve is P384 and signature uses SHA384 |
| ecdsa    | P521-SHA512 | Elliptic curve is P521 and signature uses SHA512 |
| rsa      | ----        | RSA is not supported (for now) in Fabric         |

### Hash

| Family    | 
|:----------| 
| SHA2-256  |
| SHA2-384  |
| SHA3-256  |
| SHA3-384  |

## Basic concepts
Clients (fabric and CA) can be initialized from config file with a simple call, but the user can create the config "manually" and then create
the clients from this config. Useful if you are not using YAML files or configuration is located in other places.

CAClient is responsible for issuing certificates, registering users and revoking certificates.
If you are using another system for certificates this client can be omitted. 
In this case, your certificates must be put in `gohfc.Identity` struct.Gohfc has helper function `LoadCertFromFile` for this task.

FabricClient is used for practically any interaction with Fabric.

Most of the operations require transactions to be sent to specific peers or orderer.
FabricClient methods accept the name (as string) for the peer or order as they are specified in config file.
In many situations, it is not necessary to send requests to all peers and orderers.

When installing chaincode user must provide the path for the chaincode and namespace.
So if chaincode source is `/some/path/chaincode1` and namespace is `/org/org1/chaincode1` all files and sub folders under
`/some/path/chaincode1` will be added to the archive in folder `/org/org1/chaincode1`.
This is done so gohfc will not have an external dependency on GOPATH, and will allow more flexible operations in future.
Especially when nodejs and Java based chaincode are supported (in v.1.1 probably) 


## TODO
- Transaction decoding from the block is not implemented yet. So QueryTransaction and other functions for history will not return unmarshaled block data.
- Implement get block by number
- Better error responses and logging capabilities.
- Support Fabric 1.1 (when fabric 1.1 is released)
- Add the ability to specify a policy for instantiation, for now, the default policy is used. If this is critical, user can instantiate chaincode from peer CLI
- Add support for java and nodejs chaincode when Fabric add them officially as supported languages

### Init clients
```
c, err := gohfc.NewFabricClient("./client.yaml")
if err != nil {
    fmt.Printf("Error loading file: %v", err)
    os.Exit(1)
}

ca, err := gohfc.NewCAClient("./ca.yaml", nil)
if err != nil {
    fmt.Println(err)
    os.Exit(1)
}
```

gohfc.NewCAClient accept *http.Transport as second parameter.

### Enroll
```
identity, _, err := ca.Enroll("admin", "adminpw")
if err != nil {
    fmt.Println(err)
    os.Exit(1)
}
```

### Register
```
// identity is identity obtainet from Enroll. This identity must have the abiility to register new users.
rr := gohfc.CARegistrationRequest{EnrolmentId: "username", Secret: "qwerty", Affiliation: "org1", Type: "user"}
resp, err := ca.Register(identity, &rr)
if err != nil {
    fmt.Println(err)
}
```

### Create channel
```
// create channel require admin certificate.LoadCertFromFile is helper function that takes path for public and private keys
// and loads them for use.

pk:="./crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/admincerts/Admin@org1.example.com-cert.pem"
sk:="./crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/keystore/27c48b5b7bc5befba6720f196bc0ad3d0cbdbc51f7555933b124c97d6373fdbc_sk"
channelFile:="./channel-artifacts/channel.tx"
admin, err := gohfc.LoadCertFromFile(pk,sk)
if err != nil {
    fmt.Println(err)
}
channel := gohfc.Channel{ChannelName: "mychannel", MspId: "Org1MSP"}
err = client.CreateChannel(admin, channelFile, &channel, "orderer0")
```

### Join channel
```
pk:="./crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/admincerts/Admin@org1.example.com-cert.pem"
sk:="crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/keystore/27c48b5b7bc5befba6720f196bc0ad3d0cbdbc51f7555933b124c97d6373fdbc_sk"
admin, err := gohfc.LoadCertFromFile(pk,sk)
if err != nil {
    fmt.Println(err)
}
channel := gohfc.Channel{ChannelName: "mychannel", MspId: "Org1MSP"}
result, err := client.JoinChannel(admin, &channel, []string{"peer0", "peer1"}, "orderer0")
if err != nil {
    fmt.Print(err)
}
```

### Install chaincode

```
pk:="./crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/admincerts/Admin@org1.example.com-cert.pem"
sk:="./crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/keystore/27c48b5b7bc5befba6720f196bc0ad3d0cbdbc51f7555933b124c97d6373fdbc_sk"
admin, err := gohfc.LoadCertFromFile(pk,sk)
if err != nil {
    fmt.Println(err)
}
channel := &gohfc.Channel{ChannelName: "mychannel", MspId: "Org1MSP"}
req := &gohfc.InstallRequest{
    ChainCodeType:    gohfc.ChaincodeSpec_GOLANG,
    Channel:          channel,
    ChainCodeName:    "gatakka",
    ChainCodeVersion: "1.0",
    Namespace:        "/the/namespace/for/chaincode/",
    SrcPath:          "/some/folder/path/chaincode_example02/",
    Libraries: []gohfc.ChaincodeLibrary{
    			{
    				Namespace: "/the/namespace/for/chaincode/library",
    				SrcPath:   "/some/folder/path/for/library",
    			}},
}
result, err := client.InstallChainCode(admin, req, []string{"peer0"})
if err != nil {
    fmt.Print(err)
}
```

If chaincode depends on external libraries user can vendor this libraries.

If vendoring is not practical, user can add list of `Libraries` in `gohfc.InstallRequest`. Source code of this libraries will be included in the install package with provided namespace. It is responsibility of the user to prevent name collisions, cycle imports and other conflicts.   

### Instantiate

```
pk:="./crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/admincerts/Admin@org1.example.com-cert.pem"
sk:="./crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/keystore/27c48b5b7bc5befba6720f196bc0ad3d0cbdbc51f7555933b124c97d6373fdbc_sk"
admin, err := gohfc.LoadCertFromFile(pk,sk)
if err != nil {
    fmt.Println(err)
}

channel := &gohfc.Channel{ChannelName: "mychannel", MspId: "Org1MSP"}
req := &gohfc.ChainCode{
    Type:    gohfc.ChaincodeSpec_GOLANG,
    Channel: channel,
    Name:    "gatakka",
    Version: "1.0",
    Args:    []string{"init", "a", "100", "b", "200"},
}
result, err := client.InstantiateChainCode(admin, req, []string{"peer0"}, "orderer0","deploy")
if err != nil {
    fmt.Print(err)
}

```

### Query installed chaincodes

```
pk:="./crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/admincerts/Admin@org1.example.com-cert.pem"
sk:="./crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/keystore/27c48b5b7bc5befba6720f196bc0ad3d0cbdbc51f7555933b124c97d6373fdbc_sk"
admin, err := gohfc.LoadCertFromFile(pk,sk)
if err != nil {
    fmt.Println(err)
}

result, err := client.QueryInstalledChainCodes(admin, "Org1MSP", []string{"peer0"})
if err != nil {
    fmt.Print(err)
}
```

### Query instantiated chaincodes

```
pk:="./crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/admincerts/Admin@org1.example.com-cert.pem"
sk:="./crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/keystore/27c48b5b7bc5befba6720f196bc0ad3d0cbdbc51f7555933b124c97d6373fdbc_sk"
admin, err := gohfc.LoadCertFromFile(pk,sk)
if err != nil {
    fmt.Println(err)
}

channel := &gohfc.Channel{
    MspId:       "Org1MSP",
    ChannelName: "mychannel",
}

result, err := client.QueryInstantiatedChainCodes(admin, channel, []string{"peer0"})
if err != nil {
    fmt.Print(err)
}
```

### Query channels

```
// identity is identity returned from ca.Enroll or Admin
result, err := client.QueryChannels(identity, "Org1MSP", []string{"peer0", "peer1"})
if err != nil {
    fmt.Print(err)
}
```

### Query channel Info

```

channel := &gohfc.Channel{
    MspId:       "Org1MSP",
    ChannelName: "mychannel",
}
// identity is identity returned from ca.Enroll or Admin
result, err := client.QueryChannelInfo(identity, channel, []string{"peer0", "peer1"})
if err != nil {
    fmt.Print(err)
}

```

### Query Transaction

```
channel := &gohfc.Channel{
    MspId:       "Org1MSP",
    ChannelName: "mychannel",
}
// txid is transaction ID that we are interested in
txid:="c9b212d3dee1704b16b878f45205bd567a64e085a039f957c133452246717f9f"

// identity is identity returned from ca.Enroll or Admin
result, err := client.QueryTransaction(identity, channel,txid, []string{"peer0"})
if err != nil {
    fmt.Print(err)
}
```

### Query
```
channel := &gohfc.Channel{
    MspId:       "Org1MSP",
    ChannelName: "mychannel",
}

chaincode := &gohfc.ChainCode{
    Channel: channel,
    Type:    gohfc.ChaincodeSpec_GOLANG,
    Name:    "gatakka",
    Version: "1.0",
    Args:    []string{"query", "a"},
}

// identity is identity returned from ca.Enroll or Admin
result, err := client.Query(identity, chaincode, []string{"peer0"})
if err != nil {
    fmt.Print(err)
}
```

### Invoke
```
channel := &gohfc.Channel{
    MspId:       "Org1MSP",
    ChannelName: "mychannel",
}

chaincode := &gohfc.ChainCode{
    Channel: channel,
    Type:    gohfc.ChaincodeSpec_GOLANG,
    Name:    "gatakka",
    Version: "1.0",
    Args:    []string{"invoke", "c","d","20"},
}

// identity is identity returned from ca.Enroll or Admin
result, err := client.Invoke(identity, chaincode, []string{"peer0"}, "orderer0")
if err != nil {
    fmt.Print(err)
}
```

### Event listening

```
ch:=make(chan gohfc.EventResponse)
ctx,cancel:=context.WithCancel(context.Background())
err:=client.Listen(ctx,identity,"peer0","Org1MSP",ch)
for d:= range ch{
    fmt.Println(d)
}
```
Listen starts listening for block events on particular peer and returns all transactions from the committed block.
The function is nonblocking, and events will be sent using channel. No data is filtered/omitted.
To stop listen provide context.WithCancel and execute cancel.
The caller is responsible to read the channel, otherwise, Listen will block, until the channel is read or overflow occurs.
Every message will represent single transaction in a block including its status if event/s are sent from chaincode
they will be available in event response `CCEvents`.
SDK user can call Listen multiple times on different event peers. This is useful in order to have redundancy. If one peer fails,
events from other peers will be received. All Listen calls can share the same channel.
In such scenarios, every peer will send its own transactions from blocks. It is SDK user responsibility to
handle multiple identical events on the same channel.

## Benchmark
CPU: AMD Ryzen 7 1700 8 cores, 16 threats
RAM: 16GB DDR4
OS: Linux 4.10.10-041010-generic
Hyperledger version 1.0.3 - official images
Docker version:17.09.0-ce
Go: 1.9.1 linux/amd64

Benchmark results are based on invocation transactions. Request is send to 2 peers for endorsement and
response from the endorsement is broadcasted to a single order. Orderer is always the same.
Transaction is counted as completed after broadcast.recv method returns.

Hyperledger network is identical to Kafka examples in bddtests.

Here are the results in TPM (transactions per minute)

| Workers count in parallel | Orderer max block size | Number of executed transactions | Time (s) | TPM   |
|--------------------------|------------------------|---------------------------------|----------|-------|
| 1                        | 10                     | 100                             | 1.3      | 4615  |
| 10                       | 10                     | 1000                            | 2.5      | 24000 |
| 100                      | 10                     | 10000                           | 9.7      | 61856 |
| 200                      | 10                     | 20000                           | 16.5     | 72727 |
| 300                      | 10                     | 30000                           | 23.7     | 75949 |
| 1                        | 100                    | 100                             | 0.9      | 6667  |
| 10                       | 100                    | 1000                            | 1.664    | 36058 |
| 100                      | 100                    | 10000                           | 8.3      | 72289 |
| 200                      | 100                    | 20000                           | 15.2     | 78947 |
| 300                      | 100                    | 30000                           | 21.7     | 82949 |
| 1                        | 1000                   | 100                             | 1.27     | 4724  |
| 10                       | 1000                   | 1000                            | 2.1      | 28571 |
| 100                      | 1000                   | 10000                           | 8.8      | 68182 |
| 200                      | 1000                   | 20000                           | 14.5     | 82759 |
| 300                      | 1000                   | 30000                           | 21       | 85714 |


This table execute same benchmark in same environment with the difference that broadcast is send to one of the three
orderers using round-robin scheduling

| Workers count in parallel  | Orderer max block size  | Number of executed transactions  | Time (s)  | TPM   |
|----------------------------|-------------------------|----------------------------------|-----------|-------|
| 1                          | 10                      | 100                              | 1.1       | 5455  |
| 10                         | 10                      | 1000                             | 2         | 30000 |
| 100                        | 10                      | 10000                            | 7.6       | 78947 |
| 200                        | 10                      | 20000                            | 12.9      | 93023 |
| 300                        | 10                      | 30000                            | 18.2      | 98901 |
| 1                          | 100                     | 100                              | 1.1       | 5455  |
| 10                         | 100                     | 1000                             | 1.9       | 31579 |
| 100                        | 100                     | 10000                            | 8         | 75000 |
| 200                        | 100                     | 20000                            | 13.5      | 88889 |
| 300                        | 100                     | 30000                            | 18.1      | 99448 |
| 1                          | 1000                    | 100                              | 1.3       | 4615  |
| 10                         | 1000                    | 1000                             | 2.3       | 26087 |
| 100                        | 1000                    | 10000                            | 9.2       | 65217 |
| 200                        | 1000                    | 20000                            | 15.4      | 77922 |
| 300                        | 1000                    | 30000                            | 21.2      | 84906 |

As expected block size is really important.

Also GOHFC has potential for better optimizations that can increase the throughput even more. Probably we will add them 
with changes for HL v1.1  