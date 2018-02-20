# GOHFC - Golang Hyperledger Fabric Client

This is SDK for Hyperledger Fabric written in pure Golang using minimum requirements.
This is not official SDK and does not follow official SDK API guidelines provided by Hyperledger team.
For the list of official SDK's refer to the official Hyperledger documentation.

It is designed to be easy to use and to be fast as possible. Currently, it outperforms the official Go SDK by far.

We are using it in our production applications, but no guarantees are provided.

This version will be updated and supported, so pull requests and reporting any issues are more than welcome.

Recommended Go version is >=1.9

This SDK is tested for Hyperledger Fabric 1.1.x. 

Versions 1.0.x should work, but some features will not be available. We are not planning to support 1.0.x anymore.
We are planning to keep backward comparability for versions >=1.1.x

For examples see examples folder.
 

## Dependency

```
go get -u golang.org/x/crypto/sha3
go get -u gopkg.in/yaml.v2

```

## Installation

```
go get -u github.com/CognitionFoundry/gohfc

```

## Basic concepts

Gohfc provide two high level clients, one for FabricCA and one for Fabric. They work together but user may use them separately.

`FabricCAClient` is client to work with Fabric certificate authority (CA) and allows you to register, enroll,
revoke certificates, manage affiliations and attributes.

Every operation in Fabric MUST be signed by proper certificate. You can generate this certificates using openssl or
other tools, but FabricCA server makes this procedure much more streamline and hides a lot of the complexity.

`FabricCAClient` can be used to generate complete MSP structure if you do not want to use `cryptogen` tool for some reason.

`FabricClient` expose high level API's for working with blockchain, ledger, chaincodes, channels and events.

General flow is like this:
- Start Fabric using docker-compose or any other tool appropriate for you. Running Fabric is not responsibility of gohfc.
- Create one or many channels by sending channels config to orderer. This is done using `gohfc.CreateUpdateChannel`
- Join one or more peers to one or more channels. This is done using `gohfc.JoinChannel`
- Install one or many chaincodes in one or many peers. This can be done using `gohfc.InstallChainCode`
- Instantiate one or more already installed chaincodes. This can be dine using `gohfc.InstantiateChainCode`
- Query chaincode using `gohfc.Query`. This is readonly operation. No changes to blockchain or ledger will be made.
- Invoke chaincode using `gohfc.Invoke`. This operation may update the blockchain and the ledger.
- Listen for events using `gohfc.ListenForFullBlock` or `gohfc.ListenForFilteredBlock` 

There are many more methods to get particular block, list channels, get chaincodes etc.

See examples folder.

## Initialization

Both clients can be initialised from yaml file or manually.

`FabricCAClient` config file:

```

---
url: http://ca.example.com:7052 # URL for the CA server
skipTLSValidation: true         # skip TLS verification in case when you are not providing custom transport
mspId: comp1Msp                 # this value will be added automatically to any gohfc.Identity returned from this CA  
crypto:                         # cryptographic settings 
  family: ecdsa                 
  algorithm: P256-SHA256         
  hash: SHA2-256
  
```

`FabricCAClient` initialization from config file:

```
caClient, err := gohfc.NewCAClient("./ca.yaml", nil)
if err != nil {
    fmt.Println(err)
    os.Exit(1)
}

```

### About MSPId
Every peer and orderer in Fabric must have set of cryptographic materials like root CA certificates, 
intermediate certificates, list of revoked certificates and more. This set of certificates is associated with ID
and this ID is called MSP (member service provider). In every operation MSPID must be provided so the peer and orderer
know which set of crypto materials to load and to use for verification of the request.

In general MSP define a organization and entities inside organization with there roles. Couple of MSP's are combined to 
form a consortium so multiple organizations, each one with own set of certificates, can work together.

So when any request to fabric is send this request must be signed by Ecert (user certificate hold in `gohfc.Identity`)
and MSPID must be provided so Fabric loads MSP by ID, make verification that this request is coming from member of the
organization and that this member has the appropriate access.

Because (in general case) one FabricCa is serving one organization (one MSP) it makes sense to put this ID in config
and to auto populate it when new `gohfc.Identity` is generated (enroll or reenroll). This is for convenience,
user can always overwrite this value.

`FabricClient` config file:

```

---
crypto:
  family: ecdsa
  algorithm: P256-SHA256
  hash: SHA2-256
orderers:
  orderer0:
    host: orderer0.example.com:7050
    useTLS: false
    tlsPath: /path/to/tls/server.pem
  orderer1:
    host: orderer0.example.com:7048
    useTLS: false
    tlsPath: /path/to/tls/server.pem
peers:
  peer01:
    host: peer0.example.com:7051
    useTLS: false
    tlsPath: /path/to/tls/server.pem
  peer11:
    host: peer1.example.com:8051
    useTLS: false
    tlsPath: /path/to/tls/server.pem
  peer02:
    host: peer0.example.com:9051
    useTLS: false
    tlsPath: /path/to/tls/server.pem
  peer12:
      host: peer1.example.com:10051
      useTLS: false
      tlsPath: /path/to/tls/server.pem
eventPeers:
  peer0:
    host: peer0.example.com:7051
    useTLS: false
    tlsPath: /path/to/tls/server.pem


```

`FabricClient` initialization from config file:

```
c, err := gohfc.NewFabricClient("./client.yaml")
if err != nil {
    fmt.Printf("Error loading file: %v", err)
	os.Exit(1)
}

```

### Install chaincode

When new chaincode is installed a struct of type `gohfc.InstallRequest` must be provided:

```

request := &gohfc.InstallRequest{
    ChainCodeType:    gohfc.ChaincodeSpec_GOLANG,
    ChannelId:        "testchannel",
    ChainCodeName:    "samplechaincode",
    ChainCodeVersion: "1.0",
    Namespace:        "github.com/hyperledger/fabric-samples/chaincode/chaincode_example02/go/",
    SrcPath:          "/absolute/path/to/folder/containing/chaincode",
    Libraries: []gohfc.ChaincodeLibrary{
        {
            Namespace: "namespace",
            SrcPath:   "path",
        },
    },
}

```

Fabric will support chaincode written in different languages, so language type must be specified using `ChainCodeType`
Gohfc for now support only Go. Other chaincode languages will be added later when Fabric officially start support them.

`ChannelId` is the channel name where the chaincode must be installed.

`ChainCodeName` is the name of the chaincode. This name will be used in future requests (query, invoke, etc..)
to specify which chaincode must be executed. One channel may have multiple chaincodes. name must be unique in context
of a channel.

`ChainCodeVersion` specify the version.

Gohfc is designed to work without need of Go environment. So when user try to install chaincode he/she must provide
`Namespace`,`SrcPath` and optional `Libraries`

`Namespace` is the Go namespace where chaincode will be "installed" in Fabric runtime. Like `github.com/some/code`

`SrcPath` is the absolute path where source code is located, from where it must be red, packed and prepared for 
install. 

This separation allows gohfc to run without any external runtime dependencies, also this is very flexible in
context of CI,CD systems.

`Libraries` is a optional list of libraries that will be included in packing of the chaincode. They follow the same
logic of `Namespace` and `SrcPath`. 

Vendoring the dependencies is an option, but in more complex chaincodes is much better to have some library installed
as library and not as vendored dependencies in multiple places.

### Note about names

Many operations require specific peer or orderer to be specified. Gohfc use name alias for this, and names are taken
from config file. For example, if you want to query specific peers:

```
client.Query(*identity, *chaincode, []string{"peer01","peer11"})

``` 

In this example "peer01" and "peer11" are names given to peers in config file and query operation will be send to this two peers.

## TODO
- full block decoding. For now user can take raw block data, but will be much better to provide utility functions to decode block
- specify policy in `InstantiateChainCode`. Waiting for official tool from Fabric and decide how to integrate it.
- gencrl call for FabricCA
- easy mutual TLS configuration


### Available cryptographic algorithms

| Family   | Algorithm   | Description                                      | 
|:--------:|:-----------:|--------------------------------------------------| 
| ecdsa    | P256-SHA256 | Elliptic curve is P256 and signature uses SHA256 |
| ecdsa    | P384-SHA384 | Elliptic curve is P384 and signature uses SHA384 |
| ecdsa    | P521-SHA512 | Elliptic curve is P521 and signature uses SHA512 |
| rsa      | ----        | RSA is not supported in Fabric                   |

### Hash

| Family    | 
|:----------| 
| SHA2-256  |
| SHA2-384  |
| SHA3-256  |
| SHA3-384  |