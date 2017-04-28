## Gohfc (Golang Hyperledger Fabric)
Gohfc is pure Go SDK for [Hyperledger Fabric](https://github.com/hyperledger/fabric)

**Because Fabric is developed so rapidly we will wait for stable version before updating this SDK.**
**Currently this SDK is not compatible with latest Fabric master branch**

It gives you series of APIs that allow you to use Fabric using Go

**Note:** This is an alpha SDK over alpha software. If something can go wrong, it will go wrong! Breaking API changes are more than expected at this stage of development!
 
**Note:** This is not an official Hyperledger Fabric SDK. For official SDKs see the [official documentation](http://hyperledger-fabric.readthedocs.io/en/latest/)  

**Note:** This SDK is for Hyperledger Fabric v1, it is not compatible with v0.6

**Note:** Current API design of Gohfc is not fully compliant with [Hyperledger Fabric SDK Design Specification v1.0](https://docs.google.com/document/d/1R5RtIBMW9fZpli37E5Li5_Q9ve3BnQ4q3gWmGZj6Sv4/edit#heading=h.kspvx6g87vie). Official specification API calls for HL 1.0 is in our road-map. This will be done by creating a layer over existing Gohfc API, but we will keep access to lower level API. We are waiting for at least RC version of HL.   

### Requirements
* Go >=1.7
* sha3
* grpc
* protobuf
* go-logging
* context (if using go 1.7. Not needed for go >=1.8)
```
go get golang.org/x/crypto/sha3
go get google.golang.org/grpc
go get -u github.com/golang/protobuf/{proto,protoc-gen-go}
go get github.com/op/go-logging
go get golang.org/x/net/context 
```

### Gohfc Installation
```
go get github.com/CognitionFoundry/gohfc
```
You must have running at least one CA, Peer and Orderer to be able to use this SDK.

For information how to install and run Fabric refer to [official documentation](http://hyperledger-fabric.readthedocs.io/en/latest/)

Or if you want a quick Fabric setup guide look [Gohfc wiki](https://github.com/CognitionFoundry/gohfc/wiki/Hyperledger-Fabric-developer-setup) 
### TL;DR
See examples folder
```
package main

import (
	"github.com/CognitionFoundry/gohfc"
	"fmt"
	"os"
	"github.com/hyperledger/fabric/protos/peer"
)

func main() {
    kvsore, err := gohfc.NewFileKeyValue("./kvstore")
    if err != nil {
        fmt.Printf("Error creating kvstore %s\n", err)
        os.Exit(1)
    }
    client, err := gohfc.NewClientFromJSONConfig("./config.json", kvsore)
    if err != nil {
        fmt.Printf("Error creating client %s\n", err)
        os.Exit(1)
    }
    identity, err := client.Enroll("admin", "adminpw")
    if err != nil {
        fmt.Printf("Error enrolling client %s\n", err)
        os.Exit(1)
    }
    peers := []*gohfc.Peer{client.Peers[0]}    
    chain, err := gohfc.NewChain("myc1", "mycc", "DEFAULT", peer.ChaincodeSpec_GOLANG, client.Crypt)
    if err != nil {
        fmt.Printf("Error creating chain %s\n", err)
        return
    }
    r,err:=client.Query(identity.Certificate, chain, peers, []string{"query", "a"})
    if err!=nil{
        fmt.Printf("Error quering %s\n", err)
        os.Exit(1)
    }
    fmt.Println(string(r.Response[0].Response.Response.Payload))
}
```
### Architecture
Gohfc is composed of series of APIs that do not enforce specific workflow. Users can use higher level APIs provided by gohfc.Client, or can access lower level APIs provided by different components to create specific transaction, do custom validation or any other logic.

Gohfc is designed for expandability, thus users can extend CA, Crypto and Key-Value store components.

Here is a general description for different components and their responsibilities.

#### CAClient 
Certificate authority (CA) is responsible for creating and revoking certificates (ECert or TCert)

Current Gohfc SDK has implementation only for [fabric-ca](https://github.com/hyperledger/fabric-ca) but using other CA is possible. Users must implement CAClient interface
``` 
type CAClient interface {
	Enroll(enrollmentId, password string) (*Identity, error)
	Register(certificate *Certificate, req *RegistrationRequest) (*CAResponse, error)
	Revoke(certificate *Certificate, request *RevocationRequest) (*CAResponse, error)
	TCerts(certificate *Certificate) ([]*Certificate, error)
}
```
#### Chain
Chain is responsible for almost all operations in Fabric. Creating transactions, endorsing transactions, install and instantiate chain codes etc...
 
Chain is defined by Chanel name, Chaincode name and MspId.

If you are running default Fabric setup MspId is always "DEFAULT" (case sensitive)

#### Client 
Client component is higher level APIs build on top of Chain component that simplify common operations like enrolment, query, invoke, install etc.

#### Key-Value store
Key-value store is used to keep long-term data from enrollments (ECerts). It must be persistent and secure because certificates with their private keys are stored inside.
Users can use any technology for storage by implementing simple interface:
```
type KeyValueStore interface {
	Get(key string) (string, bool, error)
	Set(key string, value string) error
	Delete(key string) error
}
```

Gohfc currently provide 3 implementations:

* MemoryKeyValue - data is stored in memory and is destroyed when app is stopped
* DummyKeyValue - no data is stored at all
* FileKeyValue - data is stored in file system as text file. This implementation do not scale efficiently

For production use is highly recommended to use proper secure scalable storage like database.

#### Crypto
Crypto provide necessary cryptographic functionality to generate private keys, certificates, hashing and signing messages.

Currently Fabric (and gohfc) supports (by default) Elliptic curves and RSA but custom crypto suites can be implemented in fabric and gohfc.
 
For custom crypto implementation users must implement this interface:

```
type CryptSuite interface {
	GenerateKey() (interface{}, error)	
	CreateCertificateRequest(enrolmentId string, key interface{}) ([]byte, error)	
	Sign(msg []byte, key interface{}) ([]byte, error)	
	CASign(msg []byte, key interface{}) ([]byte, error)	
	Hash(data []byte) ([]byte)
}
```

**Note:** Fabric is not completely ready with RSA implementation. Avoid using it for now!

**Note:** Fabric and gohfc crypto settings must match.

Available crypto options are shown in the table bellow:


| Family   | Algorithm   | Description                                      | 
|:--------:|:-----------:|--------------------------------------------------| 
| ecdsa    | P256-SHA256 | Elliptic curve is P256 and signature uses SHA256 |
| ecdsa    | P384-SHA384 | Elliptic curve is P384 and signature uses SHA384 |
| ecdsa    | P521-SHA512 | Elliptic curve is P521 and signature uses SHA512 |
| rsa      | 2048-SHA256 | Key length is 2048 and signature uses SHA256     |
| rsa      | 4096-SHA512 | Key length is 4096 and signature uses SHA512     |

Available hashing options are shown in table below

| Family   | Size | 
|:--------:|:----:| 
| SHA2     | 256  |
| SHA2     | 384  |
| SHA3     | 256  |
| SHA3     | 384  |

#### Config
Config facilitate creating necessary structures from JSON file using:

`gohfc.NewConfigFromJSON("path/to/config.json")`

Users can create different configuration schemes (yaml, ini, database etc...) and the result must be a valid **Config** struct type with valid values.

Actually, config is not even necessary because users can instantiate any component manually (see examples folder) 

**Note:** currently **http.transport** is not in config so if users want to communicate using proxy and/or some specific TLS setup must manually provide **http.Transport** options
  
#### Peer

Peer is used to identify uniquely different peers,their settings and allows registering an event listener.

### Limitations

Currently Gohfc and Hyperledger Fabric are in very intensive development so not all functionality is implemented or stable.

Here is a list of some of the main limitations:

* TCerts are not working as expected. Waiting for final/stable Fabric implementation. 
* Only event sent from Fabric is for Block type. There is no way to get event for rejected transactions. This will be fixed in final version. For now users must relay on timeout to catch rejected transactions.
* RSA implementation is not complete and stable. Avoid using it for now.
* Logging logs only errors. 
* Creating new channel is not possible using gohfc. Channel creation must be done using CLI from Fabric containers.
* Chaincode deployed using gohfc must be written in Go. Other languages (Java and CAR) will be added later. Gohfc can work with chaincode written in other languages but chaincode must be installed using CLI or other SDK.
* Some of the APIs need refactoring.
* Grpc connection is established and closed on every transaction. In future version permanent connections and mechanism to control them will be added.
* Will be good to provide some functionality to manage chains in more flexible way.  

## License <a name="license"></a>
The Gohfc Project uses the [Apache License Version 2.0](LICENSE) software
license.
