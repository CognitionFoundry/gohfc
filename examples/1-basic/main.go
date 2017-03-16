package main

import (
	"github.com/CognitionFoundry/gohfc"
	"fmt"
	"os"
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

	chain, err := gohfc.NewChain("myc1", "mycc", "DEFAULT", gohfc.ChaincodeSpec_GOLANG, client.Crypt)
	if err != nil {
		gohfc.Logger.Debugf("Erro creating chain %s", err)
		return
	}
	r,err:=client.Query(identity.Certificate, chain, peers, []string{"query", "a"})
	if err!=nil{
		fmt.Printf("Error quering %s\n", err)
		os.Exit(1)
	}
	fmt.Println(string(r.Response[0].Response.Response.Payload))
}

