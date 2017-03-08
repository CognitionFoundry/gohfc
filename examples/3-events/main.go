package main

import (
	"github.com/CognitionFoundry/gohfc"
	"fmt"
	"os"
	"github.com/hyperledger/fabric/protos/peer"
	"time"
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

	identity, err := enroll(client)
	if err != nil {
		fmt.Printf("Error enrolling client %s\n", err)
		os.Exit(1)
	}

	eventChan := make(chan *gohfc.EventResponse)
	doneChan := make(chan bool)

	client.Peers[0].Event(eventChan, doneChan)
	go func() {
		for v := range eventChan {
			fmt.Println("Event recieved")
			fmt.Println(v)
		}
	}()

	chain, err := gohfc.NewChain("myc1", "mycc", "DEFAULT", peer.ChaincodeSpec_GOLANG, client.Crypt)
	if err != nil {
		gohfc.Logger.Debugf("Error creating chain %s", err)
		return
	}
	client.Invoke(identity.Certificate, chain, client.Peers, client.Orderers, []string{"invoke", "a", "b", "10"})

	//gorutine for event will be stopped when application finish execution so we sleep.
	time.Sleep(20 * time.Second)

	//close event listening
	doneChan<-true
	// now eventChan and connection to event peer are closed


}

func query(certificate *gohfc.Certificate, client *gohfc.GohfcClient) {

	peers := []*gohfc.Peer{client.Peers[0]}

	chain, err := gohfc.NewChain("myc1", "mycc", "DEFAULT", peer.ChaincodeSpec_GOLANG, client.Crypt)
	if err != nil {
		gohfc.Logger.Debugf("Error creating chain %s", err)
		return
	}
	r, err := client.Query(certificate, chain, peers, []string{"query", "a"})
	fmt.Println(string(r.Response[0].Response.Response.Payload))

}

func install(certificate *gohfc.Certificate, client *gohfc.GohfcClient) {
	installReq := &gohfc.InstallRequest{ChannelName: "myc1",
		ChaincodeVersion:                       "0.1",
		ChaincodeName:                          "mycc",
		Namespace:                              "github.com/foo/bar/chaincode/",
		SrcPath:                                "/path/to/chaincode/src/"}
	chain, err := gohfc.NewChain("myc1", "mycc", "DEFAULT", peer.ChaincodeSpec_GOLANG, client.Crypt)
	peers := []*gohfc.Peer{client.Peers[0]}
	if err != nil {
		gohfc.Logger.Debugf("Error creating chain %s", err)
		return
	}
	result, err := client.Install(certificate, chain, peers, installReq)
	fmt.Printf("Install error: %s\n", err)
	fmt.Printf("Install result: %s\n", result)
}

func instantiate(certificate *gohfc.Certificate, client *gohfc.GohfcClient) {
	installReq := &gohfc.InstallRequest{ChannelName: "myc1",
		ChaincodeVersion:                       "0.1",
		ChaincodeName:                          "mycc",
		Namespace:                              "github.com/foo/bar/chaincode/",
		SrcPath:                                "/path/to/chaincode/src/",
		Args:                                   []string{"init", "a", "100", "b", "200"}}
	chain, err := gohfc.NewChain("myc1", "mycc", "DEFAULT", peer.ChaincodeSpec_GOLANG, client.Crypt)
	if err != nil {
		gohfc.Logger.Debugf("Error creating chain %s", err)
		return
	}
	policy, err := gohfc.DefaultPolicy()
	if err != nil {
		gohfc.Logger.Debugf("Error creating policy %s", err)
		return
	}
	result, err := client.Instantiate(certificate, chain, client.Peers[0], client.Orderers[0], installReq, policy)
	fmt.Printf("Instantiate error: %s\n", err)
	fmt.Printf("Instantiate result: %s\n", result)
}

func invoke(certificate *gohfc.Certificate, client *gohfc.GohfcClient) {
	peers := []*gohfc.Peer{client.Peers[0]}
	orderers := []*gohfc.Orderer{client.Orderers[0]}

	chain, err := gohfc.NewChain("myc1", "mycc", "DEFAULT", peer.ChaincodeSpec_GOLANG, client.Crypt)
	if err != nil {
		gohfc.Logger.Debugf("Error creating chain %s", err)
		return
	}
	client.Invoke(certificate, chain, peers, orderers, []string{"invoke", "a", "b", "10"})

}

func getChannels(certificate *gohfc.Certificate, client *gohfc.GohfcClient) {
	r, err := client.GetChannels(certificate, client.Peers[0], "DEFAULT")
	fmt.Println(err)
	fmt.Println(r)
}
func getInstalledChainCodes(certificate *gohfc.Certificate, client *gohfc.GohfcClient) {
	r, err := client.GetInstalledChainCodes(certificate, client.Peers[0], "DEFAULT")
	fmt.Println(err)
	fmt.Println(r.Chaincodes[0].Name)
}

func getChainCodes(certificate *gohfc.Certificate, client *gohfc.GohfcClient) {
	r, err := client.GetChannelChainCodes(certificate, client.Peers[0], "myc1", "DEFAULT")
	fmt.Println(err)
	fmt.Println(r)
}
func queryTransaction(certificate *gohfc.Certificate, client *gohfc.GohfcClient) {
	transaction, payload, err := client.QueryTransaction(certificate, client.Peers[0], "myc1", "cba2c17f568c0e47769b07ef2c21558ca8d2752be045f30b7a45fb164b21bfef", "DEFAULT")
	fmt.Println(transaction)
	fmt.Println(payload)
	fmt.Println(err)
}

func enroll(client *gohfc.GohfcClient) (*gohfc.Identity, error) {
	data, err := client.Enroll("admin", "adminpw")
	if err != nil {
		gohfc.Logger.Debugf("Erro enroll %s", err)
		return nil, err
	}
	return data, nil
}

func register(certificate *gohfc.Certificate, client *gohfc.GohfcClient) {
	regReq := new(gohfc.RegistrationRequest)
	regReq.EnrolmentId = "finder1"
	regReq.Type = "client"
	regReq.Affiliation = "org1"
	regReq.Attrs = []gohfc.RegistrationRequestAttr{{Name: "company", Value: "testcompany"}}
	attrs := make([]gohfc.RegistrationRequestAttr, 0, 2)
	attrs = append(attrs, gohfc.RegistrationRequestAttr{Name: "role", Value: "founder"})
	attrs = append(attrs, gohfc.RegistrationRequestAttr{Name: "accout", Value: "123456"})
	regReq.Attrs = attrs
	enr_pass, err := client.Register(certificate, regReq)
	if err != nil {
		gohfc.Logger.Debugf("Error registering %s", err)
		return
	}
	gohfc.Logger.Debugf("User registration successfull! Password is: %s", enr_pass.Result.Credential)
}
