package main

import (
	"fmt"
	"github.com/CognitionFoundry/gohfc"
	"os"

	"math/rand"
	"context"
)

const ADM_PK = "/path/to/admin/cert.pem"
const ADM_SK = "/path/to/admin/admin.key"

func main() {

	// initialize Fabric client
	c, err := gohfc.NewFabricClient("./client.yaml")
	if err != nil {
		fmt.Printf("Error loading file: %v", err)
		os.Exit(1)
	}

	// Initialize FabricCa client
	ca, err := gohfc.NewCAClient("./ca.yaml", nil)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Optional, define which attributes to be included in ECert. This attributes must be set when entity is registered.
	// If not provided attributes from registration with attribute Ecert will be included.
	attrs := []gohfc.CaEnrollAttribute{{
		Name:     "attr1",
		Optional: true,
	},
		{
			Name:     "attr2",
			Optional: true,
		},
	}
	enrollRequest := gohfc.CaEnrollmentRequest{EnrollmentId: "user", Secret: "password", Attrs: attrs}
	identity, _, err := ca.Enroll(enrollRequest)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// if you want to export ECert as .pem file use identity.ToPem()
	// if you want to serialize Identity in text form use MarshalIdentity(identity) and UnmarshalIdentity() for reverse operation

	// CA calls examples
	register(ca, identity)
	reenroll(ca, identity)
	getCaCerts(ca, identity)
	listAffiliation(ca, identity)
	removeAffiliation(ca, identity)
	modifyAffiliation(ca, identity)
	addAffiliation(ca, identity)
	listAllIdentities(ca, identity)
	getIdentity(ca, identity)
	removeIdentity(ca, identity)
	modifyIdentity(ca, identity)
	revoke(ca, identity)

	// Fabric calls examples
	// some operations require admin certificate
	createUpdateChannel(c)
	joinChannel(c)
	installCC(c)
	instantiateCC(c)
	queryInstalledChaincodes(c)
	queryInstantiatedChaincodes(c)
	queryChannels(c, identity)
	queryChannelInfo(c)
	query(c, identity)
	invoke(c, *identity, []string{"invoke", "a", "b", "20"})
	queryTransaction(c, identity)
	eventFullBlock(c, identity)
	eventFilteredBlock(c, identity)
}

func eventFullBlock(client *gohfc.FabricClient, identity *gohfc.Identity) {
	ch := make(chan gohfc.EventBlockResponse)
	ctx, cancel := context.WithCancel(context.Background())
	err := client.ListenForFullBlock(ctx, *identity, "peer0", "testchannel", ch)
	if err != nil {
		fmt.Println(err)
		cancel()
	}
	for d := range ch {
		fmt.Println(d)
	}
}

func eventFilteredBlock(client *gohfc.FabricClient, identity *gohfc.Identity) {

	ch := make(chan gohfc.EventBlockResponse)
	ctx, cancel := context.WithCancel(context.Background())
	err := client.ListenForFullBlock(ctx, *identity, "peer0", "testchannel", ch)
	if err != nil {
		fmt.Println(err)
		cancel()
	}
	for d := range ch {
		fmt.Println(d)
	}
}

func invoke(client *gohfc.FabricClient, identity gohfc.Identity, q []string) {

	chaincode := gohfc.ChainCode{
		ChannelId: "testchannel",
		Type:      gohfc.ChaincodeSpec_GOLANG,
		Name:      "samplechaincode",
		Version:   "1.0",
		Args:      q,
	}

	result, err := client.Invoke(identity, chaincode, []string{"peer01", "peer11"}, "orderer0")
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
	fmt.Println(result)

}

func query(client *gohfc.FabricClient, identity *gohfc.Identity) {

	chaincode := &gohfc.ChainCode{
		ChannelId: "testchannel",
		Type:      gohfc.ChaincodeSpec_GOLANG,
		Name:      "samplechaincode",
		Version:   "1.0",
		Args:      []string{"query", "a"},
	}

	result, err := client.Query(*identity, *chaincode, []string{"peer01"})
	if err != nil {
		fmt.Print(err)
		os.Exit(2)
	}
	fmt.Println(result)
}

func queryTransaction(client *gohfc.FabricClient, identity *gohfc.Identity) {

	txid := "dd0945350a2e9e24515826f8fa6c7c8c5150001f0111478d7340d542dce6bd06"
	result, err := client.QueryTransaction(*identity, "testchannel", txid, []string{"peer0"})
	if err != nil {
		fmt.Print(err)
		os.Exit(2)
	}
	fmt.Println(result)
}

func queryChannelInfo(client *gohfc.FabricClient) {
	admin, err := gohfc.LoadCertFromFile(ADM_PK, ADM_SK)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Please note that we must provide MSPid manually because Identity is not from FabricCA
	admin.MspId = "comp1Msp"
	result, err := client.QueryChannelInfo(*admin, "testchannel", []string{"peer0", "peer1"})
	if err != nil {
		fmt.Print(err)
		os.Exit(2)
	}
	fmt.Println(result)
}

func queryChannels(client *gohfc.FabricClient, identity *gohfc.Identity) {

	result, err := client.QueryChannels(*identity, []string{"peer0", "peer1"})
	if err != nil {
		fmt.Print(err)
		os.Exit(2)
	}
	fmt.Println(result)
}

func queryInstantiatedChaincodes(client *gohfc.FabricClient) {

	admin, err := gohfc.LoadCertFromFile(ADM_PK, ADM_SK)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// Please note that we must provide MSPid manually because Identity is not from FabricCA
	admin.MspId = "comp1Msp"

	result, err := client.QueryInstantiatedChainCodes(*admin, "testchannel", []string{"peer0"})
	if err != nil {
		fmt.Print(err)
		os.Exit(2)
	}
	fmt.Println(result)

}

func queryInstalledChaincodes(client *gohfc.FabricClient) {
	admin, err := gohfc.LoadCertFromFile(ADM_PK, ADM_SK)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// Please note that we must provide MSPid manually because Identity is not from FabricCA
	admin.MspId = "comp1Msp"
	response, err := client.QueryInstalledChainCodes(*admin, []string{"peer0"})
	if err != nil {
		fmt.Print(err)
		os.Exit(2)
	}
	fmt.Println(response)

}

func instantiateCC(client *gohfc.FabricClient) {

	admin, err := gohfc.LoadCertFromFile(ADM_PK, ADM_SK)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// Please note that we must provide MSPid manually because Identity is not from FabricCA
	admin.MspId = "comp1Msp"

	req := &gohfc.ChainCode{
		Type:      gohfc.ChaincodeSpec_GOLANG,
		ChannelId: "testchannel",
		Name:      "samplechaincode",
		Version:   "1.0",
		Args:      []string{"init", "a", "100", "b", "200"}, // optional arguments for instantiation
	}

	// gohfc.CollectionConfig is new for v 1.1 and specify private collections for this chaincode. It is optional.

	cc := []gohfc.CollectionConfig{
		{
			MaximumPeersCount:  2,
			RequiredPeersCount: 1,
			Name:               "marbleTest",
			Organizations:      []string{"comp1Msp", "comp2Msp"},
		},
	}
	response, err := client.InstantiateChainCode(*admin, req, []string{"peer01", "peer11"}, "orderer0", "deploy", cc)
	if err != nil {
		fmt.Print(err)
		os.Exit(2)
	}

	fmt.Println(response)
}

func installCC(client *gohfc.FabricClient) {
	admin, err := gohfc.LoadCertFromFile(ADM_PK, ADM_SK)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// Please note that we must provide MSPid manually because Identity is not from FabricCA
	admin.MspId = "comp1Msp"
	req := &gohfc.InstallRequest{
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
	response, err := client.InstallChainCode(*admin, req, []string{"peer01", "peer11"})
	if err != nil {
		fmt.Print(err)
		os.Exit(2)
	}
	fmt.Println(response)
}

func joinChannel(client *gohfc.FabricClient) {
	admin, err := gohfc.LoadCertFromFile(ADM_PK, ADM_SK)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// Please note that we must provide MSPid manually because Identity is not from FabricCA
	admin.MspId = "comp1Msp"
	response, err := client.JoinChannel(*admin, "testchannel", []string{"peer01", "peer11"}, "orderer0")
	if err != nil {
		fmt.Print(err)
		os.Exit(2)
	}
	fmt.Println(response)

}

func createUpdateChannel(client *gohfc.FabricClient) {

	admin, err := gohfc.LoadCertFromFile(ADM_PK, ADM_SK)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// Please note that we must provide MSPid manually because Identity is not from FabricCA
	admin.MspId = "comp1Msp"
	err = client.CreateUpdateChannel(*admin, "/path/to/channel-artifacts/testchannel.tx", "testchannel", "orderer1")
	fmt.Print(err)

}

func register(ca *gohfc.FabricCAClient, identity *gohfc.Identity) {

	// Optional list of attributes
	attr := []gohfc.CaRegisterAttribute{{
		Name:  "option1",
		Value: "option1 value",
		ECert: true,
	},
		{
			Name:  "option2",
			Value: "option2 value",
			ECert: false,
		}}

	rr := gohfc.CARegistrationRequest{
		EnrolmentId: "newUserName",
		Secret:      "qwerty",
		Affiliation: "comp1org",
		Type:        "user",
		Attrs:       attr}
	resp, err := ca.Register(identity, &rr)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(resp)
}

func reenroll(ca *gohfc.FabricCAClient, identity *gohfc.Identity) {
	// optional attributes
	req := gohfc.CaReEnrollmentRequest{
		Identity: identity,
		Attrs: []gohfc.CaEnrollAttribute{
			{
				Name:     "option2",
				Optional: true,
			},
		},
	}
	resp, _, err := ca.ReEnroll(req)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(resp)
}

func revoke(ca *gohfc.FabricCAClient, identity *gohfc.Identity) {
	// To revoke user use:
	rr := gohfc.CARevocationRequest{EnrollmentId: "newUser1"}

	// To revoke specific sertificate use:
	rr = gohfc.CARevocationRequest{
		AKI:    "A84DEDAE57124E3D8305C9B8303E74A6EE196E27",
		Serial: "64e888fd586a6226016a70c22f2f5d95baa92599",
		GenCRL: true}
	r, err := ca.Revoke(identity, &rr)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(r)

}

func getCaCerts(ca *gohfc.FabricCAClient, identity *gohfc.Identity) {

	resp, err := ca.GetCaCertificateChain("")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(resp)

}

func listAffiliation(ca *gohfc.FabricCAClient, identity *gohfc.Identity) {

	// path is optional
	resp, err := ca.ListAffiliations(identity, "organization1", "")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(resp.CAName)
	fmt.Println(resp.Name)
	fmt.Println(resp.Affiliations)

}

func addAffiliation(ca *gohfc.FabricCAClient, identity *gohfc.Identity) {
	req := gohfc.CAAddAffiliationRequest{Name: "organization1.dep2", Force: false}
	resp, err := ca.AddAffiliation(identity, req)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(resp)
}

func removeAffiliation(ca *gohfc.FabricCAClient, identity *gohfc.Identity) {
	// CA must be configured to support affiliation removal
	req := gohfc.CARemoveAffiliationRequest{Name: "organization1.department1", Force: false}
	resp, err := ca.RemoveAffiliation(identity, req)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(resp)
}

func modifyAffiliation(ca *gohfc.FabricCAClient, identity *gohfc.Identity) {
	req := gohfc.CAModifyAffiliationRequest{Name: "organization1.department1", NewName: "org1.dep1", Force: true}
	resp, err := ca.ModifyAffiliation(identity, req)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(resp)
}

func listAllIdentities(ca *gohfc.FabricCAClient, identity *gohfc.Identity) {

	resp, err := ca.ListAllIdentities(identity, "")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(resp)

}

func removeIdentity(ca *gohfc.FabricCAClient, identity *gohfc.Identity) {
	req := gohfc.CARemoveIdentityRequest{Name: "newUser1", Force: false}
	resp, err := ca.RemoveIdentity(identity, req)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(resp)
}

func modifyIdentity(ca *gohfc.FabricCAClient, identity *gohfc.Identity) {
	// see documentation for all fields that can be modified.
	req := gohfc.CAModifyIdentityRequest{ID: "newUser1",
		Attributes: []gohfc.CaRegisterAttribute{
			{
				Name:  "new1",
				ECert: true,
				Value: "new value 1",
			},
		},
		Secret: "new password",}
	resp, err := ca.ModifyIdentity(identity, req)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(resp)
}

func getIdentity(ca *gohfc.FabricCAClient, identity *gohfc.Identity) {

	resp, err := ca.GetIdentity(identity, "newUser1", "")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(resp)

}

func RandStringRunes(n int) string {
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
