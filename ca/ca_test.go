/*
Copyright Mojing Inc. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package ca

import (
	"fmt"
	"github.com/hyperledger/fabric/core/crypto"
	"github.com/hyperledger/fabric/core/crypto/primitives"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"gopkg.in/check.v1"
	"io/ioutil"
	"net"
	"os"
)

const (
	name = "ca"
)

var (
	caFiles = [4]string{name + ".cert", name + ".db", name + ".priv", name + ".pub"}
)

type TestCA struct {
	eca *ECA
	aca *ACA
	tca *TCA
	srv *grpc.Server
}

var _ = check.Suite(&TestCA{})

func (t *TestCA) SetUpSuite(c *check.C) {
	setupTestConfig()
	c.Check(crypto.Init(), check.IsNil)

	t.eca = NewECA()
	t.aca = NewACA()
	t.tca = NewTCA(t.eca)

	go t.startPKI()
}

func (t *TestCA) TearDownSuite(c *check.C) {
	t.eca.Stop()
	t.aca.Stop()
	t.tca.Stop()
	t.srv.Stop()

	os.Remove("./testdata/ca.db")
	os.Remove("./testdata/aca.db")
	os.Remove("./testdata/eca.db")
	os.Remove("./testdata/tca.db")
}

func setupTestConfig() {
	primitives.SetSecurityLevel("SHA3", 256)
	viper.AutomaticEnv()
	viper.SetConfigName("config") // name of config file (without extension)
	viper.AddConfigPath("./")     // path to look for the config file in
	viper.AddConfigPath("./..")   // path to look for the config file in
	err := viper.ReadInConfig()   // Find and read the config file
	if err != nil {               // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}
}

func (t *TestCA) startPKI() {
	var opts []grpc.ServerOption
	fmt.Printf("open socket...\n")
	sockp, err := net.Listen("tcp", viper.GetString("idprovider.server.addr"))
	if err != nil {
		panic("Cannot open port: " + err.Error())
	}
	fmt.Printf("open socket...done\n")

	t.srv = grpc.NewServer(opts...)
	t.eca.Start(t.srv)
	t.aca.Start(t.srv)
	t.tca.Start(t.srv)
	fmt.Printf("start serving...\n")
	t.srv.Serve(sockp)
}

func (t *TestCA) TestNewCA(c *check.C) {
	//Create new CA
	ca := NewCA(name)
	c.Check(ca, check.NotNil)

	for _, f := range caFiles {
		_, err := os.Stat(ca.path + "/" + f)
		c.Check(err, check.IsNil)
	}

	//check CA certificate for correct properties
	pem, errPem := ioutil.ReadFile(ca.path + "/" + name + ".cert")
	c.Check(errPem, check.IsNil)

	cacert, errP2C := primitives.PEMtoCertificate(pem)
	c.Check(errP2C, check.IsNil)

	//check that commonname, organization and country match config
	c.Check(cacert.Subject.Organization[0], check.Equals, viper.GetString("idprovider.ca.organization"))
	c.Check(cacert.Subject.Country[0], check.Equals, viper.GetString("idprovider.ca.country"))
}
