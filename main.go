/*
Copyright Mojing Inc. 2016 All Rights Reserved.
Written by mint.zhao.chiu@gmail.com. github.com: https://www.github.com/mintzhao

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
package main

import (
	"net"
	"runtime"

	"github.com/conseweb/common/config"
	"github.com/conseweb/common/exec"
	"github.com/conseweb/idprovider/idp"
	"github.com/hyperledger/fabric/core/crypto"
	"github.com/hyperledger/fabric/flogging"
	"github.com/hyperledger/fabric/membersrvc/ca"
	"github.com/op/go-logging"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	logger = logging.MustGetLogger("server")
	aca    *ca.ACA
	eca    *ca.ECA
	tca    *ca.TCA
	tlsca  *ca.TLSCA
	id     *idp.IDP
)

func main() {
	if err := config.LoadConfig("IDPROVIDER", "idprovider", "github.com/conseweb/idprovider"); err != nil {
		logger.Fatal(err)
	}
	flogging.LoggingInit("server")

	// Init the crypto layer
	if err := crypto.Init(); err != nil {
		logger.Panicf("Failed initializing the crypto layer [%s]", err)
	}
	// cache configure
	ca.CacheConfiguration()

	logger.Infof("CA Server (" + viper.GetString("server.version") + ")")
	aca = ca.NewACA()
	eca = ca.NewECA(aca)
	tca = ca.NewTCA(eca)
	tlsca = ca.NewTLSCA(eca)
	id = idp.NewIDP()

	runtime.GOMAXPROCS(viper.GetInt("server.gomaxprocs"))
	var opts []grpc.ServerOption
	if viper.GetBool("server.tls.enabled") {
		creds, err := credentials.NewServerTLSFromFile(viper.GetString("server.tls.cert.file"), viper.GetString("server.tls.key.file"))
		if err != nil {
			logger.Panic(err)
		}
		opts = []grpc.ServerOption{grpc.Creds(creds)}
	}
	srv := grpc.NewServer(opts...)

	if viper.GetBool("aca.enabled") {
		aca.Start(srv)
	}
	eca.Start(srv)
	tca.Start(srv)
	tlsca.Start(srv)
	id.Start(srv)

	lis, err := net.Listen("tcp", viper.GetString("server.port"))
	if err != nil {
		logger.Fatalf("Fail to start IDProvider Server: %s", err)
	}

	go srv.Serve(lis)
	exec.HandleSignal(aca.Stop, func() error {
		eca.Stop()
		return nil
	}, tca.Stop, tlsca.Stop, id.Stop)
}
