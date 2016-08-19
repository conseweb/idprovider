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
package main

import (
	"net"
	"os"
	"runtime"

	"github.com/conseweb/idprovider/config"
	"github.com/conseweb/idprovider/idp"
	"github.com/hyperledger/fabric/core/crypto"
	"github.com/hyperledger/fabric/flogging"
	"github.com/hyperledger/fabric/membersrvc/ca"
	"github.com/op/go-logging"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"os/signal"
	"syscall"
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
	config.LoadConfig()
	flogging.LoggingInit("server")

	// Init the crypto layer
	if err := crypto.Init(); err != nil {
		logger.Panicf("Failed initializing the crypto layer [%s]", err)
	}
	// cache configure
	ca.CacheConfiguration()

	logger.Infof("CA Server (" + viper.GetString("server.version") + ")")

	aca = ca.NewACA()
	eca = ca.NewECA()
	tca = ca.NewTCA(eca)
	tlsca = ca.NewTLSCA(eca)
	id = idp.NewIDP()

	runtime.GOMAXPROCS(viper.GetInt("server.gomaxprocs"))

	var opts []grpc.ServerOption
	if viper.GetString("server.tls.cert.file") != "" {
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

	go handleSignal()
	srv.Serve(lis)
}

func handleSignal() {
	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	for {
		s := <-sigChan
		logger.Infof("Server receive signal: %v", s)

		switch s {
		case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
			logger.Infof("Server is graceful shutdown...")

			aca.Stop()
			eca.Stop()
			tca.Stop()
			tlsca.Stop()
			id.Stop()

			logger.Info("Server has shutdown.")
		}
	}
}
