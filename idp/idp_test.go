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
package idp

import (
	"github.com/conseweb/idprovider/config"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"gopkg.in/check.v1"
	"net"
	"testing"
	"time"
	"os"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type TestIDP struct {
	id *IDP
}

var _ = check.Suite(&TestIDP{})

func (t *TestIDP) SetUpSuite(c *check.C) {
	config.LoadConfig()

	t.id = NewIDP()

	lis, err := net.Listen("tcp", viper.GetString("server.port"))
	c.Check(err, check.IsNil)

	srv := grpc.NewServer()
	t.id.Start(srv)

	go srv.Serve(lis)
}

func (t *TestIDP) TearDownSuite(c *check.C) {
	time.Sleep(time.Second)
	c.Check(t.id.Stop(), check.IsNil)
	if viper.GetString("db.driver.name") == "sqlite3" {
		os.Remove(viper.GetString("db.driver.dsn"))
	}
}
