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
	pb "github.com/conseweb/idprovider/protos"
	"github.com/spf13/viper"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/check.v1"
	"time"
)

// NewClientConnectionWithAddress Returns a new grpc.ClientConn to the given address.
func NewClientConnectionWithAddress(address string, block bool, tslEnabled bool, creds credentials.TransportCredentials) (*grpc.ClientConn, error) {
	var opts []grpc.DialOption
	if tslEnabled {
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}
	opts = append(opts, grpc.WithTimeout(3*time.Second))
	if block {
		opts = append(opts, grpc.WithBlock())
	}
	conn, err := grpc.Dial(address, opts...)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (t *TestIDP) TestAcquireCaptchaOK(c *check.C) {
	conn, err := NewClientConnectionWithAddress(viper.GetString("server.port"), false, false, nil)
	c.Check(err, check.IsNil)
	defer conn.Close()

	idppcli := pb.NewIDPPClient(conn)
	rsp, err := idppcli.AcquireCaptcha(context.Background(), &pb.AcquireCaptchaReq{
		SignUpType: pb.SignUpType_EMAIL,
		SignUp:     "xxx@example.com",
	})
	c.Check(err, check.IsNil)
	c.Check(rsp, check.NotNil)
	c.Check(rsp.Error.OK(), check.Equals, true)
}

func (t *TestIDP) TestAcquireCaptchaWrong(c *check.C) {
	conn, err := NewClientConnectionWithAddress(viper.GetString("server.port"), false, false, nil)
	c.Check(err, check.IsNil)
	defer conn.Close()

	idppcli := pb.NewIDPPClient(conn)
	rsp, err := idppcli.AcquireCaptcha(context.Background(), &pb.AcquireCaptchaReq{
		SignUpType: pb.SignUpType_EMAIL,
		SignUp:     "xxxjsdfjddd",
	})
	c.Check(err, check.IsNil)
	c.Check(rsp, check.NotNil)
	c.Check(rsp.Error.OK(), check.Equals, false)
}

func (t *TestIDP) TestVerifyCaptchaWrong(c *check.C) {
	conn, err := NewClientConnectionWithAddress(viper.GetString("server.port"), false, false, nil)
	c.Check(err, check.IsNil)
	defer conn.Close()

	idppcli := pb.NewIDPPClient(conn)
	rsp, err := idppcli.VerifyCaptcha(context.Background(), &pb.VerifyCaptchaReq{
		SignUpType: pb.SignUpType_EMAIL,
		SignUp:     "xxxjsdfjddd",
		Captcha:    "sdfjidf",
	})
	c.Check(err, check.IsNil)
	c.Check(rsp, check.NotNil)
	c.Check(rsp.Error.OK(), check.Equals, false)
}

func (t *TestIDP) TestRegisterUser(c *check.C) {
	c.Skip("not impl")
}