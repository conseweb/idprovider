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
package idp

import (
	"crypto/x509"
	"fmt"
	"github.com/conseweb/common/crypto"
	pb "github.com/conseweb/common/protos"
	"github.com/conseweb/common/utils"
	"github.com/hyperledger/fabric/core/crypto/primitives"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/check.v1"
	"runtime"
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
	rsp, err := t.idppCli.AcquireCaptcha(context.Background(), &pb.AcquireCaptchaReq{
		SignUpType: pb.SignUpType_EMAIL,
		SignUp:     "xxx@example.com",
	})
	c.Check(err, check.IsNil)
	c.Check(rsp, check.NotNil)
	c.Check(rsp.Error.OK(), check.Equals, true)

	rsp1, err := t.idppCli.AcquireCaptcha(context.Background(), &pb.AcquireCaptchaReq{
		SignUpType: pb.SignUpType_MOBILE,
		SignUp: "13800000000",
	})

	c.Check(err, check.IsNil)
	c.Check(rsp1, check.NotNil)
	c.Check(rsp1.Error.OK(), check.Equals, true)

	time.Sleep(time.Second)
}

func (t *TestIDP) TestAcquireCaptchaWrong(c *check.C) {
	rsp, err := t.idppCli.AcquireCaptcha(context.Background(), &pb.AcquireCaptchaReq{
		SignUpType: pb.SignUpType_EMAIL,
		SignUp:     "xxxjsdfjddd",
	})
	c.Check(err, check.IsNil)
	c.Check(rsp, check.NotNil)
	c.Check(rsp.Error.OK(), check.Equals, false)
}

func (t *TestIDP) TestVerifyCaptchaWrong(c *check.C) {
	rsp, err := t.idppCli.VerifyCaptcha(context.Background(), &pb.VerifyCaptchaReq{
		SignUpType: pb.SignUpType_EMAIL,
		SignUp:     "xxxjsdfjddd",
		Captcha:    "sdfjidf",
	})
	c.Check(err, check.IsNil)
	c.Check(rsp, check.NotNil)
	c.Check(rsp.Error.OK(), check.Equals, false)
}

func (t *TestIDP) TestRegisterUser(c *check.C) {
	// test1
	req1 := &pb.RegisterUserReq{
		SignUpType: pb.SignUpType_MOBILE,
		SignUp:     "13800000000",
		Nick:       "13800000000",
		Pass:       "13800000000",
	}
	req1.Wpub = []byte("13800000000")
	priv, err := primitives.NewECDSAKey()
	c.Check(err, check.IsNil)

	pubraw, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	c.Check(err, check.IsNil)
	req1.Spub = pubraw

	c.Check(crypto.SignGRPCRequest(req1, priv), check.IsNil)
	c.Logf("req1: %+v\n", req1)

	rsp1, err1 := t.idppCli.RegisterUser(context.Background(), req1)
	c.Check(err1, check.IsNil)
	c.Check(rsp1, check.NotNil)
	c.Check(rsp1.Error.OK(), check.Equals, true)
	c.Check(rsp1.User.Nick, check.Equals, "13800000000")

	// test2
	rsp2, err2 := t.idppCli.RegisterUser(context.Background(), req1)
	c.Check(err2, check.IsNil)
	c.Check(rsp2, check.NotNil)
	c.Check(rsp2.Error.OK(), check.Equals, false)
}

func (t *TestIDP) TestBindUserDevice(c *check.C) {
	// test register user
	req1 := &pb.RegisterUserReq{
		SignUpType: pb.SignUpType_MOBILE,
		SignUp:     "13800000001",
		Nick:       "13800000001",
		Pass:       "13800000001",
	}

	req1.Wpub = []byte("13800000001")
	priv, err := primitives.NewECDSAKey()
	c.Check(err, check.IsNil)

	pubraw, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	c.Check(err, check.IsNil)
	req1.Spub = pubraw

	c.Check(crypto.SignGRPCRequest(req1, priv), check.IsNil)

	rsp1, err1 := t.idppCli.RegisterUser(context.Background(), req1)
	c.Check(err1, check.IsNil)
	c.Check(rsp1, check.NotNil)
	c.Check(rsp1.Error.OK(), check.Equals, true)
	c.Check(rsp1.User.Nick, check.Equals, "13800000001")

	// test bind user device ok
	req2 := &pb.BindDeviceReq{
		UserID: rsp1.User.UserID,
		Os:     fmt.Sprintf("%s, %s", runtime.GOOS, runtime.GOARCH),
		For:    pb.DeviceFor_FARMER,
		Mac:    utils.GetHardwareAddr(),
	}

	req2.Wpub = []byte("binduserdeviceok")
	req2.Spub = []byte("atthistimenotuse")
	c.Check(crypto.SignGRPCRequest(req2, priv), check.IsNil)

	rsp2, err2 := t.idppCli.BindDeviceForUser(context.Background(), req2)
	c.Check(err2, check.IsNil)
	c.Check(rsp2, check.NotNil)
	c.Check(rsp2.Error.OK(), check.Equals, true)

	// test bind user device wrong
	rsp3, err3 := t.idppCli.BindDeviceForUser(context.Background(), req2)

	c.Check(err3, check.IsNil)
	c.Check(rsp3, check.NotNil)
	c.Check(rsp3.Error.OK(), check.Equals, false)
}
