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
	"crypto/x509"
	"fmt"
	"github.com/conseweb/common/crypto"
	pb "github.com/conseweb/common/protos"
	"github.com/conseweb/common/utils"
	"github.com/hyperledger/fabric/core/crypto/primitives"
	"golang.org/x/net/context"
	"gopkg.in/check.v1"
	"runtime"
)

func (t *TestIDP) TestVerifyDevice(c *check.C) {
	// test register user
	req1 := &pb.RegisterUserReq{
		SignUpType: pb.SignUpType_MOBILE,
		SignUp:     "13800000002",
		Nick:       "13800000002",
		Pass:       "13800000002",
	}

	req1.Wpub = []byte("13800000002")
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
	c.Check(rsp1.User.Nick, check.Equals, "13800000002")

	// test bind user device ok
	rsp2, err2 := t.idppCli.BindDeviceForUser(context.Background(), &pb.BindDeviceReq{
		UserID: rsp1.User.UserID,
		Os:     fmt.Sprintf("%s, %s", runtime.GOOS, runtime.GOARCH),
		For:    pb.DeviceFor_FARMER,
		Mac:    utils.GetHardwareAddr(),
	})
	c.Check(err2, check.IsNil)
	c.Check(rsp2, check.NotNil)
	c.Check(rsp2.Error.OK(), check.Equals, true)

	// test verify device
	rsp3, err3 := t.idpaCli.VerifyDevice(context.Background(), &pb.VerifyDeviceReq{
		DeviceID: rsp2.Device.DeviceID,
		For:      pb.DeviceFor_FARMER,
	})
	c.Check(err3, check.IsNil)
	c.Check(rsp3, check.NotNil)
	c.Check(rsp3.Error.OK(), check.Equals, true)

	// test verify device(id wrong)
	rsp4, err4 := t.idpaCli.VerifyDevice(context.Background(), &pb.VerifyDeviceReq{
		DeviceID: "wrong id, whatever",
		For:      pb.DeviceFor_FARMER,
	})
	c.Check(err4, check.IsNil)
	c.Check(rsp4, check.NotNil)
	c.Check(rsp4.Error.OK(), check.Equals, false)

	// test verify device(for wrong)
	rsp5, err5 := t.idpaCli.VerifyDevice(context.Background(), &pb.VerifyDeviceReq{
		DeviceID: rsp2.Device.DeviceID,
		For:      pb.DeviceFor_SUPERVISOR,
	})
	c.Check(err5, check.IsNil)
	c.Check(rsp5, check.NotNil)
	c.Check(rsp5.Error.OK(), check.Equals, false)
}
