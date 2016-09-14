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
	pb "github.com/conseweb/common/protos"
	"github.com/op/go-logging"
	"golang.org/x/net/context"
)

type IDPA struct {
	idp *IDP
}

var idpaLogger = logging.MustGetLogger("idpa")

// Verify device
func (idpa *IDPA) VerifyDevice(ctx context.Context, req *pb.VerifyDeviceReq) (*pb.VerifyDeviceRsp, error) {
	rsp := &pb.VerifyDeviceRsp{
		Error: pb.ResponseOK(),
	}
	idpaLogger.Debugf("IDPA.VerifyDevice, req: %+v", req)
	defer idpaLogger.Debugf("IDPA.VerifyDevice, rsp: %+v", rsp)

	var device *pb.Device
	var err error
	// 1. fetch device using device id
	if device, err = idpa.idp.fetchDeviceByID(req.DeviceID); err != nil {
		rsp.Error = pb.NewError(pb.ErrorType_INTERNAL_ERROR, err.Error())
		goto RET
	}

	// 2. device for verify
	if device.For != req.For {
		rsp.Error = pb.NewError(pb.ErrorType_INVALID_DEVICE, "device for not match")
		goto RET
	}

	switch device.For {
	case pb.DeviceFor_SUPERVISOR:
		if device.Alias != req.DeviceAlias || device.UserID != req.UserID {
			rsp.Error = pb.NewError(pb.ErrorType_INVALID_DEVICE, "device for not match")
			goto RET
		}
	}

RET:
	return rsp, nil
}
