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
	cpb "github.com/conseweb/common/protos"
	pb "github.com/conseweb/idprovider/protos"
	"github.com/op/go-logging"
	"golang.org/x/net/context"
)

var (
	idppLogger = logging.MustGetLogger("idpp")
)

type IDPP struct {
	idp *IDP
}

// Acquire email/tel captcha
func (idpp *IDPP) AcquireCaptcha(ctx context.Context, req *pb.AcquireCaptchaReq) (*pb.AcquireCaptchaRsp, error) {
	rsp := &pb.AcquireCaptchaRsp{
		Error: cpb.ResponseOK(),
	}

	// 1. verify signup
	if !req.Validate() {
		rsp.Error = cpb.NewError(cpb.ErrorType_INVALID_PARAM, "AcquireCaptchaReq is invalid.")
		idppLogger.Debugf("AcquireCaptcha's request is invalid: %v", req)
		goto RET
	}

	// 2. verify already user
	if idpp.idp.isUserExist(req.SignUp) {
		rsp.Error = cpb.NewErrorf(cpb.ErrorType_ALREADY_SIGNUP, "%s is already a user", req.SignUp)
		goto RET
	}

	// 3. send captcha
	if err := idpp.idp.sendCaptcha(req.SignUpType, req.SignUp); err != nil {
		rsp.Error = cpb.NewError(cpb.ErrorType_INTERNAL_ERROR, err.Error())
		goto RET
	}

RET:
	return rsp, nil
}

// Verify email/tel captcha
func (idpp *IDPP) VerifyCaptcha(ctx context.Context, req *pb.VerifyCaptchaReq) (*pb.VerifyCaptchaRsp, error) {
	rsp := &pb.VerifyCaptchaRsp{
		Error: cpb.ResponseOK(),
	}

	// 1. verify captcha
	if !idpp.idp.verifyCaptcha(req.SignUp, req.Captcha) {
		rsp.Error = cpb.NewError(cpb.ErrorType_INVALID_CAPTCHA, "captcha is wrong, may be expired")
		goto RET
	}

RET:
	return rsp, nil
}

// Register a user
func (idpp *IDPP) RegisterUser(ctx context.Context, req *pb.RegisterUserReq) (*pb.RegisterUserRsp, error) {
	rsp := &pb.RegisterUserRsp{
		Error: cpb.ResponseOK(),
	}

	// declaration field
	var user *pb.User

	// 1. verify already user
	if idpp.idp.isUserExist(req.SignUp) {
		rsp.Error = cpb.NewErrorf(cpb.ErrorType_ALREADY_SIGNUP, "%s is already a user", req.SignUp)
		goto RET
	}

	// 2. register a user
	user = new(pb.User)
	switch req.SignUpType {
	case pb.SignUpType_EMAIL:
		user.Email = req.SignUp
	case pb.SignUpType_MOBILE:
		user.Mobile = req.SignUp
	}
	user.Pass = req.Pass
	user.Nick = req.Nick
	if u, err := idpp.idp.registerUser(user); err != nil {
		idppLogger.Debugf("registerUser return error: %v", err)
		rsp.Error = cpb.NewError(cpb.ErrorType_INTERNAL_ERROR, err.Error())
		goto RET
	} else {
		rsp.User = u
	}

RET:
	return rsp, nil
}

// Bind a device for a user
func (idpp *IDPP) BindDeviceForUser(ctx context.Context, req *pb.BindDeviceReq) (*pb.BindDeviceRsp, error) {
	rsp := &pb.BindDeviceRsp{
		Error: cpb.ResponseOK(),
	}

	// 1. verify user identity
	if _, err := idpp.idp.fetchUserByID(req.UserID); err != nil {
		idppLogger.Errorf("verify user identity error: %v", err)
		rsp.Error = cpb.NewError(cpb.ErrorType_INVALID_USERID, err.Error())
		goto RET
	}

	// 2. verify device exist
	// if user has another device using same mac address, can't be done.
	// TODO only farmer require this check?
	if req.For == pb.DeviceFor_FARMER {
		if devs, err := idpp.idp.fetchUserDevicesByMac(req.UserID, req.Mac); err == nil && len(devs) > 0 {
			idppLogger.Debugf("user[%s] already has a device using mac: %s", req.UserID, req.Mac)
			rsp.Error = cpb.NewErrorf(cpb.ErrorType_ALREADY_DEVICE_MAC, "user[%s] already has a device using mac: %s", req.UserID, req.Mac)
			goto RET
		}
	}

	// 3. verify device using userid & alias
	// if user has another device using same alias, can't be done.
	if req.Alias == "" {
		req.Alias = "default"
	}
	if dev, err := idpp.idp.fetchUserDeviceByAlias(req.UserID, req.Alias); err == nil && dev != nil && dev.DeviceID != "" {
		idppLogger.Debugf("user[%s] already has a device using alias: %s", req.UserID, req.Alias)
		rsp.Error = cpb.NewErrorf(cpb.ErrorType_ALREADY_DEVICE_ALIAS, "user[%s] already has a device using alias: %s", req.UserID, req.Alias)
		goto RET
	}

	// 4. bind a device
	if dev, err := idpp.idp.bindUserDevice(&pb.Device{
		UserID: req.UserID,
		Os:     req.Os,
		For:    req.For,
		Mac:    req.Mac,
		Alias:  req.Alias,
	}); err != nil {
		rsp.Error = cpb.NewError(cpb.ErrorType_INTERNAL_ERROR, err.Error())
		goto RET
	} else {
		rsp.Device = dev
	}

RET:
	return rsp, nil
}
