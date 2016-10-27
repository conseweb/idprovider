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
	"fmt"
	"github.com/conseweb/common/crypto"
	pb "github.com/conseweb/common/protos"
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
	idppLogger.Debugf("gRPC AcquireCaptcha, request: %+v", req)
	rsp := &pb.AcquireCaptchaRsp{
		Error: pb.ResponseOK(),
	}

	// 1. verify signup
	if !req.Validate() {
		rsp.Error = pb.NewError(pb.ErrorType_INVALID_PARAM, "AcquireCaptchaReq is invalid.")
		idppLogger.Debugf("AcquireCaptcha's request is invalid: %v", req)
		goto RET
	}

	// 2. verify already user
	if idpp.idp.isUserExist(req.SignUp) {
		rsp.Error = pb.NewErrorf(pb.ErrorType_ALREADY_SIGNUP, "%s is already a user", req.SignUp)
		goto RET
	}

	// 3. send captcha
	if err := idpp.idp.sendCaptcha(req.SignUpType, req.SignUp); err != nil {
		rsp.Error = pb.NewError(pb.ErrorType_INTERNAL_ERROR, err.Error())
		goto RET
	}

RET:
	return rsp, nil
}

// Verify email/tel captcha
func (idpp *IDPP) VerifyCaptcha(ctx context.Context, req *pb.VerifyCaptchaReq) (*pb.VerifyCaptchaRsp, error) {
	rsp := &pb.VerifyCaptchaRsp{
		Error: pb.ResponseOK(),
	}

	// 1. verify captcha
	if !idpp.idp.verifyCaptcha(req.SignUp, req.Captcha) {
		rsp.Error = pb.NewError(pb.ErrorType_INVALID_CAPTCHA, "captcha is wrong, may be expired")
		goto RET
	}

RET:
	return rsp, nil
}

// Register a user
func (idpp *IDPP) RegisterUser(ctx context.Context, req *pb.RegisterUserReq) (*pb.RegisterUserRsp, error) {
	idppLogger.Debug("idpp gRPC: RegisterUser")

	rsp := &pb.RegisterUserRsp{
		Error: pb.ResponseOK(),
	}

	// declaration field
	var (
		user *pb.User
	)

	// 0. check signature
	if err := crypto.VerifyGRPCRequest(req, req.Spub); err != nil {
		idppLogger.Errorf("parsePKIPublicKey error: %v", err)
		rsp.Error = pb.NewError(pb.ErrorType_INVALID_SIGNATURE, err.Error())
		goto RET
	}

	// 1. verify already user
	if idpp.idp.isUserExist(req.SignUp) {
		rsp.Error = pb.NewErrorf(pb.ErrorType_ALREADY_SIGNUP, "%s is already a user", req.SignUp)
		goto RET
	}

	// 2. register a user
	user = new(pb.User)
	switch req.SignUpType {
	case pb.SignUpType_MOBILE:
		user.Mobile = req.SignUp
	default:
		user.Email = req.SignUp
	}
	user.Pass = req.Pass
	user.Nick = req.Nick
	user.UserType = req.UserType
	user.Wpub = req.Wpub
	user.Spub = req.Spub

	idppLogger.Debugf("before register user: %#v", user)
	if u, err := idpp.idp.registerUser(user); err != nil {
		idppLogger.Debugf("registerUser return error: %v", err)
		rsp.Error = pb.NewError(pb.ErrorType_INTERNAL_ERROR, err.Error())
		goto RET
	} else {
		idppLogger.Debugf("after register user: %#v", u)
		rsp.User = u
	}

RET:
	return rsp, nil
}

// Login a user
func (idpp *IDPP) LoginUser(ctx context.Context, req *pb.LoginUserReq) (*pb.LoginUserRsp, error) {
	rsp := &pb.LoginUserRsp{
		Error: pb.ResponseOK(),
	}

	// 0. get user info
	var (
		user *pb.User
		err  error
	)
	switch req.SignInType {
	case pb.SignInType_SI_EMAIL:
		user, err = idpp.idp.dbAdapter.FetchUserByEmail(req.SignIn)
	case pb.SignInType_SI_MOBILE:
		user, err = idpp.idp.dbAdapter.FetchUserByMobile(req.SignIn)
	case pb.SignInType_SI_USERID:
		user, err = idpp.idp.dbAdapter.FetchUserByID(req.SignIn)
	default:
		err = fmt.Errorf("invalid signInType: %v", req.SignInType)
	}
	if err != nil {
		err = fmt.Errorf("user(%s) not existed.", req.SignIn)
		idppLogger.Warning(err.Error())
		rsp.Error = pb.NewError(pb.ErrorType_INVALID_SIGN_IN, err.Error())
		goto RET
	}

	// 1. check signature
	if err := crypto.VerifyGRPCRequest(req, user.Spub); err != nil {
		idppLogger.Errorf("parsePKIPublicKey error: %v", err)
		rsp.Error = pb.NewError(pb.ErrorType_INVALID_SIGNATURE, err.Error())
		goto RET
	}

	// 2. check password
	if !idpp.idp.verifyPass(req.Password, user.Pass) {
		rsp.Error = pb.NewError(pb.ErrorType_INVALID_SIGN_IN, "invalid password")
		goto RET
	}

	// 3. fetch devices
	user.Devices, err = idpp.idp.dbAdapter.FetchUserDevices(user.UserID)
	if err != nil {
		rsp.Error = pb.NewError(pb.ErrorType_INTERNAL_ERROR, err.Error())
		goto RET
	}
	rsp.User = user

RET:
	return rsp, nil
}

// Bind a device for a user
func (idpp *IDPP) BindDeviceForUser(ctx context.Context, req *pb.BindDeviceReq) (*pb.BindDeviceRsp, error) {
	rsp := &pb.BindDeviceRsp{
		Error: pb.ResponseOK(),
	}

	// 1. verify user identity
	if user, err := idpp.idp.dbAdapter.FetchUserByID(req.UserID); err != nil {
		idppLogger.Errorf("verify user identity error: %v", err)
		rsp.Error = pb.NewError(pb.ErrorType_INVALID_USERID, err.Error())
		goto RET
	} else {
		// 0. check signature
		if err := crypto.VerifyGRPCRequest(req, user.Spub); err != nil {
			idppLogger.Errorf("parsePKIPublicKey error: %v", err)
			rsp.Error = pb.NewError(pb.ErrorType_INVALID_SIGNATURE, err.Error())
			goto RET
		}
	}

	// 2. verify device exist
	// if user has another device using same mac address, can't be done.
	// TODO only farmer require this check?
	if req.For == pb.DeviceFor_FARMER {
		if dev, err := idpp.idp.dbAdapter.FetchUserDeviceByMac(req.UserID, req.Mac); err == nil && dev != nil && dev.DeviceID != "" {
			idppLogger.Debugf("user[%s] already has a device using mac: %s", req.UserID, req.Mac)
			rsp.Error = pb.NewErrorf(pb.ErrorType_ALREADY_DEVICE_MAC, "user[%s] already has a device using mac: %s", req.UserID, req.Mac)
			goto RET
		}
	}

	// 3. verify device using userid & alias
	// if user has another device using same alias, can't be done.
	if req.Alias == "" {
		req.Alias = "default"
	}
	if dev, err := idpp.idp.dbAdapter.FetchUserDeviceByAlias(req.UserID, req.Alias); err == nil && dev != nil && dev.DeviceID != "" {
		idppLogger.Debugf("user[%s] already has a device using alias: %s", req.UserID, req.Alias)
		rsp.Error = pb.NewErrorf(pb.ErrorType_ALREADY_DEVICE_ALIAS, "user[%s] already has a device using alias: %s", req.UserID, req.Alias)
		goto RET
	}

	// 4. bind a device
	if dev, err := idpp.idp.bindUserDevice(&pb.Device{
		UserID: req.UserID,
		Os:     req.Os,
		For:    req.For,
		Mac:    req.Mac,
		Alias:  req.Alias,
		Wpub:   req.Wpub,
		Spub:   req.Spub,
	}); err != nil {
		rsp.Error = pb.NewError(pb.ErrorType_INTERNAL_ERROR, err.Error())
		goto RET
	} else {
		rsp.Device = dev
	}

RET:
	return rsp, nil
}
