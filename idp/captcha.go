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
	"github.com/conseweb/common/captcha"
	pb "github.com/conseweb/common/protos"
)

func (idp *IDP) sendCaptcha(signUpType pb.SignUpType, signUp string) error {
	var err error
	switch signUpType {
	case pb.SignUpType_EMAIL:
		err = idp.sendCaptchaEmail(signUp)
	case pb.SignUpType_MOBILE:
		err = idp.sendCaptchaSMS(signUp)
	}

	if err != nil {
		idpLogger.Errorf("sending captcha return error: %v", err)
	}

	return err
}

// verify captcha
func (idp *IDP) verifyCaptcha(signup, capt string) bool {
	idpLogger.Debugf("IDP verify captcha: [%s, %s]", signup, capt)
	return captcha.VerifyString(signup, capt)
}
