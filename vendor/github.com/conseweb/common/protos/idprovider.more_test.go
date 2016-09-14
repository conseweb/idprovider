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
package protos

import (
	"gopkg.in/check.v1"
)

func (t *TestProtos) TestValidateAcquireCaptchaEmailOk(c *check.C) {
	req := &AcquireCaptchaReq{
		SignUpType: SignUpType_EMAIL,
		SignUp:     "abc@example.com",
	}

	c.Check(req.Validate(), check.Equals, true)
}

func (t *TestProtos) TestValidateAcquireCaptchaEmailError(c *check.C) {
	req := &AcquireCaptchaReq{
		SignUpType: SignUpType_EMAIL,
		SignUp:     "jir99j]f_/sdfo994",
	}

	c.Check(req.Validate(), check.Equals, false)
}

func (t *TestProtos) TestValidateAcquireCaptchaMobileOk(c *check.C) {
	req := &AcquireCaptchaReq{
		SignUpType: SignUpType_MOBILE,
		SignUp:     "13800000000",
	}

	c.Check(req.Validate(), check.Equals, true)
}

func (t *TestProtos) TestValidateAcquireCaptchaMobileError(c *check.C) {
	req := &AcquireCaptchaReq{
		SignUpType: SignUpType_MOBILE,
		SignUp:     "374839238494",
	}

	c.Check(req.Validate(), check.Equals, false)
}
