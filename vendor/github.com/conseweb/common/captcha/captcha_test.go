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
package captcha

import (
	"gopkg.in/check.v1"
	"testing"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type TestCaptcha struct {
}

var _ = check.Suite(&TestCaptcha{})

func (t *TestCaptcha) TestCaptchaNew(c *check.C) {
	c.Check(len(New("13800000000")), check.Equals, CaptchaLen)
}

func (t *TestCaptcha) TestCaptchaNewLen(c *check.C) {
	c.Check(len(NewLen("13800000001", 10)), check.Equals, 10)
}

func (t *TestCaptcha) TestCaptchaVerifyOK(c *check.C) {
	cpt := New("13800000002")
	c.Check(Verify("13800000002", []byte(cpt)), check.Equals, true)
}

func (t *TestCaptcha) TestCaptchaVerifyError(c *check.C) {
	New("13800000003")
	c.Check(Verify("13800000003", []byte("ajbdd")), check.Equals, false)
}

func (t *TestCaptcha) TestCaptchaVerifyStringOK(c *check.C) {
	cpt := New("13800000004")
	c.Check(VerifyString("13800000004", cpt), check.Equals, true)
}

func (t *TestCaptcha) TestCaptchaVerifyStringError(c *check.C) {
	New("13800000005")
	c.Check(VerifyString("13800000005", "SDFJEWOJ"), check.Equals, false)
}
