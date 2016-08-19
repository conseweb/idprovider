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
package protos

import (
	"gopkg.in/check.v1"
)

func (t *TestProtos) TestResponseOK(c *check.C) {
	ok := ResponseOK()
	c.Check(ok.OK(), check.Equals, true)
}

func (t *TestProtos) TestNewError(c *check.C) {
	c.Check(NewError(ErrorType_NONE_ERROR, "ok").OK(), check.Equals, true)
	c.Check(NewError(ErrorType_INVALID_PARAM, "not ok").OK(), check.Equals, false)
}

func (t *TestProtos) TestNewErrorf(c *check.C) {
	c.Check(NewError(ErrorType_INVALID_PARAM, "not ok").Message, check.Equals, "not ok")
}
