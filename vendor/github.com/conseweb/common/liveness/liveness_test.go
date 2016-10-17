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
package liveness

import (
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/spf13/viper"
	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type LivenessTest struct{}

var _ = check.Suite(&LivenessTest{})

func (t *LivenessTest) SetUpSuite(c *check.C) {
	viper.Set("liveness.rootnode", "127.0.0.1:7950")
	viper.Set("liveness.role", "teller")
	viper.Set("liveness.address", "0.0.0.0")
	viper.Set("liveness.port", "7946")
	viper.Set("logging.liveness", "debug")

	config1 := memberlist.DefaultWANConfig()
	config1.Name = fmt.Sprintf("%s_7950", config1.Name)
	config1.BindPort = 7950
	config1.AdvertiseAddr = "0.0.0.0"
	config1.AdvertisePort = 7950
	memberlist.Create(config1)
}

func (t *LivenessTest) TestInitLiveness(c *check.C) {
	c.Check(InitLiveness(), check.IsNil)
}

func (t *LivenessTest) TestLivenessMembers(c *check.C) {
	time.Sleep(time.Millisecond * 500)
	c.Check(len(LivenessMembers()), check.Equals, 2)
}
