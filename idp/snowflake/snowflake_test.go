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
package snowflake

import (
	"gopkg.in/check.v1"
	"runtime"
	"testing"
	"time"
)

func TestSnowflake(t *testing.T) {
	check.TestingT(t)
}

type SnowflakeTest struct {
	sf        *Snowflake
	startTime int64
	machineID uint64
}

var _ = check.Suite(&SnowflakeTest{})

func (this *SnowflakeTest) SetUpSuite(c *check.C) {
	t, err := time.Parse("2006/01/02 15:04:05", "2016/08/16 16:35:00")
	c.Check(err, check.IsNil)
	st := &Settings{
		StartTime: t,
	}

	this.sf = NewSnowflake(st)
	c.Check(this.sf, check.NotNil)

	this.startTime = toSnowflakeTime(st.StartTime)
	ip, _ := lowerPrivateIP()
	this.machineID = ip
}

func (this *SnowflakeTest) TestNextID(c *check.C) {
	_, err := this.sf.NextID(1, 0)
	c.Check(err, check.IsNil)
}

func (this *SnowflakeTest) TestSnowflakeInParallel(c *check.C) {
	runtime.GOMAXPROCS(runtime.NumCPU())

	consumer := make(chan uint64)

	const numID = 10000
	generate := func() {
		for i := 0; i < numID; i++ {
			id, err := this.sf.NextID(1, 0)
			c.Check(err, check.IsNil)

			consumer <- id
		}
	}

	const numGenerator = 10
	for i := 0; i < numGenerator; i++ {
		go generate()
	}

	ids := make(map[uint64]bool)
	for i := 0; i < numGenerator*numID; i++ {
		id := <-consumer

		if flag, ok := ids[id]; ok && flag {
			c.Errorf("id duplicated")
		} else {
			ids[id] = true
		}
	}
	c.Check(len(ids), check.Equals, numGenerator*numID)
}

func (this *SnowflakeTest) BenchmarkNextID(c *check.C) {
	for i := 0; i <= c.N; i++ {
		this.sf.NextID(1, 0)
	}
}
