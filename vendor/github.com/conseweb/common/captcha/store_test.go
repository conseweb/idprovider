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
package captcha

import (
	"fmt"
	"gopkg.in/check.v1"
)

func (t *TestCaptcha) TestStoreSetGet(c *check.C) {
	s := NewMemoryStore(CollectNum, Expiration)
	id := "captcha id"
	d := randomBytes(10)
	s.Set(id, d)
	d2 := s.Get(id, false)
	c.Check(d2, check.NotNil)
	c.Check(d, check.DeepEquals, d2)
}

func (t *TestCaptcha) TestStoreGetClear(c *check.C) {
	s := NewMemoryStore(CollectNum, Expiration)
	id := "captcha id"
	d := randomBytes(10)
	s.Set(id, d)
	d2 := s.Get(id, true)
	c.Check(d2, check.NotNil)
	c.Check(d, check.DeepEquals, d2)

	d2 = s.Get(id, false)
	c.Check(d2, check.IsNil)
}

func (t *TestCaptcha) BenchmarkStoreSet(c *check.C) {
	s := NewMemoryStore(c.N, Expiration)
	for i := 0; i < c.N; i++ {
		s.Set(fmt.Sprintf("id_%d", i), randomBytes(10))
	}
}

func (t *TestCaptcha) BenchmarkStoreGet(c *check.C) {
	s := NewMemoryStore(CollectNum, Expiration)
	s.Set("id", randomBytes(10))
	for i := 0; i < c.N; i++ {
		s.Get("id", false)
	}
}
