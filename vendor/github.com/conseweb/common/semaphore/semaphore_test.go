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
package semaphore

import (
	"gopkg.in/check.v1"
	"runtime"
	"sync"
	"testing"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type SemaphoreTest struct {
}

var _ = check.Suite(&SemaphoreTest{})

func (t *SemaphoreTest) TestSemaphore(c *check.C) {
	sema := NewSemaphore(2)
	if !(sema.TryAcquire() && sema.TryAcquire() && !sema.TryAcquire()) {
		c.Error("error, TryAcquire")
	}

	sema.Release()
	sema.Release()
}

func (t *SemaphoreTest) BenchmarkSemaphore(c *check.C) {
	sema := NewSemaphore(1)
	for i := 0; i < c.N; i++ {
		if sema.TryAcquire() {
			sema.Release()
		}
	}
}

func (t *SemaphoreTest) BenchmarkSemaphoreConcurrent(c *check.C) {
	sema := NewSemaphore(1)
	wg := sync.WaitGroup{}
	workers := runtime.NumCPU()
	each := c.N / workers
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			for i := 0; i < each; i++ {
				if sema.TryAcquire() {
					sema.Release()
				}
			}
			wg.Done()
		}()
	}
	wg.Wait()
}
