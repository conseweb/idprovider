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
	"time"
	"sync"
	"container/list"
)

// a store interface to hold captcha info
type Store interface {
	Set(id string, digits []byte)
	Get(id string, clear bool) (digits []byte)
}

// it shows when the id is set into storage
type idByTimeValue struct {
	timestamp time.Time
	id string
}

// memoryStore is an internal store for captcha
type memoryStore struct {
	sync.RWMutex
	digitsById map[string][]byte
	idByTime *list.List
	// Number of items stored since last collection.
	numStored int
	// Number of saved items that triggers collection.
	collectNum int
	// Expiration time
	expiration time.Duration
}

// NewMemoryStore returns a new standard memory store for captcha
func NewMemoryStore(collectNum int, expiration time.Duration) Store {
	s := new(memoryStore)
	s.digitsById = make(map[string][]byte)
	s.idByTime = list.New()
	s.collectNum = collectNum
	s.expiration = expiration
	return s
}

func (s *memoryStore) Set(id string, digits []byte) {
	s.Lock()

	// if found, just return
	if _, ok := s.digitsById[id]; ok {
		s.Unlock()
		return
	}

	s.digitsById[id] = digits
	s.idByTime.PushBack(idByTimeValue{time.Now(), id})
	s.numStored++
	if s.numStored <= s.collectNum {
		s.Unlock()
		return
	}
	s.Unlock()
	go s.collect()
}

func (s *memoryStore) Get(id string, clear bool) (digits []byte) {
	if !clear {
		s.RLock()
		defer s.RUnlock()
	} else {
		s.Lock()
		defer s.Unlock()
	}

	var ok bool
	digits, ok = s.digitsById[id]
	if !ok {
		return
	}

	if clear {
		delete(s.digitsById, id)
	}
	return
}

func (s *memoryStore) collect() {
	now := time.Now()
	s.Lock()
	defer s.Unlock()

	for e := s.idByTime.Front(); e != nil ; {
		ev, ok := e.Value.(idByTimeValue)
		if !ok {
			return
		}

		if ev.timestamp.Add(s.expiration).Before(now) {
			delete(s.digitsById, ev.id)
			next := e.Next()
			s.idByTime.Remove(e)
			e = next
		} else {
			return
		}
	}
}