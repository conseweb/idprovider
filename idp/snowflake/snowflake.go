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
	"errors"
	"net"
	"sync"
	"time"
)

// a distributed unique id generator inspired by Twitter's Snowflake

const (
	BitLenTime      = 41                               // bit length of time
	BitLenSequence  = 12                               // bit length of sequence number
	BitLenMachineID = 63 - BitLenTime - BitLenSequence // bit length of machine id
)

type Settings struct {
	StartTime      time.Time
	MachineID      func() (uint64, error)
	CheckMachineID func(uint64) bool
}

type Snowflake struct {
	l           *sync.Mutex
	startTime   int64
	elapsedTime int64
	sequence    uint64
	machineID   uint64
}

func NewSnowflake(st *Settings) *Snowflake {
	sf := &Snowflake{
		l:        &sync.Mutex{},
		sequence: uint64(1<<BitLenSequence - 1),
	}

	if st.StartTime.After(time.Now()) {
		return nil
	}

	if st.StartTime.IsZero() {
		sf.startTime = toSnowflakeTime(time.Date(2016, 8, 16, 16, 35, 0, 0, time.UTC))
	} else {
		sf.startTime = toSnowflakeTime(st.StartTime)
	}

	var err error
	if st.MachineID == nil {
		sf.machineID, err = lowerPrivateIP()
	} else {
		sf.machineID, err = st.MachineID()
	}

	if err != nil || (st.CheckMachineID != nil && !st.CheckMachineID(sf.machineID)) {
		return nil
	}

	return sf
}

func (sf *Snowflake) NextID() (uint64, error) {
	const maskSequence = uint64(1<<BitLenSequence - 1)

	sf.l.Lock()
	defer sf.l.Unlock()

	current := currentElapsedTime(sf.startTime)
	if sf.elapsedTime < current {
		sf.elapsedTime = current
		sf.sequence = 0
	} else {
		sf.sequence = (sf.sequence + 1) & maskSequence
		if sf.sequence == 0 {
			sf.elapsedTime++
			overtime := sf.elapsedTime - current
			time.Sleep(sleepTime(overtime))
		}
	}

	return sf.toID()
}

func (sf *Snowflake) toID() (uint64, error) {
	if sf.elapsedTime >= 1<<BitLenTime {
		return 0, errors.New("over the time limit")
	}

	return uint64(sf.elapsedTime)<<(BitLenSequence+BitLenMachineID) | sf.sequence<<BitLenMachineID | sf.machineID, nil
}

func sleepTime(overtime int64) time.Duration {
	return time.Duration(overtime)*10*time.Millisecond - time.Duration(time.Now().UTC().UnixNano()%1e7)*time.Nanosecond
}

func toSnowflakeTime(t time.Time) int64 {
	return t.UTC().UnixNano() / 1e7
}

func privateIPv4() (net.IP, error) {
	ias, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	for _, ia := range ias {
		ipnet, ok := ia.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}

		ip := ipnet.IP.To4()
		if isPrivateIPv4(ip) {
			return ip, nil
		}
	}

	return nil, errors.New("no private ip address")
}

func isPrivateIPv4(ip net.IP) bool {
	return ip != nil && (ip[0] == 10 || ip[0] == 172 && (ip[1] >= 16 && ip[1] < 32) || ip[0] == 192 && ip[1] == 168)
}

func lowerPrivateIP() (uint64, error) {
	ip, err := privateIPv4()
	if err != nil {
		return 0, err
	}

	return uint64(ip[2]<<8) + uint64(ip[3]), nil
}

func currentElapsedTime(startTime int64) int64 {
	return toSnowflakeTime(time.Now()) - startTime
}
