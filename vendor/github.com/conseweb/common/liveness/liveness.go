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
	"os"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/hyperledger/fabric/flogging"
	"github.com/op/go-logging"
	"github.com/spf13/viper"
)

var (
	livenessLogger = logging.MustGetLogger("liveness")

	// member list
	members *memberlist.Memberlist
)

// InitLiveness
func InitLiveness() (err error) {
	flogging.LoggingInit("liveness")

	livenessLogger.Info("init liveness, join into memberlist network")
	hostname, _ := os.Hostname()
	addr := viper.GetString("liveness.address")
	port := viper.GetInt("liveness.port")
	if port <= 0 {
		port = 7046
	}
	members, err = memberlist.Create(&memberlist.Config{
		Name:            fmt.Sprintf("%s_%s_%v", viper.GetString("liveness.role"), hostname, port),
		BindAddr:        addr,
		BindPort:        port,
		AdvertiseAddr:   addr,
		AdvertisePort:   port,
		ProtocolVersion: memberlist.ProtocolVersionMax,
		TCPTimeout: func() time.Duration {
			duration, err := time.ParseDuration(viper.GetString("liveness.tcptimeout"))
			if err != nil {
				duration = time.Second * 10
			}

			return duration
		}(),
		IndirectChecks:          3, // Use 3 nodes for the indirect ping
		RetransmitMult:          4, // Retransmit a message 4 * log(N+1) nodes
		SuspicionMult:           6, // Suspect a node for 6 * log(N+1) * Interval
		SuspicionMaxTimeoutMult: 6, // For 10k nodes this will give a max timeout of 120 seconds
		PushPullInterval: func() time.Duration {
			duration, err := time.ParseDuration(viper.GetString("liveness.interval"))
			if err != nil {
				duration = time.Second * 60
			}

			return duration
		}(),
		ProbeTimeout:           3 * time.Second, // Reasonable RTT time for WAN
		ProbeInterval:          5 * time.Second, // Failure check every 5 second
		DisableTcpPings:        false,           // TCP pings are safe, even with mixed versions
		AwarenessMaxMultiplier: 8,               // Probe interval backs off to 8 seconds

		GossipNodes: func() int {
			nodes := viper.GetInt("liveness.gossipNodes")
			if nodes <= 0 {
				nodes = 4
			}
			return nodes
		}(), // Gossip nodes
		GossipInterval: func() time.Duration {
			duration, err := time.ParseDuration(viper.GetString("liveness.gossipInterval"))
			if err != nil {
				duration = 500 * time.Millisecond
			}

			return duration
		}(), // Gossip more rapidly

		EnableCompression: true, // Enable compression by default

		SecretKey: []byte(viper.GetString("liveness.secretKey")),
		Keyring:   nil,

		DNSConfigPath: "/etc/resolv.conf",

		HandoffQueueDepth: 1024,
	})
	if err != nil {
		livenessLogger.Errorf("create memberlist network return error: %v", err)
		return
	}

	// check rootnode
	rootnodes := viper.GetStringSlice("liveness.rootnode")
	livenessLogger.Infof("config rootnodes: %v", rootnodes)
	_, err = members.Join(rootnodes)
	if err != nil {
		livenessLogger.Errorf("join into memberlist network return error: %v", err)
	}

	return
}

// GetMembers return a not nil memberlist
func GetMembers() *memberlist.Memberlist {
	if members == nil {
		InitLiveness()
	}

	return members
}

// LivenessMembers returns a list of all known live nodes.
func LivenessMembers() []*memberlist.Node {
	ms := GetMembers().Members()
	for _, m := range ms {
		livenessLogger.Debugf("live node: %+v", m)
	}

	msCopy := make([]*memberlist.Node, len(ms))
	copy(msCopy, ms)
	return msCopy
}
