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
package id

import (
	"github.com/conseweb/idprovider/id/snowflake"
	"github.com/op/go-logging"
	"github.com/spf13/viper"
	"sync"
	"time"
)

const (
	default_snowflake_start_time_fmt = "2016/08/16 16:35:00"
)

var (
	sf     *snowflake.Snowflake
	sfOnce *sync.Once
	logger = logging.MustGetLogger("idprovider")
)

func init() {
	sfOnce = &sync.Once{}
}

func getSnowflake() *snowflake.Snowflake {
	sfOnce.Do(func() {
		if sf != nil {
			return
		}

		startTimeFmt := viper.GetString("idprovider.snowflake.startTime")
		if startTimeFmt == "" {
			startTimeFmt = default_snowflake_start_time_fmt
		}
		startTime, err := time.Parse("2006/01/02 15:04:05", startTimeFmt)
		if err != nil {
			logger.Fatalf("parse snowflake start time string err: %v", err)
		}

		machineID := uint64(viper.GetInt("idprovider.snowflake.machineID"))
		if machineID <= 0 {
			logger.Fatal("idprovider must set machineID")
		}
		sf = snowflake.NewSnowflake(&snowflake.Settings{
			StartTime: startTime,
			MachineID: func() (uint64, error) {
				return machineID, nil
			},
			CheckMachineID: func(machineID uint64) bool {
				return uint64(viper.GetInt("idprovider.snowflake.machineID")) == machineID
			},
		})

		if sf == nil {
			logger.Fatal("singleton snowflake init error, exit.")
		}
	})

	return sf
}

func NextID() uint64 {
	nextID, err := getSnowflake().NextID()
	if err != nil {
		logger.Errorf("generate snowflake next id err: %v", err)
	}

	return nextID
}
