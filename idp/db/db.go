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
package db

import (
	"errors"

	pb "github.com/conseweb/common/protos"
	"github.com/op/go-logging"
)

var (
	DBLogger = logging.MustGetLogger("idp/db")

	ErrInvalidParams = errors.New("invalid params")
)

type DBAdapter interface {
	InitDB() error
	IsUserExist(username string) bool
	RegisterUser(user *pb.User) (*pb.User, error)
	FetchUserByID(userID string) (*pb.User, error)
	FetchUserByEmail(email string) (*pb.User, error)
	FetchUserByMobile(mobile string) (*pb.User, error)
	FetchUserDevices(userID string) ([]*pb.Device, error)
	FetchUserDeviceByAlias(userID, alias string) (*pb.Device, error)
	FetchUserDeviceByMac(userID, mac string) (*pb.Device, error)
	BindUserDevice(dev *pb.Device) (*pb.Device, error)
	FetchDeviceByID(deviceID string) (*pb.Device, error)
	Close() error
}
