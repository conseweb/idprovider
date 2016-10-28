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
package idp

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/conseweb/common/captcha"
	"github.com/conseweb/common/crypto"
	pb "github.com/conseweb/common/protos"
	"github.com/conseweb/common/snowflake"
	"github.com/conseweb/idprovider/idp/db"
	"github.com/hyperledger/fabric/flogging"
	"github.com/op/go-logging"
	"github.com/satori/go.uuid"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"gopkg.in/gomail.v2"
)

const (
	default_snowflake_start_time_fmt = "2016/08/16 16:35:00"
)

var (
	idpLogger = logging.MustGetLogger("idp")

	ErrInvalidParams = errors.New("invalid params")
)

// IDP holds a snowflake id generator and a db handler
type IDP struct {
	dbAdapter  db.DBAdapter
	sf         *snowflake.Snowflake
	gRPCServer *grpc.Server
	mailDialer *gomail.Dialer
	mailChan   chan *gomail.Message
	smsChan    chan *smsMessage

	captchaLen int
}

// NewIDP returns a IDProvider,
// If some error occur, the application just exit with status 1
func NewIDP() *IDP {
	flogging.LoggingInit("idp")
	idp := new(IDP)

	// init snowflake
	idpLogger.Info("IDP init snowflake")
	startTimeFmt := viper.GetString("snowflake.startTime")
	if startTimeFmt == "" {
		startTimeFmt = default_snowflake_start_time_fmt
	}
	startTime, err := time.Parse("2006/01/02 15:04:05", startTimeFmt)
	if err != nil {
		idpLogger.Fatalf("parse snowflake start time string err: %v", err)
	}

	machineID := uint64(viper.GetInt("snowflake.machineID"))
	if machineID < 0 {
		idpLogger.Fatal("idprovider must set machineID")
	}
	idp.sf = snowflake.NewSnowflake(&snowflake.Settings{
		StartTime: startTime,
		MachineID: func() (uint64, error) {
			return machineID, nil
		},
		CheckMachineID: func(machineID uint64) bool {
			return uint64(viper.GetInt("snowflake.machineID")) == machineID
		},
	})

	if idp.sf == nil {
		idpLogger.Fatal("singleton snowflake init error, exit.")
	}

	// init db
	idpLogger.Info("IDP init db")
	var dbAdapter db.DBAdapter
	switch viper.GetString("db.driver") {
	case "sqlite3":
		dbAdapter = db.NewSQLiteDB()
	}
	if err := dbAdapter.InitDB(); err != nil {
		idpLogger.Fatalf("IDP init db error: %v", err)
	}
	idp.dbAdapter = dbAdapter

	// init gomail
	idpLogger.Info("IDP init gomail")
	messagePool := viper.GetInt("mail.messagePool")
	if messagePool <= 0 {
		messagePool = 10
	}
	idp.mailChan = make(chan *gomail.Message, messagePool)
	idp.mailDialer = gomail.NewDialer(viper.GetString("mail.host"), viper.GetInt("mail.port"), viper.GetString("mail.user"), viper.GetString("mail.pass"))

	// init sms
	idpLogger.Info("IDP init sms")
	smsPool := viper.GetInt("sms.messagePool")
	if smsPool <= 0 {
		smsPool = 100
	}
	idp.smsChan = make(chan *smsMessage, smsPool)

	// init captcha
	idpLogger.Info("IDP init captcha")
	idp.captchaLen = viper.GetInt("captcha.length")
	collectNum := viper.GetInt("captcha.collectNum")
	expiration := viper.GetDuration("captcha.expiration")
	captcha.SetCustomStore(captcha.NewMemoryStore(collectNum, expiration))

	// populate users
	idp.populateUsersTable()
	// populate devices
	idp.populateUserDevicesTable()

	return idp
}

// populate users
func (idp *IDP) populateUsersTable() {
	for nick, user := range viper.GetStringMapString("db.users") {
		vals := strings.Split(user, ";")
		email := vals[0]
		pass := crypto.MD5Hash(vals[1])
		userType, err := strconv.Atoi(vals[2])
		if err != nil {
			idpLogger.Errorf("convert userType string 2 int return error: %v", err)
			continue
		}

		if idp.dbAdapter.IsUserExist(email) {
			continue
		}

		idpLogger.Debugf("populate user: %v", vals)
		if _, err := idp.registerUser(&pb.User{
			Email:    email,
			Pass:     pass,
			Nick:     nick,
			UserType: pb.UserType(userType),
			Wpub:     bytes.NewBufferString(vals[3]).Bytes(),
		}); err != nil {
			idpLogger.Errorf("pre register user return error: %v", err)
			continue
		}
	}
}

// populate devices
func (idp *IDP) populateUserDevicesTable() {
	for alias, device := range viper.GetStringMapString("db.devices") {
		vals := strings.Split(device, ";")
		userEmail := vals[0]
		os := vals[1]
		deviceFor, err := strconv.Atoi(vals[2])
		if err != nil {
			continue
		}
		mac := ""
		if len(vals) >= 4 {
			mac = vals[3]
		}
		wpub := ""
		if len(vals) >= 5 {
			wpub = vals[4]
		}

		user, err := idp.dbAdapter.FetchUserByEmail(userEmail)
		if err != nil {
			continue
		}

		if dev, err := idp.dbAdapter.FetchUserDeviceByAlias(user.UserID, alias); err == nil && dev != nil && dev.DeviceID != "" {
			idpLogger.Warningf("user[%s] already has a device using alias: %s", user.UserID, alias)
			continue
		}

		idpLogger.Debugf("populateUserDevice: %v", vals)
		if _, err := idp.bindUserDevice(&pb.Device{
			UserID: user.UserID,
			Os:     os,
			For:    pb.DeviceFor(deviceFor),
			Mac:    mac,
			Alias:  alias,
			Wpub:   bytes.NewBufferString(wpub).Bytes(),
		}); err != nil {
			idpLogger.Errorf("pre bind user device return error: %v", err)
			continue
		}
	}
}

// Start starts idprovider service
func (idp *IDP) Start(srv *grpc.Server) {
	idpLogger.Info("Starting IDProvider...")

	go idp.asyncSendEmail()
	go idp.asyncSendSMS()
	idp.startIDPP(srv)
	idp.startIDPA(srv)
	idp.gRPCServer = srv

	idpLogger.Info("IDProvider started.")
}

func (idp *IDP) startIDPP(srv *grpc.Server) {
	pb.RegisterIDPPServer(srv, &IDPP{idp})
	flogging.LoggingInit("idpp")
	idpLogger.Info("IDP PUBLIC gRPC API server started")
}

func (idp *IDP) startIDPA(srv *grpc.Server) {
	pb.RegisterIDPAServer(srv, &IDPA{idp})
	flogging.LoggingInit("idpa")
	idpLogger.Info("IDP ADMIN gRPC API server started")
}

func (idp *IDP) Stop() error {
	idpLogger.Info("Stopping IDP services...")
	if idp.gRPCServer != nil {
		idp.gRPCServer.Stop()
	}

	if idp.dbAdapter != nil {
		if err := idp.dbAdapter.Close(); err != nil {
			idpLogger.Errorf("IDP Error stoping services: %s", err)
			return err
		}
	}

	// close mail chan
	close(idp.mailChan)
	for {
		mailLen := len(idp.mailChan)
		if mailLen == 0 {
			break
		}

		idpLogger.Infof("IDP mail channel isn't empty: %d, waiting...", mailLen)
		time.Sleep(time.Second)
	}

	// close sms chan
	close(idp.smsChan)
	for {
		smsLen := len(idp.smsChan)
		if smsLen == 0 {
			break
		}

		idpLogger.Infof("IDP sms channel isn't empty: %d, waiting...", smsLen)
	}

	idpLogger.Info("IDP stopped")

	return nil
}

// bcrypt md5(password)
func (idp *IDP) encodePass(pass string) string {
	bpass, err := bcrypt.GenerateFromPassword([]byte(crypto.MD5Hash(pass)), bcrypt.DefaultCost)
	if err != nil {
		idpLogger.Errorf("bcrypt.GenerateFromPassword() error: %v", err)
		return ""
	}

	return bytes.NewBuffer(bpass).String()
}

// compare bcrypt md5(password)
// return true if password is right, otherwise return false.
func (idp *IDP) verifyPass(pass string, hash string) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(crypto.MD5Hash(pass))); err != nil {
		return false
	}

	return true
}

// register a user into db
func (idp *IDP) registerUser(user *pb.User) (*pb.User, error) {
	user.UserID = uuid.NewV1().String()
	user.Pass = idp.encodePass(user.Pass)

	return idp.dbAdapter.RegisterUser(user)
}

// bind a device 2 a user
func (idp *IDP) bindUserDevice(dev *pb.Device) (*pb.Device, error) {
	nextId, err := idp.sf.NextID(int64(dev.For), int64(viper.GetInt("snowflake.areaCode")))
	if err != nil {
		idpLogger.Errorf("generate device id error: %v", err)
		return nil, err
	}

	dev.DeviceID = strconv.FormatUint(nextId, 16)
	return idp.dbAdapter.BindUserDevice(dev)
}

// fetch device using device id
func (idp *IDP) fetchDeviceByID(deviceID string) (*pb.Device, error) {
	return idp.dbAdapter.FetchDeviceByID(deviceID)
}
