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
package idp

import (
	"bytes"
	"errors"
	"github.com/conseweb/common/captcha"
	pb "github.com/conseweb/common/protos"
	"github.com/conseweb/common/snowflake"
	"github.com/hyperledger/fabric/flogging"
	"github.com/op/go-logging"
	"github.com/satori/go.uuid"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"gopkg.in/gomail.v2"
	"html/template"
	"strconv"
	"strings"
	"time"
)

const (
	default_snowflake_start_time_fmt = "2016/08/16 16:35:00"
)

var (
	idpLogger = logging.MustGetLogger("idp")
)

// IDP holds a snowflake id generator and a db handler
type IDP struct {
	db         dbAdapter
	sf         *snowflake.Snowflake
	gRPCServer *grpc.Server
	mailDialer *gomail.Dialer
	mailChan   chan *gomail.Message
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
	var db dbAdapter
	switch viper.GetString("db.driver") {
	case "sqlite3":
		db = newSQLiteDB()
	}
	if err := db.initDB(); err != nil {
		idpLogger.Fatalf("IDP init db error: %v", err)
	}
	idp.db = db

	// init gomail
	idpLogger.Info("IDP init gomail")
	messagePool := viper.GetInt("mail.messagePool")
	if messagePool <= 0 {
		messagePool = 10
	}
	idp.mailChan = make(chan *gomail.Message, messagePool)
	idp.mailDialer = gomail.NewDialer(viper.GetString("mail.host"), viper.GetInt("mail.port"), viper.GetString("mail.user"), viper.GetString("mail.pass"))

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
		pass := encodeMD5(vals[1])
		userType, err := strconv.Atoi(vals[2])
		if err != nil {
			idpLogger.Errorf("convert userType string 2 int return error: %v", err)
			continue
		}

		if idp.isUserExist(email) {
			continue
		}

		if _, err := idp.registerUser(&pb.User{
			Email:    email,
			Pass:     pass,
			Nick:     nick,
			UserType: pb.UserType(userType),
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

		user, err := idp.fetchUserByEmail(userEmail)
		if err != nil {
			continue
		}

		if dev, err := idp.fetchUserDeviceByAlias(user.UserID, alias); err == nil && dev != nil && dev.DeviceID != "" {
			idpLogger.Warningf("user[%s] already has a device using alias: %s", user.UserID, alias)
			continue
		}

		if _, err := idp.bindUserDevice(&pb.Device{
			UserID: user.UserID,
			Os:     os,
			For:    pb.DeviceFor(deviceFor),
			Mac:    mac,
			Alias:  alias,
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
		idp.gRPCServer.GracefulStop()
	}

	if idp.db != nil {
		if err := idp.db.close(); err != nil {
			idpLogger.Errorf("IDP Error stoping services: %s", err)
			return err
		}
	}

	close(idp.mailChan)
	for {
		mailLen := len(idp.mailChan)
		if mailLen == 0 {
			break
		}

		idpLogger.Infof("IDP mail chanel isn't empty: %d, waitting...", mailLen)
		time.Sleep(time.Second)
	}

	idpLogger.Info("IDP stopped")

	return nil
}

func (idp *IDP) sendCaptcha(signUpType pb.SignUpType, signUp string) error {
	var err error
	switch signUpType {
	case pb.SignUpType_EMAIL:
		err = idp.sendCaptchaEmail(signUp)
	case pb.SignUpType_MOBILE:
		err = idp.sendCaptchaSMS(signUp)
	}

	if err != nil {
		idpLogger.Errorf("sending captcha return error: %v", err)
	}

	return err
}

// verify captcha
func (idp *IDP) verifyCaptcha(signup, capt string) bool {
	idpLogger.Debugf("IDP verify captcha: [%s, %s]", signup, capt)
	return captcha.VerifyString(signup, capt)
}

// check the db whether the username is already has one.
// return true if has,or return false
func (idp *IDP) isUserExist(username string) bool {
	return idp.db.isUserExist(username)
}

// bcrypt md5(password)
func (idp *IDP) encodePass(pass string) string {
	bpass, err := bcrypt.GenerateFromPassword([]byte(encodeMD5(pass)), bcrypt.DefaultCost)
	if err != nil {
		idpLogger.Errorf("bcrypt.GenerateFromPassword() error: %v", err)
		return ""
	}

	return bytes.NewBuffer(bpass).String()
}

// compare bcrypt md5(password)
// return true if password is right, otherwise return false.
func (idp *IDP) verifyPass(pass string, hash string) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(encodeMD5(pass))); err != nil {
		return false
	}

	return true
}

// register a user into db
func (idp *IDP) registerUser(user *pb.User) (*pb.User, error) {
	user.UserID = uuid.NewV1().String()
	user.Pass = idp.encodePass(user.Pass)
	return idp.db.registerUser(user)
}

// fetch user though id
func (idp *IDP) fetchUserByID(userID string) (*pb.User, error) {
	if userID == "" {
		return nil, errors.New("invalid params")
	}
	return idp.db.fetchUserByID(userID)
}

// fetch user by email
func (idp *IDP) fetchUserByEmail(email string) (*pb.User, error) {
	if email == "" {
		return nil, errors.New("invalid params")
	}

	return idp.db.fetchUserByEmail(email)
}

// fetch user devices using mac address,
// we support one user can only have different mac address device
func (idp *IDP) fetchUserDevicesByMac(userID, mac string) ([]*pb.Device, error) {
	if userID == "" || mac == "" {
		return nil, errors.New("invalid params")
	}

	return idp.db.fetchUserDevicesByMac(userID, mac)
}

// fetch user device using alias
// one user can have different alias devices
func (idp *IDP) fetchUserDeviceByAlias(userID, alias string) (*pb.Device, error) {
	if userID == "" || alias == "" {
		return nil, errors.New("invalid params")
	}

	return idp.db.fetchUserDeviceByAlias(userID, alias)
}

// bind a device 2 a user
func (idp *IDP) bindUserDevice(dev *pb.Device) (*pb.Device, error) {
	nextId, err := idp.sf.NextID(int64(dev.For), int64(viper.GetInt("snowflake.areaCode")))
	if err != nil {
		idpLogger.Errorf("generate device id error: %v", err)
		return nil, err
	}

	dev.DeviceID = strconv.FormatUint(nextId, 16)
	return idp.db.bindUserDevice(dev)
}

// fetch device using device id
func (idp *IDP) fetchDeviceByID(deviceID string) (*pb.Device, error) {
	return idp.db.fetchDeviceByID(deviceID)
}

var (
	captchaHtmlTpl = `
		<html><body><p>captcha:<span>{{.captcha}}</span></p></body></html>
	`
)

func (idp *IDP) sendCaptchaEmail(email string) error {
	// only for test, if email contains '@example', just return nil
	if strings.Contains(email, "@example") {
		return nil
	}

	capt := captcha.NewLen(email, idp.captchaLen)
	idpLogger.Debugf("IDP generate a new captcha:[%s:%v]", email, capt)

	tmpl, err := template.New(email).Parse(captchaHtmlTpl)
	if err != nil {
		idpLogger.Errorf("parese captcha html template error: %v", err)
		return err
	}

	writer := bytes.NewBufferString("")
	err = tmpl.Execute(writer, map[string]interface{}{
		"captcha": capt,
	})
	if err != nil {
		idpLogger.Errorf("execute html template return error: %v", err)
		return err
	}

	m := gomail.NewMessage()
	m.SetHeader("From", viper.GetString("mail.user"))
	m.SetHeader("To", email)
	m.SetHeader("Subject", viper.GetString("mail.captchaEmailSubject"))
	m.SetBody("text/html", writer.String())

	idp.mailChan <- m

	return nil
}

func (idp *IDP) sendCaptchaSMS(mobile string) error {
	return nil
}

func (idp *IDP) asyncSendEmail() {
	idpLogger.Info("IDP mail sender started")

	var s gomail.SendCloser
	var err error
	ticker := time.NewTicker(time.Second * 30)
	open := false

	for {
		select {
		case m, ok := <-idp.mailChan:
			if !ok {
				continue
			}

			if !open {
				if s, err = idp.mailDialer.Dial(); err != nil {
					idpLogger.Errorf("mail dialer dial error: %v", err)
					continue
				}

				open = true
			}

			if err = gomail.Send(s, m); err != nil {
				idpLogger.Errorf("mail send error: %v", err)
				continue
			}

			idpLogger.Debugf("sending an email to %v", m.GetHeader("To"))
		case <-ticker.C:
			if open {
				if err = s.Close(); err != nil {
					idpLogger.Errorf("close mail sender error: %v", err)
				}

				open = false
			}
		}
	}
}
