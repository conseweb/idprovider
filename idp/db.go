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
	"database/sql"
	"errors"
	pb "github.com/conseweb/common/protos"
	"github.com/hyperledger/fabric/flogging"
	_ "github.com/mattn/go-sqlite3"
	"github.com/op/go-logging"
	"github.com/spf13/viper"
	"os"
	"path/filepath"
	"fmt"
)

var (
	dbLogger = logging.MustGetLogger("db")
)

type dbAdapter interface {
	initDB() error
	isUserExist(username string) bool
	registerUser(user *pb.User) (*pb.User, error)
	fetchUserByID(userID string) (*pb.User, error)
	fetchUserByEmail(email string) (*pb.User, error)
	fetchUserDevicesByMac(userID, mac string) ([]*pb.Device, error)
	fetchUserDeviceByAlias(userID, alias string) (*pb.Device, error)
	bindUserDevice(dev *pb.Device) (*pb.Device, error)
	fetchDeviceByID(deviceID string) (*pb.Device, error)
	close() error
}

type sqliteImpl struct {
	db     *sql.DB
	dbpath string
}

func newSQLiteDB() dbAdapter {
	flogging.LoggingInit("db")

	dbLogger.Info("using sqlite3 as dbAdapter...")
	dbPath := viper.GetString("db.sqlite3.dbpath")
	if _, err := os.Stat(dbPath); err != nil {
		dbLogger.Info("Fresh start; creating databases")
		if err := os.MkdirAll(dbPath, 0755); err != nil {
			dbLogger.Fatal(err)
		}
	}

	db, err := sql.Open("sqlite3", filepath.Join(dbPath, "idprovider.db"))
	if err != nil {
		dbLogger.Fatalf("open sqlite3 db error: %v", err)
	}

	if err := db.Ping(); err != nil {
		dbLogger.Fatalf("ping sqlite3 db error: %v", err)
	}

	db.SetMaxIdleConns(viper.GetInt("db.maxIdle"))
	db.SetMaxOpenConns(viper.GetInt("db.maxOpen"))

	return &sqliteImpl{
		db:     db,
		dbpath: dbPath,
	}
}

func (s *sqliteImpl) initDB() error {
	// create table users
	dbLogger.Info("sqlite3 create users table")
	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			row INTEGER PRIMARY KEY,
			id VARCHAR(32),
			email VARCHAR(32),
			mobile VARCHAR(20),
			nick VARCHAR(20),
			pass VARCHAR(255),
			type INTEGER,
			wpub BLOB,
			spub BLOB
		)
	`); err != nil {
		return err
	}

	// create table devices
	dbLogger.Info("sqlite3 create devices table")
	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS devices (
			row INTEGER PRIMARY KEY,
			id VARCHAR(32),
			userID VARCHAR(32),
			os VARCHAR(32),
			for INTEGER,
			mac VARCHAR(64),
			alias VARCHAR(64),
			wpub BLOB,
			spub BLOB
		)
	`); err != nil {
		return err
	}

	return nil
}

func (s *sqliteImpl) isUserExist(username string) bool {
	if username == "" {
		return false
	}

	var row int
	if s.db.QueryRow("SELECT row FROM users WHERE email = ? OR mobile = ?", username, username).Scan(&row); row > 0 {
		return true
	}

	return false
}

func (s *sqliteImpl) registerUser(user *pb.User) (*pb.User, error) {
	// check whether user pub key already been token.
	var row int
	if err := s.db.QueryRow("SELECT row FROM users WHERE wpub = ?", user.Wpub).Scan(&row); err == nil && row > 0 {
		return nil, fmt.Errorf("user wallet public key already been token: %s", user.Wpub)
	}

	if _, err := s.db.Exec("INSERT INTO users(id, email, mobile, nick, pass, type, wpub, spub) VALUES(?, ?, ?, ?, ?, ?, ?, ?)", user.UserID, user.Email, user.Mobile, user.Nick, user.Pass, user.UserType, user.Wpub, user.Spub); err != nil {
		dbLogger.Errorf("insert into user db error: %v", err)
		return nil, err
	}

	dbLogger.Debugf("user registered: %+v", user)
	return user, nil
}

func (s *sqliteImpl) fetchUserByID(userID string) (*pb.User, error) {
	if userID == "" {
		return nil, errors.New("invalid params")
	}

	u := &pb.User{}
	if err := s.db.QueryRow("SELECT id, email, mobile, nick, pass, type, wpub, spub FROM users WHERE id = ?", userID).Scan(&u.UserID, &u.Email, &u.Mobile, &u.Nick, &u.Pass, &u.UserType, &u.Wpub, &u.Spub); err != nil {
		return nil, err
	}

	dbLogger.Debugf("user fetched by id: %+v", u)
	return u, nil
}

func (s *sqliteImpl) fetchUserByEmail(email string) (*pb.User, error) {
	if email == "" {
		return nil, errors.New("invalid params")
	}

	u := &pb.User{}
	if err := s.db.QueryRow("SELECT id, email, mobile, nick, pass, type, wpub, spub FROM users WHERE email = ?", email).Scan(&u.UserID, &u.Email, &u.Mobile, &u.Nick, &u.Pass, &u.UserType, &u.Wpub, &u.Spub); err != nil {
		return nil, err
	}

	dbLogger.Debugf("user fetched by email: %+v", u)
	return u, nil
}

func (s *sqliteImpl) fetchUserDevicesByMac(userID, mac string) ([]*pb.Device, error) {
	if userID == "" || mac == "" {
		return nil, errors.New("invalid params")
	}

	rows, err := s.db.Query("SELECT id, userID, os, for, mac, alias, wpub, spub From devices WHERE userID = ? AND mac = ?", userID, mac)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	devices := make([]*pb.Device, 0)
	for rows.Next() {
		device := &pb.Device{}
		err := rows.Scan(&device.DeviceID, &device.UserID, &device.Os, &device.For, &device.Mac, &device.Alias, &device.Wpub, &device.Spub)
		if err != nil {
			continue
		}

		devices = append(devices, device)
	}

	dbLogger.Debugf("devices fetched by mac: %+v", devices)
	return devices, nil
}

func (s *sqliteImpl) fetchUserDeviceByAlias(userID, alias string) (*pb.Device, error) {
	if userID == "" || alias == "" {
		return nil, errors.New("invalid params")
	}

	device := &pb.Device{}
	if err := s.db.QueryRow("SELECT id, userID, os, for, mac, alias, wpub, spub FROM devices WHERE userID=? AND alias = ?", userID, alias).Scan(&device.DeviceID, &device.UserID, &device.Os, &device.For, &device.Mac, &device.Alias, &device.Wpub, &device.Spub); err != nil {
		dbLogger.Debugf("fetching user device by alias return error: %v", err)
		return nil, err
	}

	dbLogger.Debugf("fetching user device by alias: %+v", device)
	return device, nil
}

func (s *sqliteImpl) bindUserDevice(dev *pb.Device) (*pb.Device, error) {
	if dev == nil || dev.UserID == "" || dev.DeviceID == "" || dev.Mac == "" {
		return nil, errors.New("invalid params")
	}

	// check whether device pub key has already been token
	var row int
	if err := s.db.QueryRow("SELECT row FROM devices WHERE wpub = ?", dev.Wpub).Scan(&row); err == nil && row > 0 {
		return nil, errors.New("device public key has already been token.")
	}

	if _, err := s.db.Exec("INSERT INTO devices(id, userID, os, for, mac, alias, wpub, spub) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", dev.DeviceID, dev.UserID, dev.Os, dev.For, dev.Mac, dev.Alias, dev.Wpub, dev.Spub); err != nil {
		dbLogger.Errorf("bind user device ret error: %v", err)
		return nil, err
	}

	dbLogger.Debugf("user[%s] bind device: %+v", dev.UserID, dev)
	return dev, nil
}

func (s *sqliteImpl) fetchDeviceByID(deviceID string) (*pb.Device, error) {
	if deviceID == "" {
		return nil, errors.New("invalid params")
	}
	device := &pb.Device{}

	if err := s.db.QueryRow("SELECT id, userID, os, for, mac, alias, wpub, spub FROM devices WHERE id = ?", deviceID).Scan(&device.DeviceID, &device.UserID, &device.Os, &device.For, &device.Mac, &device.Alias, &device.Wpub, &device.Spub); err != nil {
		dbLogger.Warningf("using deviceID: %s fetching device return error: %v", deviceID, err)
		return nil, err
	}

	return device, nil
}

func (s *sqliteImpl) close() error {
	return s.db.Close()
}
