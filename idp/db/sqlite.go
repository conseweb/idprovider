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
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"errors"
	pb "github.com/conseweb/common/protos"
	"github.com/hyperledger/fabric/flogging"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

type SqliteImpl struct {
	db     *sql.DB
	dbpath string
}

// NewSQLiteDB return a sqlite db adapter
func NewSQLiteDB() DBAdapter {
	flogging.LoggingInit("idp/db")

	DBLogger.Info("using sqlite3 as dbAdapter...")
	dbPath := viper.GetString("db.sqlite3.dbpath")
	if _, err := os.Stat(dbPath); err != nil {
		DBLogger.Info("Fresh start; creating databases")
		if err := os.MkdirAll(dbPath, 0755); err != nil {
			DBLogger.Fatal(err)
		}
	}

	db, err := sql.Open("sqlite3", filepath.Join(dbPath, "idprovider.db"))
	if err != nil {
		DBLogger.Fatalf("open sqlite3 db error: %v", err)
	}

	if err := db.Ping(); err != nil {
		DBLogger.Fatalf("ping sqlite3 db error: %v", err)
	}

	db.SetMaxIdleConns(viper.GetInt("db.maxIdle"))
	db.SetMaxOpenConns(viper.GetInt("db.maxOpen"))

	return &SqliteImpl{
		db:     db,
		dbpath: dbPath,
	}
}

func (s *SqliteImpl) InitDB() error {
	// create table users
	DBLogger.Info("sqlite3 create users table")
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
	DBLogger.Info("sqlite3 create devices table")
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

func (s *SqliteImpl) IsUserExist(username string) bool {
	if username == "" {
		return false
	}

	var row int
	if s.db.QueryRow("SELECT row FROM users WHERE email = ? OR mobile = ?", username, username).Scan(&row); row > 0 {
		return true
	}

	return false
}

func (s *SqliteImpl) RegisterUser(user *pb.User) (*pb.User, error) {
	// check whether user pub key already been token.
	var row int
	if err := s.db.QueryRow("SELECT row FROM users WHERE wpub = ?", user.Wpub).Scan(&row); err == nil && row > 0 {
		return nil, fmt.Errorf("user wallet public key already been token: %s", user.Wpub)
	}

	if _, err := s.db.Exec("INSERT INTO users(id, email, mobile, nick, pass, type, wpub, spub) VALUES(?, ?, ?, ?, ?, ?, ?, ?)", user.UserID, user.Email, user.Mobile, user.Nick, user.Pass, user.UserType, user.Wpub, user.Spub); err != nil {
		DBLogger.Errorf("insert into user db error: %v", err)
		return nil, err
	}

	return user, nil
}

func (s *SqliteImpl) FetchUserByID(userID string) (*pb.User, error) {
	if userID == "" {
		return nil, ErrInvalidParams
	}

	u := &pb.User{}
	if err := s.db.QueryRow("SELECT id, email, mobile, nick, pass, type, wpub, spub FROM users WHERE id = ?", userID).Scan(&u.UserID, &u.Email, &u.Mobile, &u.Nick, &u.Pass, &u.UserType, &u.Wpub, &u.Spub); err != nil {
		return nil, err
	}

	DBLogger.Debugf("user fetched by id: %+v", u)
	return u, nil
}

func (s *SqliteImpl) FetchUserByEmail(email string) (*pb.User, error) {
	if email == "" {
		return nil, ErrInvalidParams
	}

	u := &pb.User{}
	if err := s.db.QueryRow("SELECT id, email, mobile, nick, pass, type, wpub, spub FROM users WHERE email = ?", email).Scan(&u.UserID, &u.Email, &u.Mobile, &u.Nick, &u.Pass, &u.UserType, &u.Wpub, &u.Spub); err != nil {
		DBLogger.Errorf("not found by email: %s", email)
		return nil, err
	}

	DBLogger.Debugf("user fetched by email: %+v", u)
	return u, nil
}

func (s *SqliteImpl) FetchUserByMobile(mobile string) (*pb.User, error) {
	if mobile == "" {
		return nil, ErrInvalidParams
	}

	u := &pb.User{}
	if err := s.db.QueryRow("SELECT id, email, mobile, nick, pass, type, wpub, spub FROM users WHERE mobile = ?", mobile).Scan(&u.UserID, &u.Email, &u.Mobile, &u.Nick, &u.Pass, &u.UserType, &u.Wpub, &u.Spub); err != nil {
		return nil, err
	}

	DBLogger.Debugf("user fetched by email: %+v", u)
	return u, nil
}

func (s *SqliteImpl) FetchUserDevices(userID string) ([]*pb.Device, error) {
	if userID == "" {
		return nil, ErrInvalidParams
	}

	rows, err := s.db.Query("SELECT id, userID, os, for, mac, alias, wpub, spub From devices WHERE userID = ?", userID)
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

	DBLogger.Debugf("devices fetched by userID: %+v", devices)
	return devices, nil
}

func (s *SqliteImpl) FetchUserDeviceByAlias(userID, alias string) (*pb.Device, error) {
	if userID == "" || alias == "" {
		return nil, ErrInvalidParams
	}

	device := &pb.Device{}
	if err := s.db.QueryRow("SELECT id, userID, os, for, mac, alias, wpub, spub FROM devices WHERE userID=? AND alias = ?", userID, alias).Scan(&device.DeviceID, &device.UserID, &device.Os, &device.For, &device.Mac, &device.Alias, &device.Wpub, &device.Spub); err != nil {
		DBLogger.Debugf("fetching user device by alias return error: %v", err)
		return nil, err
	}

	DBLogger.Debugf("fetching user device by alias: %+v", device)
	return device, nil
}

func (s *SqliteImpl) FetchUserDeviceByMac(userID, mac string) (*pb.Device, error) {
	if userID == "" || mac == "" {
		return nil, ErrInvalidParams
	}

	device := &pb.Device{}
	if err := s.db.QueryRow("SELECT id, userID, os, for, mac, alias, wpub, spub FROM devices WHERE userID=? AND mac = ?", userID, mac).Scan(&device.DeviceID, &device.UserID, &device.Os, &device.For, &device.Mac, &device.Alias, &device.Wpub, &device.Spub); err != nil {
		DBLogger.Debugf("fetching user device by mac return error: %v", err)
		return nil, err
	}

	DBLogger.Debugf("fetching user device by mac: %+v", device)
	return device, nil
}

func (s *SqliteImpl) BindUserDevice(dev *pb.Device) (*pb.Device, error) {
	if dev == nil || dev.UserID == "" || dev.DeviceID == "" || dev.Mac == "" {
		return nil, errors.New("invalid params")
	}

	// check whether device pub key has already been token
	var row int
	if err := s.db.QueryRow("SELECT row FROM devices WHERE wpub = ?", dev.Wpub).Scan(&row); err == nil && row > 0 {
		return nil, errors.New("device public key has already been token.")
	}

	if _, err := s.db.Exec("INSERT INTO devices(id, userID, os, for, mac, alias, wpub, spub) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", dev.DeviceID, dev.UserID, dev.Os, dev.For, dev.Mac, dev.Alias, dev.Wpub, dev.Spub); err != nil {
		DBLogger.Errorf("bind user device ret error: %v", err)
		return nil, err
	}

	DBLogger.Debugf("user[%s] bind device: %+v", dev.UserID, dev)
	return dev, nil
}

func (s *SqliteImpl) FetchDeviceByID(deviceID string) (*pb.Device, error) {
	if deviceID == "" {
		return nil, errors.New("invalid params")
	}
	device := &pb.Device{}

	if err := s.db.QueryRow("SELECT id, userID, os, for, mac, alias, wpub, spub FROM devices WHERE id = ?", deviceID).Scan(&device.DeviceID, &device.UserID, &device.Os, &device.For, &device.Mac, &device.Alias, &device.Wpub, &device.Spub); err != nil {
		DBLogger.Warningf("using deviceID: %s fetching device return error: %v", deviceID, err)
		return nil, err
	}

	return device, nil
}

func (s *SqliteImpl) Close() error {
	return s.db.Close()
}
