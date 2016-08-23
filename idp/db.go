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
	pb "github.com/conseweb/idprovider/protos"
	"github.com/hyperledger/fabric/flogging"
	_ "github.com/mattn/go-sqlite3"
	"github.com/op/go-logging"
	"github.com/spf13/viper"
	"os"
	"path/filepath"
)

var (
	dbLogger = logging.MustGetLogger("db")
)

type dbAdapter interface {
	initDB() error
	isUserExist(username string) bool
	registerUser(user *pb.User) (*pb.User, error)
	fetchUserByID(userID string) (*pb.User, error)
	fetchUserDevicesByMac(userID, mac string) ([]*pb.Device, error)
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
			pass VARCHAR(255)
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
			osType INTEGER,
			osVersion VARCHAR(32),
			deviceFor INTEGER,
			mac VARCHAR(64)
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
	if s.db.QueryRow("SELECT row FROM users WHERE email = ? or mobile = ?", username, username).Scan(&row); row > 0 {
		return true
	}

	return false
}

func (s *sqliteImpl) registerUser(user *pb.User) (*pb.User, error) {
	if _, err := s.db.Exec("INSERT INTO users(id, email, mobile, nick, pass) VALUES(?, ?, ?, ?, ?)", user.UserID, user.Email, user.Mobile, user.Nick, user.Pass); err != nil {
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
	if err := s.db.QueryRow("SELECT id, email, mobile, nick, pass FROM users WHERE id = ?", userID).Scan(&u.UserID, &u.Email, &u.Mobile, &u.Nick, &u.Pass); err != nil {
		return nil, err
	}

	dbLogger.Debugf("user fetched by id: %+v", u)
	return u, nil
}

func (s *sqliteImpl) fetchUserDevicesByMac(userID, mac string) ([]*pb.Device, error) {
	if userID == "" || mac == "" {
		return nil, errors.New("invalid params")
	}

	rows, err := s.db.Query("SELECT id, userID, osType, osVersion, deviceFor, mac From devices WHERE userID = ? and mac = ?", userID, mac)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	devices := make([]*pb.Device, 0)
	for rows.Next() {
		device := &pb.Device{}
		err := rows.Scan(&device.DeviceID, &device.UserID, &device.Os, &device.OsVersion, &device.For, &device.Mac)
		if err != nil {
			continue
		}

		devices = append(devices, device)
	}

	dbLogger.Debugf("devices fetched by mac: %+v", devices)
	return devices, nil
}

func (s *sqliteImpl) bindUserDevice(dev *pb.Device) (*pb.Device, error) {
	if dev == nil || dev.UserID == "" || dev.DeviceID == "" || dev.Mac == "" {
		return nil, errors.New("invalid params")
	}

	if _, err := s.db.Exec("INSERT INTO devices (id, userID, osType, osVersion, deviceFor, mac) VALUES (?, ?, ?, ?, ?, ?)", dev.DeviceID, dev.UserID, dev.Os, dev.OsVersion, dev.For, dev.Mac); err != nil {
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

	if err := s.db.QueryRow("SELECT id, userID, osType, osVersion, deviceFor, mac FROM devices WHERE id = ?", deviceID).Scan(&device.DeviceID, &device.UserID, &device.Os, &device.OsVersion, &device.For, &device.Mac); err != nil {
		dbLogger.Warningf("using deviceID: %s fetching device return error: %v", deviceID, err)
		return nil, err
	}

	return device, nil
}

func (s *sqliteImpl) close() error {
	return s.db.Close()
}
