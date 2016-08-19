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
	pb "github.com/conseweb/idprovider/protos"
	"github.com/hyperledger/fabric/flogging"
	_ "github.com/mattn/go-sqlite3"
	"github.com/op/go-logging"
	"github.com/spf13/viper"
)

var (
	dbLogger = logging.MustGetLogger("db")
)

type dbAdapter interface {
	initDB() error
	isUserExist(username string) bool
	registerUser(user *pb.User) (*pb.User, error)
	close() error
}

type sqliteImpl struct {
	db *sql.DB
}

func newSQLiteDB(dbFile string) dbAdapter {
	flogging.LoggingInit("db")
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		dbLogger.Fatalf("open sqlite3 db error: %v", err)
	}

	if err := db.Ping(); err != nil {
		dbLogger.Fatalf("ping sqlite3 db error: %v", err)
	}

	db.SetMaxIdleConns(viper.GetInt("db.maxIdle"))
	db.SetMaxOpenConns(viper.GetInt("db.maxOpen"))

	dbLogger.Infof("using sqlite3 db[%s] as dbAdapter...", dbFile)

	return &sqliteImpl{
		db: db,
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

	return nil
}

func (s *sqliteImpl) isUserExist(username string) bool {
	return false
}

func (s *sqliteImpl) registerUser(user *pb.User) (*pb.User, error) {
	return user, nil
}

func (s *sqliteImpl) close() error {
	return s.db.Close()
}
