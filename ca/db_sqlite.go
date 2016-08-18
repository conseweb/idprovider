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
package ca

import (
	"database/sql"
	"github.com/hyperledger/fabric/flogging"
	_ "github.com/mattn/go-sqlite3"
	"github.com/op/go-logging"
	"github.com/spf13/viper"
)

const (
	sqlite_create_cert_table = `
		CREATE TABLE IF NOT EXISTS certificates (
			row INTEGER PRIMARY KEY,
			id VARCHAR(64),
			timestamp INTEGER,
			usage INTEGER,
			cert BLOB,
			hash BLOB,
			kdfkey BLOB
		)
	`
	sqlite_insert_cert                    = `INSERT INTO certificates(id, timestamp, usage, cert, hash, kdfkey) VALUES (?, ?, ?, ?, ?, ?)`
	sqlite_delete_cert_by_id              = `DELETE FROM certificates Where id=?`
	sqlite_select_cert_by_id_ts           = `SELECT cert FROM certificates WHERE id=? AND timestamp=?`
	sqlite_select_cert_by_id_usage        = `SELECT cert FROM certificates WHERE id=? AND usage=?`
	sqlite_select_cert_key_by_id_ts       = `SELECT cert, kdfkey FROM certificates WHERE id=? AND timestamp=? ORDER BY usage`
	sqlite_select_cert_key_by_id          = `SELECT cert, kdfkey FROM certificates WHERE id=?`
	sqlite_select_cert_key_ts_by_id_ts_ba = `SELECT cert, kdfKey, timestamp FROM certificates WHERE id=? AND timestamp BETWEEN ? AND ? ORDER BY timestamp`
	sqlite_select_cert_by_hash            = `SELECT cert FROM certificates WHERE hash=?`

	sqlite_create_user_table = `
		CREATE TABLE IF NOT EXISTS users (
			row INTEGER PRIMARY KEY,
			id VARCHAR(64),
			enrollmentId VARCHAR(100),
			role INTEGER,
			metadata VARCHAR(255),
			token BLOB,
			state INTEGER,
			key BLOB
		)
	`
	sqlite_select_user_row_by_id      = `SELECT row FROM users WHERE id = ?`
	sqlite_select_user_metadata_by_id = `SELECT metadata FROM users WHERE id = ?`
	sqlite_select_user_by_id          = `SELECT role, token, state, key, enrollmentId FROM users WHERE id=?`
	sqlite_insert_user                = `INSERT INTO users (id, enrollmentId, token, role, metadata, state) VALUES (?, ?, ?, ?, ?, ?)`
	sqlite_update_user_key_by_id      = `UPDATE users SET token=?, state=?, key=? WHERE id=?`
	sqlite_update_user_state_by_id    = `UPDATE users SET state=? WHERE id=?`
	sqlite_delete_user_by_row         = `DELETE FROM users WHERE row=?`
	sqlite_select_users_by_role       = `SELECT id, role FROM users WHERE role&?!=0`
	sqlite_select_user_role_by_id     = `SELECT role FROM users WHERE id=?`

	sqlite_create_attribute_table = `
		CREATE TABLE IF NOT EXISTS attributes (
			row INTEGER PRIMARY KEY,
			id VARCHAR(64),
			affiliation VARCHAR(64),
			attributeName VARCHAR(64),
			validFrom DATETIME,
			validTo DATETIME,
			attributeValue BLOB
		)
	`
	sqlite_count_attribute_by_id_name  = `SELECT count(row) AS cant FROM attributes WHERE id=? AND affiliation =? AND attributeName =?`
	sqlite_select_attribute_by_id_name = `SELECT attributeName, attributeValue, validFrom, validTo AS cant FROM Attributes WHERE id=? AND affiliation =? AND attributeName =?`
	sqlite_update_attribute_by_id_name = `UPDATE attributes SET validFrom = ?, validTo = ?,  attributeValue = ? WHERE  id=? AND affiliation =? AND attributeName =? AND validFrom < ?`
	sqlite_insert_attr                 = `INSERT INTO attributes (validFrom , validTo,  attributeValue, id, affiliation, attributeName) VALUES (?,?,?,?,?,?)`

	sqlite_create_affiliationGroups_table = `
		CREATE TABLE IF NOT EXISTS affiliationGroups (
			row INTEGER PRIMARY KEY,
			name VARCHAR(64),
			parent INTEGER,
			FOREIGN KEY(parent) REFERENCES affiliationGroups(row)
		)
	`
	sqlite_count_affiliationGroups_by_name      = `SELECT count(row) FROM affiliationGroups WHERE name=?`
	sqlite_select_affiliationGroups_row_by_name = `SELECT row FROM affiliationGroups WHERE name=?`
	sqlite_insert_affiliationGroups             = `INSERT INTO affiliationGroups (name, parent) VALUES (?, ?)`
	sqlite_select_affiliationGroups             = `SELECT row, name, parent FROM affiliationGroups`

	sqlite_create_tcertificate_table = `
		CREATE TABLE IF NOT EXISTS TCertificateSets (
			row INTEGER PRIMARY KEY,
			enrollmentID VARCHAR(64),
			timestamp INTEGER,
			nonce BLOB,
			kdfkey BLOB
		)
	`
	sqlite_insert_tcertificate = `INSERT INTO TCertificateSets (enrollmentID, timestamp, nonce, kdfkey) VALUES (?, ?, ?, ?)`
	sqlite_select_tcertificate_by_enrollID = `SELECT enrollmentID, timestamp, nonce, kdfkey FROM TCertificateSets WHERE enrollmentID=?`
)

var (
	dbLogger = logging.MustGetLogger("db")
)

func init() {
	flogging.LoggingInit("db")
}

func sqliteDB(dbFile string, name string) *sql.DB {
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		dbLogger.Panic(err)
	}

	if err := db.Ping(); err != nil {
		dbLogger.Panic(err)
	}

	db.SetMaxOpenConns(viper.GetInt("idprovider.ca.db.maxOpen"))
	db.SetMaxIdleConns(viper.GetInt("idprovider.ca.db.maxIdle"))

	if _, err := db.Exec(sqlite_create_cert_table); err != nil {
		dbLogger.Panic(err)
	}

	if _, err := db.Exec(sqlite_create_user_table); err != nil {
		dbLogger.Panic(err)
	}

	if _, err := db.Exec(sqlite_create_affiliationGroups_table); err != nil {
		dbLogger.Panic(err)
	}

	if name == "aca" {
		if _, err := db.Exec(sqlite_create_attribute_table); err != nil {
			dbLogger.Panic(err)
		}
	}

	if name == "tca" {
		if _, err := db.Exec(sqlite_create_tcertificate_table); err != nil {
			dbLogger.Panic(err)
		}
	}

	return db
}
