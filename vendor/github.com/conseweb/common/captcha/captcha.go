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
package captcha

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

const (
	// how long the captcha holds the digits
	CaptchaLen = 6

	// how many id/value pair can hold into store
	CollectNum = 100

	// how long id/value pair will get expired
	Expiration = time.Minute * 10
)

var (
	// store is a shared storage for the captcha
	store = NewMemoryStore(CollectNum, Expiration)
)

// SetCustomStore sets custom storage for captchas, replacing the default memory store.
// This function must be called before generating any captchas.
func SetCustomStore(s Store) {
	store = s
}

func New(id string) string {
	return NewLen(id, CaptchaLen)
}

func NewLen(id string, length int) string {
	id = idHash(id)
	digits := randomString(length)
	store.Set(id, []byte(digits))

	return digits
}

func idHash(id string) string {
	h := sha256.New()
	h.Write([]byte(id))
	return hex.EncodeToString(h.Sum(nil))
}

// Verify returns true if the given digits are the ones that were used to create the given captha id.
// The function deletes the captcha with the given id form the internal storage,
// so that the same captcha can't be verifed anymore.
func Verify(id string, digits []byte) bool {
	if digits == nil || len(digits) == 0 {
		return false
	}
	id = idHash(id)

	reald := store.Get(id, true)
	if reald == nil {
		return false
	}

	return bytes.Equal(digits, reald)
}

// VerifyString is like Verify, but accepts a string of digits, It removes spaces and commas from the string,
// but if there is any other charachters, will cause false.
func VerifyString(id string, digits string) bool {
	if digits == "" {
		return false
	}

	digits = strings.TrimSpace(digits)
	digits = strings.Trim(digits, ",")

	return Verify(id, []byte(digits))
}
