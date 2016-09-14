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
package crypto

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/core/crypto/primitives"
)

type MessageSigner interface {
	proto.Message
	SetSignature([]byte)
	GetSignature() []byte
}

// SignGRPCRequest sign the request, priv can be nil, if nil, generate new one
func SignGRPCRequest(msg MessageSigner, priv *ecdsa.PrivateKey) error {
	if priv == nil {
		return errors.New("invalid private key for signature")
	}

	rawreq, err := proto.Marshal(msg)
	if err != nil {
		return err
	}

	sig, err := primitives.ECDSASign(priv, rawreq)
	if err != nil {
		return err
	}
	msg.SetSignature(sig)

	return nil
}

// VerifyGRPCRequest verify request signature, return error if not
func VerifyGRPCRequest(msg MessageSigner, signPub []byte) error {
	if signPub == nil || len(signPub) == 0 {
		return errors.New("invalid public key for signature")
	}

	sign := msg.GetSignature()
	msg.SetSignature(nil)

	msgRaw, err := proto.Marshal(msg)
	if err != nil {
		return err
	}

	spub, err := x509.ParsePKIXPublicKey(signPub)
	if err != nil {
		return err
	}

	if _, err := primitives.ECDSAVerify(spub, msgRaw, sign); err != nil {
		return err
	}

	return nil
}
