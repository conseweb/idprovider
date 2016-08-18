/*
Copyright IBM Corp. 2016 All Rights Reserved.

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
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"google/protobuf"
	"io/ioutil"
	"time"

	"golang.org/x/net/context"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/core/crypto/primitives"
	pb "github.com/conseweb/idprovider/protos"
	"gopkg.in/check.v1"
)

func (t *TestCA) TestNewTCA(c *check.C) {

	if t.tca.hmacKey == nil || len(t.tca.hmacKey) == 0 {
		c.Error("Could not read hmacKey from TCA")
	}

	if t.tca.rootPreKey == nil || len(t.tca.rootPreKey) == 0 {
		c.Error("Could not read rootPreKey from TCA")
	}

	if t.tca.preKeys == nil || len(t.tca.preKeys) == 0 {
		c.Error("Could not read preKeys from TCA")
	}
}

func (t *TestCA) TestCreateCertificateSet(c *check.C) {
	enrollmentID := "test_user0"
	enrollmentPassword := "MS9qrN8hFjlE"

	ecertRaw, priv, err := loadECertAndEnrollmentPrivateKey(enrollmentID, enrollmentPassword)
	if err != nil {
		c.Error(err)
	}

	const expectedTcertSubjectCommonNameValue string = "Transaction Certificate"
	ncerts := 1
	for nattributes := -1; nattributes < 1; nattributes++ {
		certificateSetRequest, err := buildCertificateSetRequest(enrollmentID, priv, ncerts, nattributes)
		if err != nil {
			c.Error(err)
		}

		var certSets []*TCertSet
		certSets, err = t.tca.getCertificateSets(enrollmentID)
		if err != nil {
			c.Error(err)
		}

		certSetsCountBefore := len(certSets)

		tcap := &TCAP{t.tca}
		response, err := tcap.createCertificateSet(context.Background(), ecertRaw, certificateSetRequest)
		if err != nil {
			c.Error(err)
		}

		certSets, err = t.tca.getCertificateSets(enrollmentID)
		if err != nil {
			c.Error(err)
		}
		certSetsCountAfter := len(certSets)

		if certSetsCountBefore != certSetsCountAfter-1 {
			c.Error("TCertSets count should be increased by 1 after requesting a new set of TCerts")
		}

		tcerts := response.GetCerts()
		if len(tcerts.Certs) != ncerts {
			c.Error(fmt.Errorf("Invalid tcert size. Expected: %v, Actual: %v", ncerts, len(tcerts.Certs)))
		}

		for pos, eachTCert := range tcerts.Certs {
			tcert, err := x509.ParseCertificate(eachTCert.Cert)
			if err != nil {
				c.Errorf("Error: %v\nCould not x509.ParseCertificate %v", err, eachTCert.Cert)
			}

			c.Logf("Examining TCert[%d]'s Subject: %v", pos, tcert.Subject)
			if tcert.Subject.CommonName != expectedTcertSubjectCommonNameValue {
				c.Errorf("The TCert's Subject.CommonName is '%s' which is different than '%s'", tcert.Subject.CommonName, expectedTcertSubjectCommonNameValue)
			}
			c.Logf("Successfully verified that TCert[%d].Subject.CommonName == '%s'", pos, tcert.Subject.CommonName)
		}
	}
}

func loadECertAndEnrollmentPrivateKey(enrollmentID string, password string) ([]byte, *ecdsa.PrivateKey, error) {
	cooked, err := ioutil.ReadFile("./testdata/key_" + enrollmentID + ".dump")
	if err != nil {
		return nil, nil, err
	}

	block, _ := pem.Decode(cooked)
	decryptedBlock, err := x509.DecryptPEMBlock(block, []byte(password))
	if err != nil {
		return nil, nil, err
	}

	enrollmentPrivateKey, err := x509.ParseECPrivateKey(decryptedBlock)
	if err != nil {
		return nil, nil, err
	}

	if err != nil {
		return nil, nil, err
	}

	ecertRaw, err := ioutil.ReadFile("./testdata/ecert_" + enrollmentID + ".dump")
	if err != nil {
		return nil, nil, err
	}

	return ecertRaw, enrollmentPrivateKey, nil
}

func buildCertificateSetRequest(enrollID string, enrollmentPrivKey *ecdsa.PrivateKey, num, numattrs int) (*pb.TCertCreateSetReq, error) {
	now := time.Now()
	timestamp := google_protobuf.Timestamp{Seconds: int64(now.Second()), Nanos: int32(now.Nanosecond())}

	var attributes []*pb.TCertAttribute
	if numattrs >= 0 { // else negative means use nil from above
		attributes = make([]*pb.TCertAttribute, numattrs)
	}

	req := &pb.TCertCreateSetReq{
		Ts:         &timestamp,
		Id:         &pb.Identity{Id: enrollID},
		Num:        uint32(num),
		Attributes: attributes,
		Sig:        nil,
	}

	rawReq, err := proto.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("Failed marshaling request [%v].", err)
	}

	r, s, err := primitives.ECDSASignDirect(enrollmentPrivKey, rawReq)
	if err != nil {
		return nil, fmt.Errorf("Failed creating signature for [%v]: [%v].", rawReq, err)
	}

	R, _ := r.MarshalText()
	S, _ := s.MarshalText()

	req.Sig = &pb.Signature{Type: pb.CryptoType_ECDSA, R: R, S: S}
	return req, nil
}
