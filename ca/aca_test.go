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
//
//import (
//	"bytes"
//	"errors"
//	"google/protobuf"
//	"io/ioutil"
//	"math/big"
//	"strings"
//	"time"
//
//	"crypto/x509"
//
//	"github.com/golang/protobuf/proto"
//	"github.com/hyperledger/fabric/core/crypto/primitives"
//	pb "github.com/conseweb/idprovider/protos"
//	"golang.org/x/net/context"
//	"gopkg.in/check.v1"
//)
//
//var identity = "test_user0"
//
//func loadECert(identityID string) (*x509.Certificate, error) {
//	ecertRaw, err := ioutil.ReadFile("./testdata/ecert_" + identityID + ".dump")
//	if err != nil {
//		return nil, err
//	}
//
//	ecert, err := x509.ParseCertificate(ecertRaw)
//
//	if err != nil {
//		return nil, err
//	}
//
//	var certificateID = strings.Split(ecert.Subject.CommonName, "\\")[0]
//
//	if identityID != certificateID {
//		return nil, errors.New("Incorrect ecert user.")
//	}
//
//	return ecert, nil
//}
//
//func (t *TestCA) TestFetchAttributes(c *check.C) {
//	resp, err := t.fetchAttributes()
//	c.Check(err, check.IsNil)
//	c.Check(resp.Status, check.Not(check.Equals), pb.ACAFetchAttrResp_FAILURE)
//}
//
//func (t *TestCA) TestFetchAttributes_MultipleInvocations(c *check.C) {
//	expectedAttributesSize := 3
//	expectedCount := 3
//
//	resp, err := t.fetchAttributes()
//	c.Check(err, check.IsNil)
//	c.Check(resp.Status, check.Not(check.Equals), pb.ACAFetchAttrResp_FAILURE)
//
//	attributesMap1, count, err := t.readAttributesFromDB("test_user0", "bank_a")
//	c.Check(err, check.IsNil)
//	c.Check(count, check.Equals, expectedCount)
//
//	resp, err = t.fetchAttributes()
//	c.Check(err, check.IsNil)
//	c.Check(resp.Status, check.Not(check.Equals), pb.ACAFetchAttrResp_FAILURE)
//
//	attributesMap2, count, err := t.readAttributesFromDB("test_user0", "bank_a")
//	c.Check(err, check.IsNil)
//	c.Check(count, check.Equals, expectedCount)
//	c.Check(len(attributesMap1), check.Equals, expectedAttributesSize)
//	c.Check(len(attributesMap1), check.Equals, len(attributesMap2))
//
//	for key, value := range attributesMap1 {
//		if bytes.Compare(value, attributesMap2[key]) != 0 {
//			c.Errorf("Error executing test: %v. Expected: [%v], Actual: [%v]", "attributes should be the same each time", value, attributesMap2[key])
//		}
//	}
//
//	if len(attributesMap1) != len(attributesMap2) {
//		c.Errorf("Error executing test: %v", "attributes should be the same each time")
//	}
//}
//
//func (t *TestCA) readAttributesFromDB(id string, affiliation string) (map[string][]byte, int, error) {
//	var attributeName string
//	var attributeValue []byte
//
//	query := "SELECT attributeName, attributeValue FROM attributes WHERE id=? AND affiliation=?"
//
//	rows, err := t.aca.db.Query(query, id, affiliation)
//	if err != nil {
//		return nil, 0, err
//	}
//
//	defer rows.Close()
//
//	count := 0
//	attributesMap := make(map[string][]byte)
//	for rows.Next() {
//		err := rows.Scan(&attributeName, &attributeValue)
//		if err != nil {
//			return nil, 0, err
//		}
//		attributesMap[attributeName] = attributeValue
//		count++
//	}
//
//	return attributesMap, count, nil
//}
//
//func (t *TestCA) fetchAttributes() (*pb.ACAFetchAttrResp, error) {
//	cert, err := loadECert(identity)
//
//	if err != nil {
//		return nil, err
//	}
//	sock, acaP, err := GetACAClient()
//	if err != nil {
//		return nil, err
//	}
//	defer sock.Close()
//
//	req := &pb.ACAFetchAttrReq{
//		Ts:        &google_protobuf.Timestamp{Seconds: time.Now().Unix(), Nanos: 0},
//		ECert:     &pb.Cert{Cert: cert.Raw},
//		Signature: nil}
//
//	var rawReq []byte
//	rawReq, err = proto.Marshal(req)
//	if err != nil {
//		return nil, err
//	}
//
//	var r, s *big.Int
//
//	r, s, err = primitives.ECDSASignDirect(t.eca.priv, rawReq)
//
//	if err != nil {
//		return nil, err
//	}
//
//	R, _ := r.MarshalText()
//	S, _ := s.MarshalText()
//
//	req.Signature = &pb.Signature{Type: pb.CryptoType_ECDSA, R: R, S: S}
//
//	resp, err := acaP.FetchAttributes(context.Background(), req)
//
//	return resp, err
//}
//
//func (t *TestCA) TestFetchAttributes_MissingSignature(c *check.C) {
//	cert, err := loadECert(identity)
//	c.Check(err, check.IsNil)
//
//	sock, acaP, err := GetACAClient()
//	c.Check(err, check.IsNil)
//	defer sock.Close()
//
//	req := &pb.ACAFetchAttrReq{
//		Ts:        &google_protobuf.Timestamp{Seconds: time.Now().Unix(), Nanos: 0},
//		ECert:     &pb.Cert{Cert: cert.Raw},
//		Signature: nil}
//
//	resp, err := acaP.FetchAttributes(context.Background(), req)
//	c.Check(err, check.IsNil)
//	c.Check(resp.Status, check.Not(check.Equals), pb.ACAFetchAttrResp_SUCCESS)
//}
//
//func (t *TestCA) TestRequestAttributes(c *check.C) {
//
//	cert, err := loadECert(identity)
//	c.Check(err, check.IsNil)
//	ecert := cert.Raw
//
//	sock, acaP, err := GetACAClient()
//	c.Check(err, check.IsNil)
//	defer sock.Close()
//
//	var attributes = make([]*pb.TCertAttribute, 0)
//	attributes = append(attributes, &pb.TCertAttribute{AttributeName: "company"})
//	attributes = append(attributes, &pb.TCertAttribute{AttributeName: "position"})
//	attributes = append(attributes, &pb.TCertAttribute{AttributeName: "identity-number"})
//
//	req := &pb.ACAAttrReq{
//		Ts:         &google_protobuf.Timestamp{Seconds: time.Now().Unix(), Nanos: 0},
//		Id:         &pb.Identity{Id: identity},
//		ECert:      &pb.Cert{Cert: ecert},
//		Attributes: attributes,
//		Signature:  nil}
//
//	var rawReq []byte
//	rawReq, err = proto.Marshal(req)
//	c.Check(err, check.IsNil)
//
//	var r, s *big.Int
//
//	r, s, err = primitives.ECDSASignDirect(t.tca.priv, rawReq)
//	c.Check(err, check.IsNil)
//
//	R, _ := r.MarshalText()
//	S, _ := s.MarshalText()
//
//	req.Signature = &pb.Signature{Type: pb.CryptoType_ECDSA, R: R, S: S}
//
//	resp, err := acaP.RequestAttributes(context.Background(), req)
//	c.Check(err, check.IsNil)
//	c.Check(resp.Status, check.Not(check.Equals), pb.ACAAttrResp_FAILURE)
//
//	aCert, err := primitives.DERToX509Certificate(resp.Cert.Cert)
//	c.Check(err, check.IsNil)
//
//	valueMap := make(map[string]string)
//	for _, eachExtension := range aCert.Extensions {
//		if IsAttributeOID(eachExtension.Id) {
//			var attribute pb.ACAAttribute
//			proto.Unmarshal(eachExtension.Value, &attribute)
//			valueMap[attribute.AttributeName] = string(attribute.AttributeValue)
//		}
//	}
//
//	c.Check(valueMap["company"], check.Equals, "ACompany")
//	c.Check(valueMap["position"], check.Equals, "Software Engineer" )
//}
//
//func (t *TestCA) TestRequestAttributes_AttributesMismatch(c *check.C) {
//
//	cert, err := loadECert(identity)
//	c.Check(err, check.IsNil)
//	ecert := cert.Raw
//
//	sock, acaP, err := GetACAClient()
//	c.Check(err, check.IsNil)
//	defer sock.Close()
//
//	var attributes = make([]*pb.TCertAttribute, 0)
//	attributes = append(attributes, &pb.TCertAttribute{AttributeName: "account"})
//
//	req := &pb.ACAAttrReq{
//		Ts:         &google_protobuf.Timestamp{Seconds: time.Now().Unix(), Nanos: 0},
//		Id:         &pb.Identity{Id: identity},
//		ECert:      &pb.Cert{Cert: ecert},
//		Attributes: attributes,
//		Signature:  nil}
//
//	var rawReq []byte
//	rawReq, err = proto.Marshal(req)
//	c.Check(err, check.IsNil)
//
//	var r, s *big.Int
//
//	r, s, err = primitives.ECDSASignDirect(t.tca.priv, rawReq)
//	c.Check(err, check.IsNil)
//
//	R, _ := r.MarshalText()
//	S, _ := s.MarshalText()
//
//	req.Signature = &pb.Signature{Type: pb.CryptoType_ECDSA, R: R, S: S}
//
//	resp, err := acaP.RequestAttributes(context.Background(), req)
//	c.Check(err, check.IsNil)
//
//	if resp.Status == pb.ACAAttrResp_FAILURE {
//		c.Errorf("Error executing test: %v", err)
//	}
//
//	if resp.Status != pb.ACAAttrResp_NO_ATTRIBUTES_FOUND {
//		c.Error("Test failed 'account' attribute shouldn't be found.")
//	}
//
//}
//
//func (t *TestCA) TestRequestAttributes_MissingSignature(c *check.C) {
//
//	cert, err := loadECert(identity)
//	if err != nil {
//		c.Errorf("Error loading ECert: %v", err)
//	}
//	ecert := cert.Raw
//
//	sock, acaP, err := GetACAClient()
//	if err != nil {
//		c.Errorf("Error executing test: %v", err)
//	}
//	defer sock.Close()
//
//	var attributes = make([]*pb.TCertAttribute, 0)
//	attributes = append(attributes, &pb.TCertAttribute{AttributeName: "company"})
//	attributes = append(attributes, &pb.TCertAttribute{AttributeName: "position"})
//	attributes = append(attributes, &pb.TCertAttribute{AttributeName: "identity-number"})
//
//	req := &pb.ACAAttrReq{
//		Ts:         &google_protobuf.Timestamp{Seconds: time.Now().Unix(), Nanos: 0},
//		Id:         &pb.Identity{Id: identity},
//		ECert:      &pb.Cert{Cert: ecert},
//		Attributes: attributes,
//		Signature:  nil}
//
//	resp, err := acaP.RequestAttributes(context.Background(), req)
//	if err != nil {
//		c.Errorf("Error executing test: %v", err)
//	}
//
//	if resp.Status < pb.ACAAttrResp_FAILURE_MINVAL || resp.Status > pb.ACAAttrResp_FAILURE_MAXVAL {
//		c.Errorf("Requesting attributes without a signature should fail")
//	}
//}
//
//func (t *TestCA) TestRequestAttributes_DuplicatedAttributes(c *check.C) {
//
//	cert, err := loadECert(identity)
//	if err != nil {
//		c.Errorf("Error loading ECert: %v", err)
//	}
//	ecert := cert.Raw
//
//	sock, acaP, err := GetACAClient()
//	if err != nil {
//		c.Errorf("Error executing test: %v", err)
//	}
//	defer sock.Close()
//
//	var attributes = make([]*pb.TCertAttribute, 0)
//	attributes = append(attributes, &pb.TCertAttribute{AttributeName: "company"})
//	attributes = append(attributes, &pb.TCertAttribute{AttributeName: "company"})
//
//	req := &pb.ACAAttrReq{
//		Ts:         &google_protobuf.Timestamp{Seconds: time.Now().Unix(), Nanos: 0},
//		Id:         &pb.Identity{Id: identity},
//		ECert:      &pb.Cert{Cert: ecert},
//		Attributes: attributes,
//		Signature:  nil}
//
//	var rawReq []byte
//	rawReq, err = proto.Marshal(req)
//	if err != nil {
//		c.Errorf("Error executing test: %v", err)
//	}
//
//	var r, s *big.Int
//
//	r, s, err = primitives.ECDSASignDirect(t.tca.priv, rawReq)
//
//	if err != nil {
//		c.Errorf("Error executing test: %v", err)
//	}
//
//	R, _ := r.MarshalText()
//	S, _ := s.MarshalText()
//
//	req.Signature = &pb.Signature{Type: pb.CryptoType_ECDSA, R: R, S: S}
//
//	resp, err := acaP.RequestAttributes(context.Background(), req)
//	if err != nil {
//		c.Errorf("Error executing test: %v", err)
//	}
//
//	if resp.Status < pb.ACAAttrResp_FAILURE_MINVAL || resp.Status > pb.ACAAttrResp_FAILURE_MAXVAL {
//		c.Errorf("Requesting attributes with multiple values should fail")
//	}
//}
//
//func (t *TestCA) TestRequestAttributes_FullAttributes(c *check.C) {
//
//	cert, err := loadECert(identity)
//	if err != nil {
//		c.Errorf("Error loading ECert: %v", err)
//	}
//	ecert := cert.Raw
//
//	sock, acaP, err := GetACAClient()
//	if err != nil {
//		c.Errorf("Error executing test: %v", err)
//	}
//	defer sock.Close()
//
//	var attributes []*pb.TCertAttribute
//	attributes = append(attributes, &pb.TCertAttribute{AttributeName: "company"})
//	attributes = append(attributes, &pb.TCertAttribute{AttributeName: "business_unit"})
//
//	req := &pb.ACAAttrReq{
//		Ts:         &google_protobuf.Timestamp{Seconds: time.Now().Unix(), Nanos: 0},
//		Id:         &pb.Identity{Id: identity},
//		ECert:      &pb.Cert{Cert: ecert},
//		Attributes: attributes,
//		Signature:  nil}
//
//	var rawReq []byte
//	rawReq, err = proto.Marshal(req)
//	if err != nil {
//		c.Errorf("Error executing test: %v", err)
//	}
//
//	var r, s *big.Int
//
//	r, s, err = primitives.ECDSASignDirect(t.tca.priv, rawReq)
//
//	if err != nil {
//		c.Errorf("Error executing test: %v", err)
//	}
//
//	R, _ := r.MarshalText()
//	S, _ := s.MarshalText()
//
//	req.Signature = &pb.Signature{Type: pb.CryptoType_ECDSA, R: R, S: S}
//
//	resp, err := acaP.RequestAttributes(context.Background(), req)
//	if err != nil {
//		c.Errorf("Error executing test: %v", err)
//	}
//
//	if resp.Status == pb.ACAAttrResp_FAILURE {
//		c.Errorf("Error executing test: %v", err)
//	}
//
//	aCert, err := primitives.DERToX509Certificate(resp.Cert.Cert)
//	if err != nil {
//		c.Errorf("Error executing test: %v", err)
//	}
//
//	valueMap := make(map[string]string)
//	for _, eachExtension := range aCert.Extensions {
//		if IsAttributeOID(eachExtension.Id) {
//			var attribute pb.ACAAttribute
//			proto.Unmarshal(eachExtension.Value, &attribute)
//			valueMap[attribute.AttributeName] = string(attribute.AttributeValue)
//		}
//	}
//
//	c.Check(valueMap["company"], check.Equals, "ACompany")
//	c.Check(valueMap["business_unit"], check.Equals, "Sales")
//	c.Check(resp.Status, check.Equals, pb.ACAAttrResp_FULL_SUCCESSFUL)
//}
//
//func (t *TestCA) TestRequestAttributes_PartialAttributes(c *check.C) {
//
//	cert, err := loadECert(identity)
//	if err != nil {
//		c.Errorf("Error loading ECert: %v", err)
//	}
//	ecert := cert.Raw
//
//	sock, acaP, err := GetACAClient()
//	c.Check(err, check.IsNil)
//	defer sock.Close()
//
//	var attributes []*pb.TCertAttribute
//	attributes = append(attributes, &pb.TCertAttribute{AttributeName: "company"})
//	attributes = append(attributes, &pb.TCertAttribute{AttributeName: "credit_card"})
//
//	req := &pb.ACAAttrReq{
//		Ts:         &google_protobuf.Timestamp{Seconds: time.Now().Unix(), Nanos: 0},
//		Id:         &pb.Identity{Id: identity},
//		ECert:      &pb.Cert{Cert: ecert},
//		Attributes: attributes,
//		Signature:  nil}
//
//	var rawReq []byte
//	rawReq, err = proto.Marshal(req)
//	if err != nil {
//		c.Errorf("Error executing test: %v", err)
//	}
//
//	var r, s *big.Int
//
//	r, s, err = primitives.ECDSASignDirect(t.tca.priv, rawReq)
//
//	if err != nil {
//		c.Errorf("Error executing test: %v", err)
//	}
//
//	R, _ := r.MarshalText()
//	S, _ := s.MarshalText()
//
//	req.Signature = &pb.Signature{Type: pb.CryptoType_ECDSA, R: R, S: S}
//
//	resp, err := acaP.RequestAttributes(context.Background(), req)
//	c.Check(err, check.IsNil)
//
//	if resp.Status == pb.ACAAttrResp_FAILURE {
//		c.Errorf("Error executing test: %v", err)
//	}
//
//	aCert, err := primitives.DERToX509Certificate(resp.Cert.Cert)
//	if err != nil {
//		c.Errorf("Error executing test: %v", err)
//	}
//
//	valueMap := make(map[string]string)
//	for _, eachExtension := range aCert.Extensions {
//		if IsAttributeOID(eachExtension.Id) {
//			var attribute pb.ACAAttribute
//			proto.Unmarshal(eachExtension.Value, &attribute)
//			valueMap[attribute.AttributeName] = string(attribute.AttributeValue)
//		}
//	}
//
//	c.Check(valueMap["company"], check.Equals, "ACompany")
//	c.Check(valueMap["credit_card"], check.Equals, "")
//	c.Check(resp.Status, check.Not(check.Equals),pb.ACAAttrResp_NO_ATTRIBUTES_FOUND )
//	c.Check(resp.Status, check.Equals, pb.ACAAttrResp_PARTIAL_SUCCESSFUL )
//}
//
//func contains(s []string, e string) bool {
//	for _, a := range s {
//		if a == e {
//			return true
//		}
//	}
//	return false
//}
