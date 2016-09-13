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
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/conseweb/common/captcha"
	"github.com/conseweb/common/semaphore"
	"github.com/spf13/viper"
)

const (
	smUrl = "https://sapi.253.com/msg/HttpBatchSendSM?account=%s&pswd=%s&mobile=%s&msg=%s"
)

type smsMessage struct {
	mobile  string
	content string
}

func (idp *IDP) sendCaptchaSMS(mobile string) error {
	// only for test, if mobile = 13800000000, just return nil
	if mobile == "13800000000" {
		return nil
	}

	capt := captcha.NewLen(mobile, idp.captchaLen)
	idpLogger.Debugf("IDP generate a new captcha:[%s:%v]", mobile, capt)

	idp.smsChan <- &smsMessage{
		mobile:  mobile,
		content: fmt.Sprintf("your verify code is %s", capt),
	}

	return nil
}

func (idp *IDP) asyncSendSMS() {
	idpLogger.Info("IDP sms sender started")

	worker := viper.GetInt("sms.worker")
	if worker <= 0 {
		worker = 8
	}
	sema := semaphore.NewSemaphore(worker)

	account := viper.GetString("sms.account")
	password := viper.GetString("sms.password")

	for {
		select {
		case m, ok := <-idp.smsChan:
			if !ok {
				continue
			}

			idpLogger.Debugf("sending a sms: %+v", m)
			sema.Acquire()
			go func(m *smsMessage) {
				defer sema.Release()

				rsp := httpCall(fmt.Sprintf(smUrl, account, password, m.mobile, url.QueryEscape(m.content)))
				idpLogger.Debugf("send a sms to %s, content: %s, response: %s", m.mobile, m.content, rsp)
			}(m)
		}
	}
}

func httpCall(strUrl string) string {
	idpLogger.Debugf("http call url: %s", strUrl)

	r, err := http.NewRequest("POST", strUrl, nil)
	if err != nil {
		idpLogger.Errorf("http.NewRequest error: %v", err)
		return ""
	}

	idpLogger.Debugf("req: %+v", r)
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		idpLogger.Errorf("http.DefaultClient.Do error: %v", err)
		return ""
	}

	idpLogger.Debugf("resp: %+v", resp)
	if resp.StatusCode != http.StatusOK {
		idpLogger.Errorf("resp.StatusCode!=http.StatusOK: %v", resp.StatusCode)
		return ""
	}

	data, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil && err != io.EOF {
		idpLogger.Errorf("ioutil.ReadAll error: %v", err)
		return ""
	}

	return string(data)
}
