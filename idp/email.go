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
package idp

import (
	"bytes"
	"html/template"
	"strings"
	"time"

	"github.com/conseweb/common/captcha"
	"github.com/conseweb/common/semaphore"
	"github.com/spf13/viper"
	"gopkg.in/gomail.v2"
)

var (
	captchaHtmlTpl = `
		<html><body><p><span>captcha: </span><span style="background-color:#EEE; font-size:18px">{{.captcha}}</span></p></body></html>
	`
)

func (idp *IDP) sendCaptchaEmail(email string) error {
	// only for test, if email contains '@example.com', just return nil
	if strings.Contains(email, "@example.com") {
		return nil
	}

	capt := captcha.NewLen(email, idp.captchaLen)
	idpLogger.Debugf("IDP generate a new captcha:[%s:%v]", email, capt)

	tmpl, err := template.New(email).Parse(captchaHtmlTpl)
	if err != nil {
		idpLogger.Errorf("parese captcha html template error: %v", err)
		return err
	}

	writer := bytes.NewBufferString("")
	err = tmpl.Execute(writer, map[string]interface{}{
		"captcha": capt,
	})
	if err != nil {
		idpLogger.Errorf("execute html template return error: %v", err)
		return err
	}

	m := gomail.NewMessage()
	m.SetHeader("From", viper.GetString("mail.user"))
	m.SetHeader("To", email)
	m.SetHeader("Subject", viper.GetString("mail.captchaEmailSubject"))
	m.SetBody("text/html", writer.String())

	idp.mailChan <- m

	return nil
}

func (idp *IDP) asyncSendEmail() {
	idpLogger.Info("IDP mail sender started")

	worker := viper.GetInt("mail.worker")
	if worker <= 0 {
		worker = 8
	}
	sema := semaphore.NewSemaphore(worker)

	var s gomail.SendCloser
	var err error
	ticker := time.NewTicker(time.Second * 30)
	open := false

	for {
		select {
		case m, ok := <-idp.mailChan:
			if !ok {
				continue
			}

			sema.Acquire()
			go func(m *gomail.Message) {
				defer sema.Release()

				if !open {
					if s, err = idp.mailDialer.Dial(); err != nil {
						idpLogger.Errorf("mail dialer dial error: %v", err)
						return
					}

					open = true
				}

				if err = gomail.Send(s, m); err != nil {
					idpLogger.Errorf("mail send error: %v", err)
					return
				}

				idpLogger.Debugf("sending an email to %v", m.GetHeader("To"))
			}(m)

		case <-ticker.C:
			if open {
				if err = s.Close(); err != nil {
					idpLogger.Errorf("close mail sender error: %v", err)
				}

				open = false
			}
		}
	}
}
