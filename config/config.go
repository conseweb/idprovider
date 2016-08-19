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
package config

import (
	"github.com/spf13/viper"
	"strings"
	"path/filepath"
	"os"
)

const envPrefix = "IDPROVIDER"

func LoadConfig() error {
	viper.SetEnvPrefix(envPrefix)
	viper.AutomaticEnv()
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)
	viper.SetConfigName("idprovider")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./")
	// Path to look for the config file based on GOPATH
	gopath := os.Getenv("GOPATH")
	for _, p := range filepath.SplitList(gopath) {
		cfgpath := filepath.Join(p, "src/github.com/conseweb/idprovider")
		viper.AddConfigPath(cfgpath)
	}

	return viper.ReadInConfig()
}
