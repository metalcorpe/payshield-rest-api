// Copyright PT Dymar Jaya Indonesia
// Date February 2020
// RestAPI Thales payShield HSM using Golang
// Code by Mudito Adi Pranowo
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package main

import (
	"net/http"

	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// Create private data struct to hold config options.
type server struct {
	Host       string
	Port       string
	Tls        bool
	ServerCert string
	ServerKey  string
}
type hsm struct {
	Ip           string
	Port         int
	PortVariant  int
	PortKeyBlock int
	Tls          bool
	ClientCert   string
	ClientKey    string
}
type config struct {
	Server server
	Hsm    hsm
}

func main() {
	// configure logger
	log, _ := zap.NewProduction(zap.WithCaller(true))
	defer func() {
		_ = log.Sync()
	}()

	viper.SetConfigType("yaml")
	viper.AddConfigPath("config")
	viper.SetConfigName("service.yaml")

	err := viper.ReadInConfig()
	if err != nil {
		log.Panic(err.Error())
		return
	}

	conf := &config{}
	err = viper.Unmarshal(conf)
	if err != nil {
		log.Panic(err.Error())
		return
	}

	addr := conf.Server.Host + ":" + conf.Server.Port
	log.Info("starting up API at: " + func(a bool) string {
		if a {
			return "https://"
		} else {
			return "http://"
		}
	}(conf.Server.Tls) + addr)

	var errHttp error
	if conf.Server.Tls {
		errHttp = http.ListenAndServeTLS(addr, conf.Server.ServerCert, conf.Server.ServerKey, ChiRouter(*conf).InitRouter())
	} else {
		errHttp = http.ListenAndServe(addr, ChiRouter(*conf).InitRouter())
	}

	if errHttp != nil {
		log.Fatal(errHttp.Error())
		return
	}
}
