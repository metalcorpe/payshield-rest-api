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
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// gin-swagger middleware
// swagger embed files

func main() {
	// configure logger
	log, _ := zap.NewProduction(zap.WithCaller(false))
	defer func() {
		_ = log.Sync()
	}()

	// print current version
	log.Info("starting up API...")

	viper.SetConfigType("yaml")
	viper.AddConfigPath("config")
	viper.SetConfigName("server.yaml")

	err := viper.ReadInConfig()
	if err != nil {
		log.Panic(err.Error())
		return
	}
	errHttp := http.ListenAndServeTLS(":"+viper.GetString("server.port"), "server.crt", "server.key", ChiRouter().InitRouter())
	if errHttp != nil {
		log.Fatal(errHttp.Error())
		return
	}

}

func authenticateUserToken(username, password, profile string) bool {
	viper.SetConfigType("json")
	viper.AddConfigPath(".")
	viper.SetConfigName("profile.conf")

	errconf := viper.ReadInConfig()
	if errconf != nil {
		fmt.Println("Load file config profile error")
	}

	USERNAME := viper.GetString(profile + "." + "username")
	PASSWORD := viper.GetString(profile + "." + "password")
	TOKENISE := viper.GetBool(profile + "." + "tokenise")

	err := (username == USERNAME) && (password == PASSWORD) && TOKENISE

	return err
}

func authenticateUserDetoken(username, password, profile string) bool {
	viper.SetConfigType("json")
	viper.AddConfigPath(".")
	viper.SetConfigName("profile.conf")

	errconf := viper.ReadInConfig()
	if errconf != nil {
		fmt.Println("Load file config profile error")
	}

	USERNAME := viper.GetString(profile + "." + "username")
	PASSWORD := viper.GetString(profile + "." + "password")
	TOKENISE := viper.GetBool(profile + "." + "detokenise")

	err := (username == USERNAME) && (password == PASSWORD) && TOKENISE

	return err
}

func respondWithError(code int, message string, c *gin.Context) {
	resp := map[string]string{"error": message}

	c.JSON(code, resp)
	c.Abort()
}

func checkProfileMask(profile string) bool {
	viper.SetConfigType("json")
	viper.AddConfigPath(".")
	viper.SetConfigName("profile.conf")

	errconf := viper.ReadInConfig()
	if errconf != nil {
		fmt.Println("Load file config profile error")
	}

	return viper.GetBool(profile + ".mask")
}

func createMask(profile, data string) string {
	viper.SetConfigType("json")
	viper.AddConfigPath(".")
	viper.SetConfigName("profile.conf")

	errconf := viper.ReadInConfig()
	if errconf != nil {
		fmt.Println("Load file config profile error")
	}

	ppl := viper.GetInt(profile + ".maskProfile." + "preservedPrefixLength")
	psl := viper.GetInt(profile + ".maskProfile." + "preservedSuffixLength")
	lenData := len(data)
	if (ppl+psl > lenData) || (ppl+psl < 0) || (ppl < 0) || (psl < 0) || (ppl > lenData) || (psl > lenData) {
		err := "Preserved prefix and suffix length in mask profile not consistent"
		return err
	}

	datappl := data[:ppl]
	datapsl := data[(len(data) - psl):]
	maskchar := viper.GetString(profile + ".maskProfile." + "maskChar")
	return datappl + strings.Repeat(maskchar, len(data[ppl:len(data)-psl])) + datapsl
}
