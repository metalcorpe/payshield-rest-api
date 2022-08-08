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
	"encoding/base64"
	"fmt"
	"hsmapi/src/engine"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// gin-swagger middleware
// swagger embed files

func main() {
	r := gin.Default()

	//r := rauth.Group("/rest", basicAuth())

	//Verify PIN
	r.POST("/verifypin", func(c *gin.Context) {
		var json engine.PinVer
		if err := c.ShouldBindJSON(&json); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var ec = engine.DA(json)

		if ec != "00" {
			c.JSON(http.StatusOK, gin.H{"errorCode": engine.CheckErrorCode(ec)})
			return
		}
		c.JSON(http.StatusOK, gin.H{"errorCode": "true"})
	})

	//Encrypt
	r.POST("/encrypt", func(c *gin.Context) {
		var json engine.InpEnc

		if err := c.ShouldBindJSON(&json); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var ec, res = engine.M0(json)

		if ec != "00" {
			c.JSON(http.StatusOK, gin.H{"errorCode": engine.CheckErrorCode(ec)})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ciphertext": res})
	})

	//Decrypt
	r.POST("/decrypt", func(c *gin.Context) {
		var json engine.InpDec

		if err := c.ShouldBindJSON(&json); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var ec, res = engine.M2(json)

		if ec != "00" {
			c.JSON(http.StatusOK, gin.H{"errorCode": engine.CheckErrorCode(ec)})
			return
		}
		c.JSON(http.StatusOK, gin.H{"cleartext": res})
	})

	//Tokenise
	r.POST("/tokenise", func(c *gin.Context) {

		var json engine.InpToken

		if err := c.ShouldBindJSON(&json); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		auth := strings.SplitN(c.Request.Header.Get("Authorization"), " ", 2)

		if len(auth) != 2 || auth[0] != "Basic" {
			respondWithError(401, "Unauthorized", c)
			return
		}
		payload, _ := base64.StdEncoding.DecodeString(auth[1])
		pair := strings.SplitN(string(payload), ":", 2)

		if len(pair) != 2 || !authenticateUserToken(pair[0], pair[1], json.Profile) {
			respondWithError(401, "Unauthorized", c)
			return
		}

		c.Next()

		var ec, res = engine.Token(json)

		if ec != "00" {
			c.JSON(http.StatusOK, gin.H{"errorCode": engine.CheckErrorCode(ec)})
			return
		}
		c.JSON(http.StatusOK, gin.H{"token": res})
	})

	//Detokenise
	r.POST("/detokenise", func(c *gin.Context) {
		var json engine.InpDetoken

		if err := c.ShouldBindJSON(&json); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		auth := strings.SplitN(c.Request.Header.Get("Authorization"), " ", 2)

		if len(auth) != 2 || auth[0] != "Basic" {
			respondWithError(401, "Unauthorized", c)
			return
		}
		payload, _ := base64.StdEncoding.DecodeString(auth[1])
		pair := strings.SplitN(string(payload), ":", 2)

		var authenticate bool = authenticateUserDetoken(pair[0], pair[1], json.Profile)

		if len(pair) != 2 || !authenticate {
			respondWithError(401, "Unauthorized", c)
			return
		}

		c.Next()

		var ec, res = engine.Detoken(json)

		if ec != "00" {
			c.JSON(http.StatusOK, gin.H{"errorCode": engine.CheckErrorCode(ec)})
			return
		}

		if authenticate && checkProfileMask(json.Profile) {
			resmask := createMask(json.Profile, res)
			c.JSON(http.StatusOK, gin.H{"data": resmask})
			return
		}

		c.JSON(http.StatusOK, gin.H{"data": res})
	})

	//Version
	r.POST("/version", func(c *gin.Context) {
		var ec, lmk, firmware = engine.NC()

		if ec != "00" {
			c.JSON(http.StatusOK, gin.H{"errorCode": engine.CheckErrorCode(ec)})
			return
		}

		c.JSON(200, gin.H{
			"lmkCheck":       lmk,
			"firmwareNumber": firmware,
		})
	})

	//Migrate
	r.POST("/migrate", func(c *gin.Context) {
		var json engine.Migrate

		if err := c.ShouldBindJSON(&json); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var ec, res = engine.BW(json)

		if ec != "00" {
			c.JSON(http.StatusOK, gin.H{"errorCode": engine.CheckErrorCode(ec)})
			return
		}
		c.JSON(http.StatusOK, res)
	})
	//Migrate
	r.POST("/migrate/private", func(c *gin.Context) {
		var json engine.TranslatePrivate

		if err := c.ShouldBindJSON(&json); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var ec, res = engine.EM(json)

		if ec != "00" {
			c.JSON(http.StatusBadRequest, gin.H{"errorCode": engine.CheckErrorCode(ec)})
			return
		}
		c.JSON(http.StatusOK, res)
	})

	//Generate Key
	r.POST("/generatekey", func(c *gin.Context) {
		var json engine.GenerateKey

		if err := c.ShouldBindJSON(&json); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var ec, res = engine.A0(json)

		if ec != "00" {
			c.JSON(http.StatusOK, gin.H{"errorCode": engine.CheckErrorCode(ec)})
			return
		}
		c.JSON(http.StatusOK, res)
	})
	//Generate Key
	r.POST("/generatekey/pair", func(c *gin.Context) {
		var json engine.GeneratePair

		if err := c.ShouldBindJSON(&json); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var ec, res = engine.EI(json)

		if ec != "00" {
			c.JSON(http.StatusOK, gin.H{"errorCode": engine.CheckErrorCode(ec)})
			return
		}
		c.JSON(http.StatusOK, res)
	})

	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.SetConfigName("server.conf")

	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println("Load file config Server error")
	}

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))
	r.RunTLS(":"+viper.GetString("server.port"), "server.crt", "server.key")

	// r.Run(":8080")

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

	if !err {
		return false
	}
	return true
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

	if !err {
		return false
	}
	return true
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
