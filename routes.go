package main

import (
	"encoding/base64"
	"github.com/gin-gonic/gin"
	"hsmapi/src/engine"
	"net/http"
	"strings"
)

func addRoutes(r *gin.Engine) {

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
	r.POST("/exportkey", func(c *gin.Context) {
		var json engine.ExportKey

		if err := c.ShouldBindJSON(&json); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var ec, res = engine.A8(json)

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

}
