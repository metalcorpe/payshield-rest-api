package main

import (
	"encoding/base64"
	"github.com/gin-gonic/gin"
	"hsmapi/src/engine"
	"net/http"
	"strings"
)

func verifypin(c *gin.Context) {
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
}

func generatekey(c *gin.Context) {
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
}

func detokenise(c *gin.Context) {
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
}

func encrypt(c *gin.Context) {
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
}

func decrypt(c *gin.Context) {
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
}

func tokenise(c *gin.Context) {

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
}

func version(c *gin.Context) {
	var ec, lmk, firmware = engine.NC()

	if ec != "00" {
		c.JSON(http.StatusOK, gin.H{"errorCode": engine.CheckErrorCode(ec)})
		return
	}

	c.JSON(200, gin.H{
		"lmkCheck":       lmk,
		"firmwareNumber": firmware,
	})
}

func migrate(c *gin.Context) {
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
}

func migratePrivate(c *gin.Context) {
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
}

func exportKey(c *gin.Context) {
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
}

func generateKeyPair(c *gin.Context) {
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
}
func addRoutes(r *gin.Engine) {

	//Verify PIN
	r.POST("/verifypin", verifypin)

	//Encrypt
	r.POST("/encrypt", encrypt)

	//Decrypt
	r.POST("/decrypt", decrypt)

	//Tokenise
	r.POST("/tokenise", tokenise)

	//Detokenise
	r.POST("/detokenise", detokenise)

	//Version
	r.POST("/version", version)

	//Migrate
	r.POST("/migrate", migrate)
	//Migrate
	r.POST("/migrate/private", migratePrivate)

	//Generate Key
	r.POST("/generatekey", generatekey)

	//Generate Key
	r.POST("/exportkey", exportKey)

	//Generate Key
	r.POST("/generatekey/pair", generateKeyPair)
}
