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

package engine

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"

	"github.com/metalcorpe/payshield-rest-gopher/interfaces"
	"github.com/metalcorpe/payshield-rest-gopher/models"
)

type HsmRepository struct {
	interfaces.IConnectionHandler
}

// Verify PIN
func (repository *HsmRepository) DA(input models.PinVer) (errCode string) {

	messageHeader := []byte("HEAD")
	commandCode := []byte("DA")
	tpk := []byte(input.Tpk)
	pvk := []byte(input.Pvk)
	pinLen := []byte("12")
	pinBlock := []byte(input.PinBlock)
	pinBlockFormat := []byte("01")
	checkLen := []byte("06")
	pan := []byte(input.Pan)
	decimalizationTable := []byte(input.DecimalizationTable)
	pinValidationData := []byte(input.PinValidationData)
	pinOffset := []byte(input.PinOffset)

	commandMessage := Join(
		messageHeader,
		commandCode,
		tpk,
		pvk,
		pinLen,
		pinBlock,
		pinBlockFormat,
		checkLen,
		pan,
		decimalizationTable,
		pinValidationData,
		pinOffset,
	)

	responseMessage := repository.WriteRequest(commandMessage)

	errCode = string(responseMessage)[8:10]

	if errCode == "00" {
		errCode = string(responseMessage)[8:]
	}
	if errCode != "00" {
		errCode = string(responseMessage)[8:]
	}
	return
}

// Encrypt
func (repository *HsmRepository) M0(input models.InpEnc) (res string, errCode string) {

	//max buffer in payshield is 32KB
	data, _ := base64.URLEncoding.DecodeString(input.ClearText)
	dataPad := zeroPadding([]byte(data), 8)
	dataLen := leftPad(string(dataPad), "0", 4)

	messageHeader := []byte("HEAD")
	commandCode := []byte("M0")
	modeFlag := []byte("00")
	inputFormatFlag := []byte("0")
	outputFormatFlag := []byte("0")
	keyType := []byte("FFF")
	key := []byte(input.Key)
	messageLen := []byte(dataLen)
	message := dataPad

	commandMessage := Join(
		messageHeader,
		commandCode,
		modeFlag,
		inputFormatFlag,
		outputFormatFlag,
		keyType,
		key,
		messageLen,
		message,
	)

	responseMessage := repository.WriteRequest(commandMessage)

	errCode = string(responseMessage)[8:10]

	if errCode == "00" {
		res = base64.URLEncoding.EncodeToString([]byte(string(responseMessage)[14:]))
	}
	if errCode != "00" {
		res = ""
	}
	return

}

// Decrypt
func (repository *HsmRepository) M2(input models.InpDec) (res string, errCode string) {

	//max buffer in payshield is 32KB
	data, _ := base64.URLEncoding.DecodeString(input.CipherText)
	dataLen := leftPad(string(data), "0", 4)

	messageHeader := []byte("HEAD")
	commandCode := []byte("M2")
	modeFlag := []byte("00")
	inputFormatFlag := []byte("0")
	outputFormatFlag := []byte("0")
	keyType := []byte("FFF")
	key := []byte(input.Key)
	messageLen := []byte(dataLen)
	message := data

	commandMessage := Join(
		messageHeader,
		commandCode,
		modeFlag,
		inputFormatFlag,
		outputFormatFlag,
		keyType,
		key,
		messageLen,
		message,
	)

	responseMessage := repository.WriteRequest(commandMessage)

	errCode = string(responseMessage)[8:10]

	if errCode == "00" {
		res = base64.URLEncoding.EncodeToString([]byte(string(responseMessage)[14:]))
	}
	if errCode != "00" {
		res = ""
	}
	return
}

// Check Version
func (repository *HsmRepository) NC() (lmk string, firmware string, errCode string) {

	messageHeader := []byte("HEAD")
	commandCode := []byte("NC")

	commandMessage := Join(
		messageHeader,
		commandCode,
	)

	responseMessage := repository.WriteRequest(commandMessage)

	errCode = string(responseMessage)[8:10]

	if errCode == "00" {
		lmk = string(responseMessage)[10 : 10+16]
		firmware = string(responseMessage)[26:]
	}
	if errCode != "00" {
		lmk = ""
		firmware = ""
	}

	return

}

// Decrypt
func (repository *HsmRepository) BW(input models.Migrate) (res models.MigrateRes, errCode string) {

	messageHeader := []byte("HEAD")
	commandCode := []byte("BW")
	keyTypeCode2d2d := []byte(input.KeyTypeCode2d)
	keyLenFlag := []byte("1")
	key := []byte(input.Key)
	delim1 := []byte(";")
	keyTypeCode2d := []byte(input.KeyTypeCode)
	delim2 := []byte("#")
	keyusage := []byte(input.KeyUsage)
	modeOfUse := []byte(input.ModeOfUse)
	kvn := []byte(input.KVN)
	exportability := []byte(input.Exportability)
	optionalBlockNumber := []byte(input.NumberOfOptionalBlocks)
	delim3 := []byte("!")
	kcvFlag := []byte(input.KCVReturnFlag)
	kcvType := []byte(input.KCVType)

	commandMessage := Join(
		messageHeader,
		commandCode,
		keyTypeCode2d2d,
		keyLenFlag,
		key,
		delim1,
		keyTypeCode2d,
		delim2,
		keyusage,
		modeOfUse,
		kvn,
		exportability,
		optionalBlockNumber,
	)
	if input.KCVReturnFlag == "1" {
		commandMessage = Join(
			commandMessage,
			delim3,
			kcvFlag,
			kcvType,
		)
	}

	responseMessage := repository.WriteRequest(commandMessage)

	errCode = string(responseMessage)[8:10]

	if errCode == "00" {
		endIndex := 0
		if input.KCVReturnFlag == "1" && input.KCVType == "0" {
			endIndex = 16
		} else if input.KCVReturnFlag == "1" && input.KCVType == "1" {
			endIndex = 6
		} else {
			endIndex = 0
		}

		index := 10
		res.Key = string(responseMessage[index : len(responseMessage)-endIndex])
		// if input.KeyScheme == "U" {
		// 	res.Key = string(responseMessage[index : index+32+1])
		// 	index += 32 + 1
		// } else if input.KeyScheme == "T" {
		// 	res.Key = string(responseMessage[index : index+48+1])
		// 	index += 48 + 1
		// } else if input.KeyScheme == "S" || input.KeyScheme == "R" {
		// 	res.Key = string(responseMessage[index : len(responseMessage)-endIndex])
		// 	index += 16
		// } else {
		// 	res.Key = string(responseMessage[index : index+16])
		// 	index += 16
		// }

		res.KCV = string(responseMessage[len(responseMessage)-endIndex:])
	}
	return
}

func keyExtraction(message []byte, index int) (key string, endIndex int) {
	keyPrefix := string(message[index : index+1])
	if keyPrefix == "U" {
		key = string(message[index : index+32+1])
		index += 32 + 1
	} else if keyPrefix == "T" {
		key = string(message[index : index+48+1])
		index += 48 + 1
	} else if keyPrefix == "S" || keyPrefix == "R" {
		keysize, _ := strconv.Atoi(string(message[index+3 : index+6]))
		key = string(message[index : index+keysize+1])
		index = index + keysize + 1
	} else {
		key = string(message[index : index+16])
		index += 16
	}
	endIndex = index
	return key, endIndex
}

// Generate Key
func (repository *HsmRepository) A0(input models.GenerateKey) (res models.GenerateKeyResp, errCode string) {

	messageHeader := []byte("HEAD")
	commandCode := []byte("A0")
	mode := []byte(input.Mode)
	keyType := []byte(input.KeyType)
	keyScheme := []byte(input.KeyScheme)
	deriveKeyMode := []byte(input.DeriveKeyMode)
	dukptMasterKeyType := []byte(input.DUKPTMasterKeyType)
	dukptMasterKey := []byte(input.DUKPTMasterKey)
	ksn := []byte(input.KSN)
	zmkTmkBdk := []byte(input.ZmkTmkBdk)
	exportKeyScheme := []byte(input.ExportKeyScheme)
	keyusage := []byte(input.KeyUsage)
	algorithm := []byte(input.Algorithm)
	modeOfUse := []byte(input.ModeOfUse)
	kvn := []byte(input.KVN)
	exportability := []byte(input.Exportability)
	numberOfOptionalBlocks := []byte(input.NumberOfOptionalBlocks)

	commandMessage := Join(
		messageHeader,
		commandCode,
	)

	// Generate
	if input.Mode == "0" {
		commandMessage = Join(
			commandMessage,
			mode,
			keyType,
			keyScheme,
		)
		// Generate and Export
	} else if input.Mode == "1" {
		panic(input.Mode)
		// Derive
	} else if input.Mode == "A" {
		panic(input.Mode)
		// Derive and Export
	} else if input.Mode == "B" {
		commandMessage = Join(
			commandMessage,
			mode,
			keyType,
			keyScheme,
		)
		if input.DeriveKeyMode == "0" {
			commandMessage = Join(
				commandMessage,
				deriveKeyMode,
				dukptMasterKeyType,
				dukptMasterKey,
				ksn,
			)
		} else if input.DeriveKeyMode == "1" {
			panic(input.DeriveKeyMode)
		} else {
			panic(input.DeriveKeyMode)
		}
		// Missing ZMK/TMK Flag check

		commandMessage = Join(
			commandMessage,
			zmkTmkBdk,
		)
		// Missing Current BDK KSN

		commandMessage = Join(
			commandMessage,
			exportKeyScheme,
		)
		kbDelim := []byte("#")
		commandMessage = Join(
			commandMessage,
			kbDelim,
			keyusage,
			algorithm,
			modeOfUse,
			kvn,
			exportability,
			numberOfOptionalBlocks,
		)

	} else {
		panic(input.Mode)
	}

	responseMessage := repository.WriteRequest(commandMessage)

	errCode = string(responseMessage)[8:10]

	if errCode == "00" {
		index := 10
		res.Key, index = keyExtraction(responseMessage, index)

		if input.Mode == "1" || input.Mode == "B" {
			res.KeyExport, _ = keyExtraction(responseMessage, index)
		}
		res.KCV = string(responseMessage[len(responseMessage)-6:])

	}
	return
}

func (repository *HsmRepository) A8(input models.ExportKey) (res models.ExportKeyResp, errCode string) {

	messageHeader := []byte("HEAD")
	commandCode := []byte("A8")
	keyType := []byte(input.KeyType)
	zmkTmk := []byte(input.ZMK_TMK)
	key := []byte(input.Key)
	keyScheme := []byte(input.KeyScheme)

	commandMessage := Join(
		messageHeader,
		commandCode,
	)
	commandMessage = Join(
		commandMessage,
		keyType,
		zmkTmk,
		key,
		keyScheme,
	)

	responseMessage := repository.WriteRequest(commandMessage)

	errCode = string(responseMessage)[8:10]

	if errCode == "00" {
		index := 10
		if input.KeyScheme == "U" {
			res.Key = string(responseMessage[index : index+32+1])
			index += 32 + 1
		} else if input.KeyScheme == "T" {
			res.Key = string(responseMessage[index : index+48+1])
			index += 48 + 1
		} else if input.KeyScheme == "S" || input.KeyScheme == "R" {
			res.Key = string(responseMessage[index : len(responseMessage)-6])
			index += 16
		} else {
			res.Key = string(responseMessage[index : index+16])
			index += 16
		}

		res.KCV = string(responseMessage[len(responseMessage)-6:])

	}
	return
}
func (repository *HsmRepository) GI(input models.ImportKeyOrDataUnderRSAPubKey) (res models.ImportKeyOrDataUnderRSAPubKeyResp, errCode string) {

	messageHeader := []byte("HEAD")
	commandCode := []byte("GI")
	encryptionId := []byte(input.EncryptionId)
	padModeId := []byte(input.PadModeId)
	maskGenFunc := []byte(input.MaskGenFunc)
	//mgfHashFunc := []byte(input.MGFHashFunc)
	oaepEncodingParams := []byte(input.OAEPEncodingParam)
	oaepEncodingParamsDelim := []byte(";")
	keyType := []byte(input.KeyType)
	//pubKey := []byte(input.PubKey)
	dataBlock, _ := hex.DecodeString(input.DataBlock)
	dataBlockDelim := []byte(";")
	privateKeyFlag := []byte(input.PrivateKeyFlag)
	privateKey, _ := base64.StdEncoding.DecodeString(input.PrivateKey)
	desAesKeyDelim := []byte(";")
	importKeyType := []byte(input.ImportKeyType)
	keySchemeLMK := []byte(input.KeySchemeLMK)
	kcvType := []byte(input.KCVType)
	dataBlockTypeDelim := []byte("=")
	keyDataBlockType := []byte(input.KeyDataBlockType)
	//kcvLen := []byte(input.KcvLen)
	kbDelim := []byte("#")
	keyUsage := []byte(input.KeyUsage)
	modeOfUse := []byte(input.ModeOfUse)
	kvn := []byte(input.KVN)
	exportability := []byte(input.Exportability)
	numberOfOptionalBlocks := []byte(input.NumberOfOptionalBlocks)

	var commandMessage []byte

	// Message Header + CC
	commandMessage = Join(
		messageHeader,
		commandCode,
	)
	// Identifier of algorithm used to decrypt the key: 01: RSA
	commandMessage = Join(
		commandMessage,
		encryptionId,
	)

	// Identifier of the Pad Mode used in the encryption process
	switch input.PadModeId {
	case "01":
		commandMessage = Join(
			commandMessage,
			padModeId,
		)
	case "02":
		oaepEncodingParamsLen := []byte("00")
		commandMessage = Join(
			commandMessage,
			padModeId,
			maskGenFunc,
			oaepEncodingParamsLen,
			oaepEncodingParams,
			oaepEncodingParamsDelim,
		)
	default:
		log.Panicf("Wrong Pad Mod Id: %s", input.PadModeId)
	}
	// Key Type. FFFF for KB
	commandMessage = Join(
		commandMessage,
		keyType,
	)

	// Misc
	dataBlockLen := []byte("0256")
	privateKeyLen := []byte("FFFF")
	commandMessage = Join(
		commandMessage,
		dataBlockLen,
		dataBlock,
		dataBlockDelim,
		privateKeyFlag,
		privateKeyLen,
		privateKey,
	)
	// The following 4 fields are only required when importing a DES/AES Key
	commandMessage = Join(
		commandMessage,
		desAesKeyDelim,
		importKeyType,
		keySchemeLMK,
		kcvType,
	)
	commandMessage = Join(
		commandMessage,
		dataBlockTypeDelim,
		keyDataBlockType,
	)
	//commandMessage = Join(
	//	commandMessage,
	//	kcvLen,
	//)
	commandMessage = Join(
		commandMessage,
		kbDelim,
		keyUsage,
		modeOfUse,
		kvn,
		exportability,
		numberOfOptionalBlocks,
	)

	responseMessage := repository.WriteRequest(commandMessage)

	errCode = string(responseMessage[8:10])
	index := 10
	if input.KeyDataBlockType == "01" {
		switch input.ImportKeyType {
		case "0":
			endIndex := index + 16
			res.InitializationValue = string(responseMessage[index:endIndex])
			index = endIndex
		case "1":
			endIndex := index + 32
			res.InitializationValue = string(responseMessage[index:endIndex])
			index = endIndex
		}
	}
	res.Key, index = keyExtraction(responseMessage, index)
	res.KCV = string(responseMessage[index : index+6])

	return
}

func (repository *HsmRepository) EI(input models.GeneratePair) (res models.GeneratePairResp, errCode string) {

	messageHeader := []byte("HEAD")
	commandCode := []byte("EI")
	keyTypeIndicator := []byte(input.KeyTypeIndicator)
	keyLen := []byte(input.KeyLen)
	publicKeyEncoding := []byte(input.PublicKeyEncoding)
	publicExponentLen := []byte(input.PublicExponentLen)
	publicExponent := []byte(input.PublicExponent)
	lmkIdDelim := []byte("%")
	lmkId := []byte(input.LMKId)
	keyBlockDelim := []byte("#")
	kvn := []byte(input.KVN)
	numberOfOptionalBlocks := []byte(input.NumberOfOptionalBlocks)
	exportabilityDelim := []byte("&")
	exportability := []byte(input.Exportability)

	commandMessage := Join(
		messageHeader,
		commandCode,
	)
	commandMessage = Join(
		commandMessage,
		keyTypeIndicator,
		keyLen,
		publicKeyEncoding,
		publicExponentLen,
		publicExponent,
	)
	if input.LMKId != "" {
		commandMessage = Join(
			commandMessage,
			lmkIdDelim,
			lmkId,
		)
	}
	commandMessage = Join(
		commandMessage,
		keyBlockDelim,
		kvn,
		numberOfOptionalBlocks,
		exportabilityDelim,
		exportability,
	)

	responseMessage := repository.WriteRequest(commandMessage)

	fmt.Println(hex.Dump(responseMessage))

	errCode = string(responseMessage)[8:10]

	if errCode == "00" {
		var publicKey rsa.PublicKey
		rest, err := asn1.Unmarshal(responseMessage[10:], &publicKey)
		if err != nil {
			log.Panic(err.Error())
			return
		}
		pubBytes := x509.MarshalPKCS1PublicKey(&publicKey)
		res.PublicKey = base64.StdEncoding.EncodeToString(pubBytes)
		if bytes.Equal(rest[0:4], []byte("FFFF")) {
			res.PrivateKeyLen = 0000
			res.PrivateKey = base64.StdEncoding.EncodeToString(rest[4:])
		} else {
			res.PrivateKeyLen, _ = strconv.Atoi(string(rest[0:4]))
			res.PrivateKey = base64.StdEncoding.EncodeToString(rest[4 : 4+res.PrivateKeyLen])
		}
	}
	return
}
func (repository *HsmRepository) EM(input models.TranslatePrivate) (res models.TranslatePrivateResp, errCode string) {

	messageHeader := []byte("HEAD")
	commandCode := []byte("EM")
	privateKeyLen := []byte(input.PrivateKeyLen)
	privatekey, err := base64.StdEncoding.DecodeString(input.PrivateKey)
	if err != nil {
		panic(err)
	}
	if input.PrivateKeyLen == "" {
		privateKeyLen = []byte("0" + strconv.Itoa(len(privatekey)))
	}
	lmkIdDelim := []byte("%")
	lmkId := []byte(input.LMKId)
	kbDelim := []byte("#")
	kvn := []byte(input.KVN)
	numberOfOptionalBlocks := []byte(input.NumberOfOptionalBlocks)
	exportabilityDelim := []byte("&")
	exportability := []byte(input.Exportability)

	commandMessage := Join(
		messageHeader,
		commandCode,
	)
	commandMessage = Join(
		commandMessage,
		privateKeyLen,
		privatekey,
	)
	if input.LMKId != "" {
		commandMessage = Join(
			commandMessage,
			lmkIdDelim,
			lmkId,
		)
	}
	if input.KVN != "" {
		commandMessage = Join(
			commandMessage,
			kbDelim,
			kvn,
			numberOfOptionalBlocks,
			exportabilityDelim,
			exportability,
		)
	}

	responseMessage := repository.WriteRequest(commandMessage)

	errCode = string(responseMessage)[8:10]

	if errCode == "00" {
		index := 10
		var err error
		res.PrivateKeyLen, err = strconv.Atoi(string(responseMessage[index : index+4]))
		if err == nil {
			res.PrivateKey = base64.StdEncoding.EncodeToString(responseMessage[index+4 : index+4+res.PrivateKeyLen])
		} else {
			res.PrivateKey = base64.StdEncoding.EncodeToString(responseMessage[index+4:])
		}

	}
	return
}
