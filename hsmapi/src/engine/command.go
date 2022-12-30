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

	"github.com/spf13/viper"
)

type PinVer struct {
	Tpk        string `json:"tpk"`
	Pvk        string `json:"pvk"`
	Pinblock   string `json:"pinblock"`
	Pan        string `json:"pan"`
	Dectable   string `json:"dectable"`
	Pinvaldata string `json:"pinvaldata"`
	Pinoffset  string `json:"pinoffset"`
}

/* Verify PIN
{"tpk": "TEFF270C330101C2D6B23DF72EA8FFEBD0E491D62E2E3D151","pvk": "9B395FB9FE5F07DA","pinblock": "EEC12744E8F13E16","pan": "923000000431","dectable": "3456789012345678","pinvaldata": "9230000N0431","pinoffset": "330309FFFFFF"}
*/

func DA(input PinVer) (errcode string) {

	HsmLmkVariant := loadConfHSMVariant()

	messageheader := []byte("HEAD")
	commandcode := []byte("DA")
	tpk := []byte(input.Tpk)
	pvk := []byte(input.Pvk)
	pinlen := []byte("12")
	pinblock := []byte(input.Pinblock)
	pinblockformat := []byte("01")
	checklen := []byte("06")
	pan := []byte(input.Pan)
	dectable := []byte(input.Dectable)
	pinvaldata := []byte(input.Pinvaldata)
	pinoffset := []byte(input.Pinoffset)

	commandMessage := Join(
		messageheader,
		commandcode,
		tpk,
		pvk,
		pinlen,
		pinblock,
		pinblockformat,
		checklen,
		pan,
		dectable,
		pinvaldata,
		pinoffset,
	)

	responseMessage := Connect(HsmLmkVariant, commandMessage)

	//log
	fmt.Println(hex.Dump(responseMessage))

	errcode = string(responseMessage)[8:10]

	if errcode == "00" {
		errcode = string(responseMessage)[8:]
	}
	if errcode != "00" {
		errcode = string(responseMessage)[8:]
	}
	return
}

type InpEnc struct {
	Key       string `json:"key"`
	Cleartext string `json:"cleartext"`
}

/* Encrypt
{"key": "S1012822AN00S000153767C37E3DD24D17D98C9EB003C8BDAAEAABD6D4E62C1288358E24E910A49D1A75B157B813DA6903BDC1A5B9EA57FA0D01F4A0E2F9544E5", "cleartext": "aGVsbG8gd29ybGQhISEAAA=="}
*/

func M0(input InpEnc) (errcode string, res string) {

	HsmLmkKeyblock := loadConfHSMKeyblock()

	//max buffer in payshield is 32KB
	data, _ := base64.URLEncoding.DecodeString(input.Cleartext)
	datapad := zeroPadding([]byte(data), 8)
	datalen := leftPad(string(datapad), "0", 4)

	messageheader := []byte("HEAD")
	commandcode := []byte("M0")
	modeflag := []byte("00")
	inputformatflag := []byte("0")
	outputformatflag := []byte("0")
	keytype := []byte("FFF")
	key := []byte(input.Key)
	messagelen := []byte(datalen)
	message := datapad

	commandMessage := Join(
		messageheader,
		commandcode,
		modeflag,
		inputformatflag,
		outputformatflag,
		keytype,
		key,
		messagelen,
		message,
	)

	responseMessage := Connect(HsmLmkKeyblock, commandMessage)

	//log
	fmt.Println(hex.Dump(responseMessage))

	errcode = string(responseMessage)[8:10]

	if errcode == "00" {
		res = base64.URLEncoding.EncodeToString([]byte(string(responseMessage)[14:]))
	}
	if errcode != "00" {
		res = ""
	}
	return

}

type InpDec struct {
	Key        string `json:"key"`
	Ciphertext string `json:"ciphertext"`
}

/* Decrypt
{"key":"S1012822AN00S000153767C37E3DD24D17D98C9EB003C8BDAAEAABD6D4E62C1288358E24E910A49D1A75B157B813DA6903BDC1A5B9EA57FA0D01F4A0E2F9544E5","ciphertext":"7ibaZ4PV0M937lTsupfhDQ=="}
*/

func M2(input InpDec) (errcode string, res string) {

	HsmLmkKeyblock := loadConfHSMKeyblock()

	//max buffer in payshield is 32KB
	data, _ := base64.URLEncoding.DecodeString(input.Ciphertext)
	datalen := leftPad(string(data), "0", 4)

	messageheader := []byte("HEAD")
	commandcode := []byte("M2")
	modeflag := []byte("00")
	inputformatflag := []byte("0")
	outputformatflag := []byte("0")
	keytype := []byte("FFF")
	key := []byte(input.Key)
	messagelen := []byte(datalen)
	message := data

	commandMessage := Join(
		messageheader,
		commandcode,
		modeflag,
		inputformatflag,
		outputformatflag,
		keytype,
		key,
		messagelen,
		message,
	)

	responseMessage := Connect(HsmLmkKeyblock, commandMessage)

	//log
	fmt.Println(hex.Dump(responseMessage))

	errcode = string(responseMessage)[8:10]

	if errcode == "00" {
		res = base64.URLEncoding.EncodeToString([]byte(string(responseMessage)[14:]))
	}
	if errcode != "00" {
		res = ""
	}
	return
}

type InpToken struct {
	Profile string `json:"profile"`
	Data    string `json:"data"`
}

/* Tokenize
{"profile":"creditcard","data": "9453677629008564"}
*/

func Token(input InpToken) (errcode string, res string) {

	HsmLmkKeyblock := loadConfHSMKeyblock()

	profile := input.Profile

	viper.SetConfigType("json")
	viper.AddConfigPath(".")
	viper.SetConfigName("profile.conf")

	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println("Load file config profile error")
	}

	ppl := viper.GetInt(profile + "." + "preservedPrefixLength")
	psl := viper.GetInt(profile + "." + "preservedSuffixLength")
	lenData := len(input.Data)

	if (ppl+psl > lenData) || (ppl+psl < 0) || (ppl < 0) || (psl < 0) || (ppl > lenData) || (psl > lenData) {
		errcode = "911"
		return
	}

	data := input.Data[ppl:(lenData - psl)]
	datappl := input.Data[:ppl]
	datapsl := input.Data[(lenData - psl):]

	messageheader := []byte("EFF1")
	commandcode := []byte("M0")
	modeflag := []byte("11")
	fperadixflag := []byte("U")
	fperadixvalue := []byte("00010")
	fpetweak, _ := hex.DecodeString(tweak(viper.GetString(profile + "." + "keyName")))
	fpetweaklen := []byte(fmt.Sprintf("%04X", len(string(fpetweak))))
	inputformatflag := []byte("0")
	outputformatflag := []byte("0")
	keytype := []byte("FFF")
	key := []byte(viper.GetString(profile + "." + "key"))
	message, _ := hex.DecodeString(dectohex(data))
	messagelen := []byte(fmt.Sprintf("%04X", len(message)))

	commandMessage := Join(
		messageheader,
		commandcode,
		modeflag,
		fperadixflag,
		fperadixvalue,
		fpetweaklen,
		fpetweak,
		inputformatflag,
		outputformatflag,
		keytype,
		key,
		messagelen,
		message,
	)

	responseMessage := Connect(HsmLmkKeyblock, commandMessage)

	//log
	fmt.Println(hex.Dump(responseMessage))

	errcode = string(responseMessage)[8:10]

	if errcode == "00" {
		res = datappl + hextodec(hex.EncodeToString([]byte(string(responseMessage)[14:]))) + datapsl
	}
	if errcode != "00" {
		res = ""
	}
	return

}

type InpDetoken struct {
	Profile string `json:"profile"`
	Token   string `json:"token"`
}

/* Detokenize
{"profile":"creditcard","token": "6288248669598239"}
*/

func Detoken(input InpDetoken) (errcode string, res string) {

	HsmLmkKeyblock := loadConfHSMKeyblock()

	profile := input.Profile

	viper.SetConfigType("json")
	viper.AddConfigPath(".")
	viper.SetConfigName("profile.conf")

	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println("Load file config profile error")
	}

	ppl := viper.GetInt(profile + "." + "preservedPrefixLength")
	psl := viper.GetInt(profile + "." + "preservedSuffixLength")
	lenData := len(input.Token)

	if (ppl+psl > lenData) || (ppl+psl < 0) || (ppl < 0) || (psl < 0) || (ppl > lenData) || (psl > lenData) {
		errcode = "911"
		return
	}

	data := input.Token[ppl:(lenData - psl)]
	datappl := input.Token[:ppl]
	datapsl := input.Token[(lenData - psl):]

	messageheader := []byte("EFF1")
	commandcode := []byte("M2")
	modeflag := []byte("11")
	fperadixflag := []byte("U")
	fperadixvalue := []byte("00010")
	fpetweak, _ := hex.DecodeString(tweak(viper.GetString(profile + "." + "keyName")))
	fpetweaklen := []byte(fmt.Sprintf("%04X", len(string(fpetweak))))
	inputformatflag := []byte("0")
	outputformatflag := []byte("0")
	keytype := []byte("FFF")
	key := []byte(viper.GetString(profile + "." + "key"))
	message, _ := hex.DecodeString(dectohex(data))
	messagelen := []byte(fmt.Sprintf("%04X", len(message)))

	commandMessage := Join(
		messageheader,
		commandcode,
		modeflag,
		fperadixflag,
		fperadixvalue,
		fpetweaklen,
		fpetweak,
		inputformatflag,
		outputformatflag,
		keytype,
		key,
		messagelen,
		message,
	)

	responseMessage := Connect(HsmLmkKeyblock, commandMessage)

	//log
	fmt.Println(hex.Dump(responseMessage))

	errcode = string(responseMessage)[8:10]

	if errcode == "00" {
		res = datappl + hextodec(hex.EncodeToString([]byte(string(responseMessage)[14:]))) + datapsl
	}
	if errcode != "00" {
		res = ""
	}
	return

}

/* Check Version
 */

func NC() (errcode string, lmk string, firmware string) {

	HsmLmkVariant := loadConfHSMVariant()

	messageheader := []byte("HEAD")
	commandcode := []byte("NC")

	commandMessage := Join(
		messageheader,
		commandcode,
	)

	responseMessage := Connect(HsmLmkVariant, commandMessage)

	//log
	fmt.Println(hex.Dump(responseMessage))

	errcode = string(responseMessage)[8:10]

	if errcode == "00" {
		lmk = string(responseMessage)[10 : 10+16]
		firmware = string(responseMessage)[26:]
	}
	if errcode != "00" {
		lmk = ""
		firmware = ""
	}

	return

}

type Migrate struct {
	KeyTypeCode2d          string          `json:"keytypecode2d"`
	KeyLenFlag             string          `json:"keylenflag"`
	Key                    string          `json:"key"`
	KeyTypeCode            string          `json:"keytypecode"`
	KeyScheme              string          `json:"keyscheme"`
	LMKId                  string          `json:"lmkid"`
	KeyUsage               string          `json:"keyusage"`
	ModeOfUse              string          `json:"modeofuse"`
	KVN                    string          `json:"kvn"`
	Exportability          string          `json:"exportability"`
	NumberOfOptionalBlocks string          `json:"numberofoptionalblocks"`
	OptionalBlocks         []OptionalBlock `json:"optionalblocks"`
	KCVReturnFlag          string          `json:"kcvreturnflag"`
	KCVType                string          `json:"kcvtype"`
}

type MigrateRes struct {
	Key string `json:"key"`
	KCV string `json:"kcv"`
}

/* Decrypt
{"key":"S1012822AN00S000153767C37E3DD24D17D98C9EB003C8BDAAEAABD6D4E62C1288358E24E910A49D1A75B157B813DA6903BDC1A5B9EA57FA0D01F4A0E2F9544E5","ciphertext":"7ibaZ4PV0M937lTsupfhDQ=="}
*/

func BW(input Migrate) (errcode string, res MigrateRes) {

	HsmLmkKeyblock := loadConfHSMVariant()

	messageheader := []byte("HEAD")
	commandcode := []byte("BW")
	keytypecode2d := []byte(input.KeyTypeCode2d)
	keylenflag := []byte("1")
	key := []byte(input.Key)
	delim1 := []byte(";")
	keytypecode := []byte(input.KeyTypeCode)
	delim2 := []byte("#")
	keyusage := []byte(input.KeyUsage)
	modeofuse := []byte(input.ModeOfUse)
	kvn := []byte(input.KVN)
	exportability := []byte(input.Exportability)
	optionalblocknumber := []byte(input.NumberOfOptionalBlocks)
	delim3 := []byte("!")
	kcvflag := []byte(input.KCVReturnFlag)
	kcvtype := []byte(input.KCVType)

	commandMessage := Join(
		messageheader,
		commandcode,
		keytypecode2d,
		keylenflag,
		key,
		delim1,
		keytypecode,
		delim2,
		keyusage,
		modeofuse,
		kvn,
		exportability,
		optionalblocknumber,
	)
	if input.KCVReturnFlag == "1" {
		commandMessage = Join(
			commandMessage,
			delim3,
			kcvflag,
			kcvtype,
		)
	}

	responseMessage := Connect(HsmLmkKeyblock, commandMessage)

	//log
	fmt.Println(hex.Dump(responseMessage))

	errcode = string(responseMessage)[8:10]

	if errcode == "00" {
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

type OptionalBlock struct {
	OptionalBlockIdentifier string `json:"optionalblockidentifier"`
	OptionalBlockLenght     string `json:"optionalblocklength"`
	ModifiedExportValue     string `json:"modifiedexportvalue"`
	KeyBlockVersionID       string `json:"keyblockversionid"`
}
type GenerateKey struct {
	Mode                   string          `json:"mode"`
	KeyType                string          `json:"keytype"`
	KeyScheme              string          `json:"keyscheme"`
	DeriveKeyMode          string          `json:"derivekeymode"`
	DUKPTMasterKeyType     string          `json:"dukptmasterkeytype"`
	DUKPTMasterKey         string          `json:"dukptmasterkey"`
	KSN                    string          `json:"ksn"`
	ZKAMasterKeyType       string          `json:"zkamasterkeytype"`
	ZKAMasterKey           string          `json:"zkamasterkey"`
	ZKAOption              string          `json:"zkaoption"`
	ZKARNDI                string          `json:"zkarndi"`
	ZMK_TMKFlag            string          `json:"zmk_tmkflag"`
	ZmkTmkBdk              string          `json:"zmkTmkBdk"`
	IKSN                   string          `json:"iksn"`
	ExportKeyScheme        string          `json:"exportKeyScheme"`
	AtallaVariant          string          `json:"atallavariant"`
	LMKId                  string          `json:"lmkid"`
	KeyUsage               string          `json:"keyusage"`
	Algorithm              string          `json:"algorithm"`
	ModeofUse              string          `json:"modeofuse"`
	KVN                    string          `json:"kvn"`
	Exportability          string          `json:"exportability"`
	NumberOfOptionalBlocks string          `json:"numberofoptionalblocks"`
	OptionalBlocks         []OptionalBlock `json:"optionalblocks"`
}
type GenerateKeyResp struct {
	Key       string `json:"key"`
	KeyExport string `json:"keyexport"`
	KCV       string `json:"kcv"`
	ZKARNDI   string `json:"zkarndi"`
}

/* Decrypt
{"key":"S1012822AN00S000153767C37E3DD24D17D98C9EB003C8BDAAEAABD6D4E62C1288358E24E910A49D1A75B157B813DA6903BDC1A5B9EA57FA0D01F4A0E2F9544E5","ciphertext":"7ibaZ4PV0M937lTsupfhDQ=="}
*/

func keyExtraction(message []byte, index int) (key string, rindex int) {
	keyPrefex := string(message[index : index+1])
	if keyPrefex == "U" {
		key = string(message[index : index+32+1])
		index += 32 + 1
	} else if keyPrefex == "T" {
		key = string(message[index : index+48+1])
		index += 48 + 1
	} else if keyPrefex == "S" || keyPrefex == "R" {
		keysize, _ := strconv.Atoi(string(message[index+3 : index+6]))
		key = string(message[index : index+keysize+1])
		index = index + keysize + 1
	} else {
		key = string(message[index : index+16])
		index += 16
	}
	rindex = index
	return key, rindex
}

func A0(input GenerateKey) (errcode string, res GenerateKeyResp) {

	HsmLmkKeyblock := loadConfHSMKeyblock()

	messageheader := []byte("HEAD")
	commandcode := []byte("A0")
	mode := []byte(input.Mode)
	keytype := []byte(input.KeyType)
	keyscheme := []byte(input.KeyScheme)
	derivekeymode := []byte(input.DeriveKeyMode)
	dukptmasterkeytype := []byte(input.DUKPTMasterKeyType)
	dukptmasterkey := []byte(input.DUKPTMasterKey)
	ksn := []byte(input.KSN)
	zmkTmkBdk := []byte(input.ZmkTmkBdk)
	exportKeyScheme := []byte(input.ExportKeyScheme)
	keyusage := []byte(input.KeyUsage)
	algorithm := []byte(input.Algorithm)
	modeofuse := []byte(input.ModeofUse)
	kvn := []byte(input.KVN)
	exportability := []byte(input.Exportability)
	numberofoptionalblocks := []byte(input.NumberOfOptionalBlocks)

	commandMessage := Join(
		messageheader,
		commandcode,
	)

	// Generate
	if input.Mode == "0" {
		commandMessage = Join(
			commandMessage,
			mode,
			keytype,
			keyscheme,
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
			keytype,
			keyscheme,
		)
		if input.DeriveKeyMode == "0" {
			commandMessage = Join(
				commandMessage,
				derivekeymode,
				dukptmasterkeytype,
				dukptmasterkey,
				ksn,
			)
		} else if input.DeriveKeyMode == "1" {
			panic(input.DeriveKeyMode)
		} else {
			panic(input.DeriveKeyMode)
		}
		// Mising ZMK/TMK Flag check

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
			modeofuse,
			kvn,
			exportability,
			numberofoptionalblocks,
		)

	} else {
		panic(input.Mode)
	}

	responseMessage := Connect(HsmLmkKeyblock, commandMessage)

	//log
	fmt.Println(hex.Dump(responseMessage))

	errcode = string(responseMessage)[8:10]

	if errcode == "00" {
		index := 10
		res.Key, index = keyExtraction(responseMessage, index)

		if input.Mode == "1" || input.Mode == "B" {
			res.KeyExport, index = keyExtraction(responseMessage, index)
		}
		res.KCV = string(responseMessage[len(responseMessage)-6:])

	}
	return
}

type ExportKey struct {
	KeyType                string          `json:"keytype"`
	ZMK_TMKFlag            string          `json:"zmk_tmkflag"`
	ZMK_TMK                string          `json:"zmk_tmk"`
	Key                    string          `json:"key"`
	KeyScheme              string          `json:"keyscheme"`
	IV                     string          `json:"iv"`
	AtallaVariant          string          `json:"atallavariant"`
	LMKId                  string          `json:"lmkid"`
	Exportability          string          `json:"exportability"`
	NumberOfOptionalBlocks string          `json:"numberofoptionalblocks"`
	OptionalBlocks         []OptionalBlock `json:"optionalblocks"`
	KVN                    string          `json:"kvn"`

	// ZKAOption string `json:"zkaoption"`
	// ZKARNDI   string `json:"zkarndi"`
	// IKSN      string `json:"iksn"`
	// KeyUsage  string `json:"keyusage"`
	// Algorithm string `json:"algorithm"`
	// ModeofUse string `json:"modeofuse"`
}
type ExportKeyResp struct {
	Key string `json:"key"`
	KCV string `json:"kcv"`
}

func A8(input ExportKey) (errcode string, res ExportKeyResp) {

	HsmLmkKeyblock := loadConfHSMVariant()

	messageheader := []byte("HEAD")
	commandcode := []byte("A8")
	keytype := []byte(input.KeyType)
	zmkTmk := []byte(input.ZMK_TMK)
	key := []byte(input.Key)
	keyscheme := []byte(input.KeyScheme)

	commandMessage := Join(
		messageheader,
		commandcode,
	)
	commandMessage = Join(
		commandMessage,
		keytype,
		zmkTmk,
		key,
		keyscheme,
	)

	responseMessage := Connect(HsmLmkKeyblock, commandMessage)

	//log
	fmt.Println(hex.Dump(responseMessage))

	errcode = string(responseMessage)[8:10]

	if errcode == "00" {
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

type GeneratePair struct {
	KeyTypeIndicator       string          `json:"keytypeindicator"`
	KeyLen                 string          `json:"keylen"`
	PublicKeyEncoding      string          `json:"publickeyencoding"`
	PublicExponentLen      string          `json:"publicexponentlen"`
	PublicExponent         string          `json:"publicexponent"`
	LMKId                  string          `json:"lmkid"`
	KVN                    string          `json:"kvn"`
	NumberOfOptionalBlocks string          `json:"numberofoptionalblocks"`
	OptionalBlocks         []OptionalBlock `json:"optionalblocks"`
	Exportability          string          `json:"exportability"`
}
type GeneratePairResp struct {
	PublicKey     string `json:"publickey"`
	PrivateKeyLen int    `json:"privatekeylen"`
	PrivateKey    string `json:"privatekey"`
}

func EI(input GeneratePair) (errcode string, res GeneratePairResp) {

	HsmLmkKeyblock := loadConfHSMKeyblock()

	messageheader := []byte("HEAD")
	commandcode := []byte("EI")
	keytypeindicator := []byte(input.KeyTypeIndicator)
	keylen := []byte(input.KeyLen)
	publickeyencoding := []byte(input.PublicKeyEncoding)
	publicexponentlen := []byte(input.PublicExponentLen)
	publicexponent := []byte(input.PublicExponent)
	lmkidDelim := []byte("%")
	lmkid := []byte(input.LMKId)
	keyblockDelim := []byte("#")
	kvn := []byte(input.KVN)
	numberofoptionalblocks := []byte(input.NumberOfOptionalBlocks)
	exportabilityDelim := []byte("&")
	exportability := []byte(input.Exportability)

	commandMessage := Join(
		messageheader,
		commandcode,
	)
	commandMessage = Join(
		commandMessage,
		keytypeindicator,
		keylen,
		publickeyencoding,
		publicexponentlen,
		publicexponent,
	)
	if input.LMKId != "" {
		commandMessage = Join(
			commandMessage,
			lmkidDelim,
			lmkid,
		)
	}
	commandMessage = Join(
		commandMessage,
		keyblockDelim,
		kvn,
		numberofoptionalblocks,
		exportabilityDelim,
		exportability,
	)

	responseMessage := Connect(HsmLmkKeyblock, commandMessage)

	fmt.Println(hex.Dump(responseMessage))

	errcode = string(responseMessage)[8:10]

	if errcode == "00" {
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

type ImportKeyOrDataUnderRSAPubKey struct {
	EncryptionId string `json:"encryptionId"`
	PadModeId    string `json:"padModeId"`
	MaskGenFunc  string `json:"maskGenFunc"`
	MGFHashFunc  string `json:"mgfHashFunc"`
	//OAEPEncodingParamLen string `json:"oaepEncodingParamLen"`
	OAEPEncodingParam string `json:"oaepEncodingParam"`
	KeyType           string `json:"keyType"`
	//SignatureHashId   string `json:"signatureHashId"`
	//SignatureId       string `json:"signatureId"`
	//SignaturePadMode  string `json:"signaturePadMode"`
	//EncrKeyOffset     string `json:"encrKeyOffset"`
	//EncrKeyLen        string `json:"encrKeyLen"`
	//SigLen            string `json:"sigLen"`
	//Signature         string `json:"signature"`
	//PubKey                 string          `json:"pubKey"`
	DataBlock              string          `json:"dataBlock"`
	PrivateKeyFlag         string          `json:"privateKeyFlag"`
	PrivateKeyLen          string          `json:"privateKeyLen"`
	PrivateKey             string          `json:"privateKey"`
	ImportKeyType          string          `json:"importKeyType"`
	KeySchemeLMK           string          `json:"keySchemeLMK"`
	KCVType                string          `json:"kcvType"`
	KeyDataBlockType       string          `json:"keyDataBlockType"`
	KcvLen                 string          `json:"kcvLen"`
	LMKId                  string          `json:"lmkid"`
	KeyUsage               string          `json:"keyUsage"`
	ModeOfUse              string          `json:"modeOfUse"`
	KVN                    string          `json:"kvn"`
	Exportability          string          `json:"exportability"`
	NumberOfOptionalBlocks string          `json:"numberofoptionalblocks"`
	OptionalBlocks         []OptionalBlock `json:"optionalblocks"`
}
type ImportKeyOrDataUnderRSAPubKeyResp struct {
	InitializationValue string `json:"initializationValue"`
	Key                 string `json:"key"`
	KCV                 string `json:"kcv"`
}

func GI(input ImportKeyOrDataUnderRSAPubKey) (errcode string, res ImportKeyOrDataUnderRSAPubKeyResp) {
	HsmLmkKeyblock := loadConfHSMKeyblock()

	messageheader := []byte("HEAD")
	commandcode := []byte("GI")
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
		messageheader,
		commandcode,
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

	responseMessage := Connect(HsmLmkKeyblock, commandMessage)

	//log
	fmt.Println(hex.Dump(responseMessage))

	errcode = string(responseMessage[8:10])
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

type TranslatePrivate struct {
	PrivateKeyLen          string          `json:"privatekeylen"`
	PrivateKey             string          `json:"privatekey"`
	LMKId                  string          `json:"lmkid"`
	KVN                    string          `json:"kvn"`
	NumberOfOptionalBlocks string          `json:"numberofoptionalblocks"`
	OptionalBlocks         []OptionalBlock `json:"optionalblocks"`
	Exportability          string          `json:"exportability"`
}
type TranslatePrivateResp struct {
	PrivateKeyLen int    `json:"privatekeylen"`
	PrivateKey    string `json:"privatekey"`
}

func EM(input TranslatePrivate) (errcode string, res TranslatePrivateResp) {

	HsmLmkKeyblock := loadConfHSMVariant()

	messageheader := []byte("HEAD")
	commandcode := []byte("EM")
	privatekeylen := []byte(input.PrivateKeyLen)
	privatekey, err := base64.StdEncoding.DecodeString(input.PrivateKey)
	if err != nil {
		panic(err)
	}
	if input.PrivateKeyLen == "" {
		privatekeylen = []byte("0" + strconv.Itoa(len(privatekey)))
	}
	lmkidDelim := []byte("%")
	lmkid := []byte(input.LMKId)
	kbDelim := []byte("#")
	kvn := []byte(input.KVN)
	numberofoptionalblocks := []byte(input.NumberOfOptionalBlocks)
	exportabilityDelim := []byte("&")
	exportability := []byte(input.Exportability)

	commandMessage := Join(
		messageheader,
		commandcode,
	)
	commandMessage = Join(
		commandMessage,
		privatekeylen,
		privatekey,
	)
	if input.LMKId != "" {
		commandMessage = Join(
			commandMessage,
			lmkidDelim,
			lmkid,
		)
	}
	if input.KVN != "" {
		commandMessage = Join(
			commandMessage,
			kbDelim,
			kvn,
			numberofoptionalblocks,
			exportabilityDelim,
			exportability,
		)
	}

	responseMessage := Connect(HsmLmkKeyblock, commandMessage)

	//log
	fmt.Println(hex.Dump(responseMessage))

	errcode = string(responseMessage)[8:10]

	if errcode == "00" {
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
