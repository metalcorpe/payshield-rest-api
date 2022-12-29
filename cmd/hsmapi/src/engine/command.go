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
	"encoding/base64"
	"encoding/hex"
	"fmt"
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

func DA(json PinVer) (errcode string) {

	HsmLmkVariant := loadConfHSMVariant()

	messageheader := []byte("HEAD")
	commandcode := []byte("DA")
	tpk := []byte(json.Tpk)
	pvk := []byte(json.Pvk)
	pinlen := []byte("12")
	pinblock := []byte(json.Pinblock)
	pinblockformat := []byte("01")
	checklen := []byte("06")
	pan := []byte(json.Pan)
	dectable := []byte(json.Dectable)
	pinvaldata := []byte(json.Pinvaldata)
	pinoffset := []byte(json.Pinoffset)

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

func M0(json InpEnc) (errcode string, res string) {

	HsmLmkKeyblock := loadConfHSMKeyblock()

	//max buffer in payshield is 32KB
	data, _ := base64.URLEncoding.DecodeString(json.Cleartext)
	datapad := zeroPadding([]byte(data), 8)
	datalen := leftPad(string(datapad), "0", 4)

	messageheader := []byte("HEAD")
	commandcode := []byte("M0")
	modeflag := []byte("00")
	inputformatflag := []byte("0")
	outputformatflag := []byte("0")
	keytype := []byte("FFF")
	key := []byte(json.Key)
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

func M2(json InpDec) (errcode string, res string) {

	HsmLmkKeyblock := loadConfHSMKeyblock()

	//max buffer in payshield is 32KB
	data, _ := base64.URLEncoding.DecodeString(json.Ciphertext)
	datalen := leftPad(string(data), "0", 4)

	messageheader := []byte("HEAD")
	commandcode := []byte("M2")
	modeflag := []byte("00")
	inputformatflag := []byte("0")
	outputformatflag := []byte("0")
	keytype := []byte("FFF")
	key := []byte(json.Key)
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

func Token(json InpToken) (errcode string, res string) {

	HsmLmkKeyblock := loadConfHSMKeyblock()

	profile := json.Profile

	viper.SetConfigType("json")
	viper.AddConfigPath(".")
	viper.SetConfigName("profile.conf")

	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println("Load file config profile error")
	}

	ppl := viper.GetInt(profile + "." + "preservedPrefixLength")
	psl := viper.GetInt(profile + "." + "preservedSuffixLength")
	lenData := len(json.Data)

	if (ppl+psl > lenData) || (ppl+psl < 0) || (ppl < 0) || (psl < 0) || (ppl > lenData) || (psl > lenData) {
		errcode = "911"
		return
	}

	data := json.Data[ppl:(lenData - psl)]
	datappl := json.Data[:ppl]
	datapsl := json.Data[(lenData - psl):]

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

func Detoken(json InpDetoken) (errcode string, res string) {

	HsmLmkKeyblock := loadConfHSMKeyblock()

	profile := json.Profile

	viper.SetConfigType("json")
	viper.AddConfigPath(".")
	viper.SetConfigName("profile.conf")

	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println("Load file config profile error")
	}

	ppl := viper.GetInt(profile + "." + "preservedPrefixLength")
	psl := viper.GetInt(profile + "." + "preservedSuffixLength")
	lenData := len(json.Token)

	if (ppl+psl > lenData) || (ppl+psl < 0) || (ppl < 0) || (psl < 0) || (ppl > lenData) || (psl > lenData) {
		errcode = "911"
		return
	}

	data := json.Token[ppl:(lenData - psl)]
	datappl := json.Token[:ppl]
	datapsl := json.Token[(lenData - psl):]

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
	NumberofOptionalBlocks string          `json:"numberofoptionalblocks"`
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

func BW(json Migrate) (errcode string, res MigrateRes) {

	HsmLmkKeyblock := loadConfHSMVariant()

	messageheader := []byte("HEAD")
	commandcode := []byte("BW")
	keytypecode2d := []byte(json.KeyTypeCode2d)
	keylenflag := []byte("1")
	key := []byte(json.Key)
	delim1 := []byte(";")
	keytypecode := []byte(json.KeyTypeCode)
	delim2 := []byte("#")
	keyusage := []byte(json.KeyUsage)
	modeofuse := []byte(json.ModeOfUse)
	kvn := []byte(json.KVN)
	exportability := []byte(json.Exportability)
	optionalblocknumber := []byte(json.NumberofOptionalBlocks)
	delim3 := []byte("!")
	kcvflag := []byte(json.KCVReturnFlag)
	kcvtype := []byte(json.KCVType)

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
	if json.KCVReturnFlag == "1" {
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
		end_index := 0
		if json.KCVReturnFlag == "1" && json.KCVType == "0" {
			end_index = 16
		} else if json.KCVReturnFlag == "1" && json.KCVType == "1" {
			end_index = 6
		} else {
			end_index = 0
		}

		index := 10
		res.Key = string(responseMessage[index : len(responseMessage)-end_index])
		// if json.KeyScheme == "U" {
		// 	res.Key = string(responseMessage[index : index+32+1])
		// 	index += 32 + 1
		// } else if json.KeyScheme == "T" {
		// 	res.Key = string(responseMessage[index : index+48+1])
		// 	index += 48 + 1
		// } else if json.KeyScheme == "S" || json.KeyScheme == "R" {
		// 	res.Key = string(responseMessage[index : len(responseMessage)-end_index])
		// 	index += 16
		// } else {
		// 	res.Key = string(responseMessage[index : index+16])
		// 	index += 16
		// }

		res.KCV = string(responseMessage[len(responseMessage)-end_index:])
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
	NumberofOptionalBlocks string          `json:"numberofoptionalblocks"`
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

func A0(json GenerateKey) (errcode string, res GenerateKeyResp) {

	HsmLmkKeyblock := loadConfHSMKeyblock()

	messageheader := []byte("HEAD")
	commandcode := []byte("A0")
	mode := []byte(json.Mode)
	keytype := []byte(json.KeyType)
	keyscheme := []byte(json.KeyScheme)
	derivekeymode := []byte(json.DeriveKeyMode)
	dukptmasterkeytype := []byte(json.DUKPTMasterKeyType)
	dukptmasterkey := []byte(json.DUKPTMasterKey)
	ksn := []byte(json.KSN)
	zmkTmkBdk := []byte(json.ZmkTmkBdk)
	exportKeyScheme := []byte(json.ExportKeyScheme)
	keyusage := []byte(json.KeyUsage)
	algorithm := []byte(json.Algorithm)
	modeofuse := []byte(json.ModeofUse)
	kvn := []byte(json.KVN)
	exportability := []byte(json.Exportability)
	numberofoptionalblocks := []byte(json.NumberofOptionalBlocks)

	commandMessage := Join(
		messageheader,
		commandcode,
	)

	// Generate
	if json.Mode == "0" {
		commandMessage = Join(
			commandMessage,
			mode,
			keytype,
			keyscheme,
		)
		// Generate and Export
	} else if json.Mode == "1" {
		panic(json.Mode)
		// Derive
	} else if json.Mode == "A" {
		panic(json.Mode)
		// Derive and Export
	} else if json.Mode == "B" {
		commandMessage = Join(
			commandMessage,
			mode,
			keytype,
			keyscheme,
		)
		if json.DeriveKeyMode == "0" {
			commandMessage = Join(
				commandMessage,
				derivekeymode,
				dukptmasterkeytype,
				dukptmasterkey,
				ksn,
			)
		} else if json.DeriveKeyMode == "1" {
			panic(json.DeriveKeyMode)
		} else {
			panic(json.DeriveKeyMode)
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
		panic(json.Mode)
	}

	responseMessage := Connect(HsmLmkKeyblock, commandMessage)

	//log
	fmt.Println(hex.Dump(responseMessage))

	errcode = string(responseMessage)[8:10]

	if errcode == "00" {
		index := 10
		res.Key, index = keyExtraction(responseMessage, index)

		if json.Mode == "1" || json.Mode == "B" {
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
	NumberofOptionalBlocks string          `json:"numberofoptionalblocks"`
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

func A8(json ExportKey) (errcode string, res ExportKeyResp) {

	HsmLmkKeyblock := loadConfHSMVariant()

	messageheader := []byte("HEAD")
	commandcode := []byte("A8")
	keytype := []byte(json.KeyType)
	zmk_tmk := []byte(json.ZMK_TMK)
	key := []byte(json.Key)
	keyscheme := []byte(json.KeyScheme)

	commandMessage := Join(
		messageheader,
		commandcode,
	)
	commandMessage = Join(
		commandMessage,
		keytype,
		zmk_tmk,
		key,
		keyscheme,
	)

	responseMessage := Connect(HsmLmkKeyblock, commandMessage)

	//log
	fmt.Println(hex.Dump(responseMessage))

	errcode = string(responseMessage)[8:10]

	if errcode == "00" {
		index := 10
		if json.KeyScheme == "U" {
			res.Key = string(responseMessage[index : index+32+1])
			index += 32 + 1
		} else if json.KeyScheme == "T" {
			res.Key = string(responseMessage[index : index+48+1])
			index += 48 + 1
		} else if json.KeyScheme == "S" || json.KeyScheme == "R" {
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
	NumberofOptionalBlocks string          `json:"numberofoptionalblocks"`
	OptionalBlocks         []OptionalBlock `json:"optionalblocks"`
	Exportability          string          `json:"exportability"`
}
type GeneratePairResp struct {
	PublicKey     string `json:"publickey"`
	PrivateKeyLen int    `json:"privatekeylen"`
	PrivateKey    string `json:"privatekey"`
}

func EI(json GeneratePair) (errcode string, res GeneratePairResp) {

	HsmLmkKeyblock := loadConfHSMKeyblock()

	messageheader := []byte("HEAD")
	commandcode := []byte("EI")
	keytypeindicator := []byte(json.KeyTypeIndicator)
	keylen := []byte(json.KeyLen)
	publickeyencoding := []byte(json.PublicKeyEncoding)
	publicexponentlen := []byte(json.PublicExponentLen)
	publicexponent := []byte(json.PublicExponent)
	lmkid_delim := []byte("%")
	lmkid := []byte(json.LMKId)
	kvn := []byte(json.KVN)
	numberofoptionalblocks := []byte(json.NumberofOptionalBlocks)
	exportability := []byte(json.Exportability)

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
		lmkid,
	)
	if json.KVN != "" {
		commandMessage = Join(
			commandMessage,
			lmkid_delim,
			lmkid,
		)
	}
	commandMessage = Join(
		commandMessage,
		kvn,
		numberofoptionalblocks,
		exportability,
	)

	responseMessage := Connect(HsmLmkKeyblock, commandMessage)

	//log
	fmt.Println(hex.Dump(responseMessage))

	errcode = string(responseMessage)[8:10]
	// hex.DecodeString("\x02\x03\x01\x00\x01")

	// res.PrivateKey = string(asdf)
	if errcode == "00" {
		index := 10
		index_pub := bytes.Index(responseMessage, []byte("0656")) // TODO: THis is not the correct way
		res.PublicKey = base64.StdEncoding.EncodeToString(responseMessage[index:index_pub])
		res.PrivateKeyLen, _ = strconv.Atoi(string(responseMessage[index_pub : index_pub+4]))
		res.PrivateKey = base64.StdEncoding.EncodeToString(responseMessage[index_pub+4 : index_pub+4+656])

	}
	return
	// string(responseMessage[250:283])

	// "\xcbI\xe8\xc2<\x7f\xe6z\xa7w\u0096\xab⡃]\xbc\x98,\x11M\x1d\xb1\x02\x03\x01\x00\x01 0656"
	// "dR,*\tj\x1e\xb2\xe5\xe0\xe2d\x949\xa6\xd2\n\t\xe5%\xc8\xe2\xb9\x02\x03\x01\x00\x01 0656"
}

type TranslatePrivate struct {
	PrivateKeyLen          string          `json:"privatekeylen"`
	PrivateKey             string          `json:"privatekey"`
	LMKId                  string          `json:"lmkid"`
	KVN                    string          `json:"kvn"`
	NumberofOptionalBlocks string          `json:"numberofoptionalblocks"`
	OptionalBlocks         []OptionalBlock `json:"optionalblocks"`
	Exportability          string          `json:"exportability"`
}
type TranslatePrivateResp struct {
	PrivateKeyLen int    `json:"privatekeylen"`
	PrivateKey    string `json:"privatekey"`
}

func EM(json TranslatePrivate) (errcode string, res TranslatePrivateResp) {

	HsmLmkKeyblock := loadConfHSMVariant()

	messageheader := []byte("HEAD")
	commandcode := []byte("EM")
	privatekeylen := []byte(json.PrivateKeyLen)
	privatekey, err := base64.StdEncoding.DecodeString(json.PrivateKey)
	if err != nil {
		panic(err)
	}
	if json.PrivateKeyLen == "" {
		privatekeylen = []byte("0" + strconv.Itoa(len(privatekey)))
	}
	lmkid_delim := []byte("%")
	lmkid := []byte(json.LMKId)
	kb_delim := []byte("#")
	kvn := []byte(json.KVN)
	numberofoptionalblocks := []byte(json.NumberofOptionalBlocks)
	exportability_delim := []byte("&")
	exportability := []byte(json.Exportability)

	commandMessage := Join(
		messageheader,
		commandcode,
	)
	commandMessage = Join(
		commandMessage,
		privatekeylen,
		privatekey,
	)
	if json.LMKId != "" {
		commandMessage = Join(
			commandMessage,
			lmkid_delim,
			lmkid,
		)
	}
	if json.KVN != "" {
		commandMessage = Join(
			commandMessage,
			kb_delim,
			kvn,
			numberofoptionalblocks,
			exportability_delim,
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
