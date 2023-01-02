package models

type PinVer struct {
	Tpk        string `json:"tpk"`
	Pvk        string `json:"pvk"`
	Pinblock   string `json:"pinblock"`
	Pan        string `json:"pan"`
	Dectable   string `json:"dectable"`
	Pinvaldata string `json:"pinvaldata"`
	Pinoffset  string `json:"pinoffset"`
}
type VersionResponse struct {
	LmkCheck       string `json:"lmkCheck"`
	FirmwareNumber string `json:"firmwareNumber"`
}
type InpEnc struct {
	Key       string `json:"key"`
	Cleartext string `json:"cleartext"`
}
type InpDec struct {
	Key        string `json:"key"`
	Ciphertext string `json:"ciphertext"`
}

type InpToken struct {
	Profile string `json:"profile"`
	Data    string `json:"data"`
}

type InpDetoken struct {
	Profile string `json:"profile"`
	Token   string `json:"token"`
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
