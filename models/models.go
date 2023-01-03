package models

type Diagnostics struct {
	LMKType string `json:"lmkType"`
}
type DiagnosticsRes struct {
	LMKCheck       string `json:"lmkcheck"`
	FirmwareNumber string `json:"firmwarenumber"`
}

type PinVer struct {
	Tpk                 string `json:"tpk"`
	Pvk                 string `json:"pvk"`
	PinBlock            string `json:"pinBlock"`
	Pan                 string `json:"pan"`
	DecimalizationTable string `json:"decimalizationTable"`
	PinValidationData   string `json:"pinValidationData"`
	PinOffset           string `json:"pinOffset"`
}
type InpEnc struct {
	Key       string `json:"key"`
	ClearText string `json:"clearText"`
}
type InpDec struct {
	Key        string `json:"key"`
	CipherText string `json:"cipherText"`
}

type Migrate struct {
	KeyTypeCode2d          string          `json:"keyTypeCode2d"`
	KeyLenFlag             string          `json:"keyLenFlag"`
	Key                    string          `json:"key"`
	KeyTypeCode            string          `json:"keyTypeCode"`
	KeyScheme              string          `json:"keyScheme"`
	LMKId                  string          `json:"lmkId"`
	KeyUsage               string          `json:"keyUsage"`
	ModeOfUse              string          `json:"modeOfUse"`
	KVN                    string          `json:"kvn"`
	Exportability          string          `json:"exportability"`
	NumberOfOptionalBlocks string          `json:"NumberOfOptionalBlocks"`
	OptionalBlocks         []OptionalBlock `json:"optionalBlocks"`
	KCVReturnFlag          string          `json:"kcvReturnFlag"`
	KCVType                string          `json:"kcvType"`
}

type MigrateRes struct {
	Key string `json:"key"`
	KCV string `json:"kcv"`
}
type OptionalBlock struct {
	OptionalBlockIdentifier string `json:"optionalBlockIdentifier"`
	OptionalBlockLenght     string `json:"optionalBlockLength"`
	ModifiedExportValue     string `json:"modifiedExportValue"`
	KeyBlockVersionID       string `json:"keyBlockVersionId"`
}
type GenerateKey struct {
	Mode                   string          `json:"mode"`
	KeyType                string          `json:"keyType"`
	KeyScheme              string          `json:"keyScheme"`
	DeriveKeyMode          string          `json:"deriveKeyMode"`
	DUKPTMasterKeyType     string          `json:"dukptMasterKeyType"`
	DUKPTMasterKey         string          `json:"dukptMasterKey"`
	KSN                    string          `json:"ksn"`
	ZkaMasterKeyType       string          `json:"zkaMasterKeyType"`
	ZkaMasterKey           string          `json:"zkaMasterKey"`
	ZkaOption              string          `json:"zkaOption"`
	ZkaRndi                string          `json:"zkaRndi"`
	ZmkTmkFlag             string          `json:"zmkTmkFlag"`
	ZmkTmkBdk              string          `json:"zmkTmkBdk"`
	IKSN                   string          `json:"iksn"`
	ExportKeyScheme        string          `json:"exportKeyScheme"`
	AtallaVariant          string          `json:"atallaVariant"`
	LMKId                  string          `json:"lmkId"`
	KeyUsage               string          `json:"keyUsage"`
	Algorithm              string          `json:"algorithm"`
	ModeOfUse              string          `json:"modeOfUse"`
	KVN                    string          `json:"kvn"`
	Exportability          string          `json:"exportability"`
	NumberOfOptionalBlocks string          `json:"NumberOfOptionalBlocks"`
	OptionalBlocks         []OptionalBlock `json:"optionalBlocks"`
}
type GenerateKeyResp struct {
	Key       string `json:"key"`
	KeyExport string `json:"keyexport"`
	KCV       string `json:"kcv"`
	ZkaRndi   string `json:"zkaRndi"`
}

type ExportKey struct {
	KeyType                string          `json:"keyType"`
	ZmkTmkFlag             string          `json:"zmkTmkFlag"`
	ZMK_TMK                string          `json:"zmk_tmk"`
	Key                    string          `json:"key"`
	KeyScheme              string          `json:"keyScheme"`
	IV                     string          `json:"iv"`
	AtallaVariant          string          `json:"atallaVariant"`
	LMKId                  string          `json:"lmkId"`
	Exportability          string          `json:"exportability"`
	NumberOfOptionalBlocks string          `json:"NumberOfOptionalBlocks"`
	OptionalBlocks         []OptionalBlock `json:"optionalBlocks"`
	KVN                    string          `json:"kvn"`

	// ZkaOption string `json:"zkaOption"`
	// ZkaRndi   string `json:"zkaRndi"`
	// IKSN      string `json:"iksn"`
	// KeyUsage  string `json:"keyUsage"`
	// Algorithm string `json:"algorithm"`
	// ModeOfUse string `json:"modeOfUse"`
}
type ExportKeyResp struct {
	Key string `json:"key"`
	KCV string `json:"kcv"`
}

type GeneratePair struct {
	KeyTypeIndicator       string          `json:"keyTypeIndicator"`
	KeyLen                 string          `json:"keyLen"`
	PublicKeyEncoding      string          `json:"publicKeyEncoding"`
	PublicExponentLen      string          `json:"publicExponentLen"`
	PublicExponent         string          `json:"publicExponent"`
	LMKId                  string          `json:"lmkId"`
	KVN                    string          `json:"kvn"`
	NumberOfOptionalBlocks string          `json:"NumberOfOptionalBlocks"`
	OptionalBlocks         []OptionalBlock `json:"optionalBlocks"`
	Exportability          string          `json:"exportability"`
}
type GeneratePairResp struct {
	PublicKey     string `json:"publicKey"`
	PrivateKeyLen int    `json:"privateKeyLen"`
	PrivateKey    string `json:"privateKey"`
}

type TranslatePrivate struct {
	PrivateKeyLen          string          `json:"privateKeyLen"`
	PrivateKey             string          `json:"privateKey"`
	LMKId                  string          `json:"lmkId"`
	KVN                    string          `json:"kvn"`
	NumberOfOptionalBlocks string          `json:"NumberOfOptionalBlocks"`
	OptionalBlocks         []OptionalBlock `json:"optionalBlocks"`
	Exportability          string          `json:"exportability"`
}
type TranslatePrivateResp struct {
	PrivateKeyLen int    `json:"privateKeyLen"`
	PrivateKey    string `json:"privateKey"`
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
	LMKId                  string          `json:"lmkId"`
	KeyUsage               string          `json:"keyUsage"`
	ModeOfUse              string          `json:"modeOfUse"`
	KVN                    string          `json:"kvn"`
	Exportability          string          `json:"exportability"`
	NumberOfOptionalBlocks string          `json:"NumberOfOptionalBlocks"`
	OptionalBlocks         []OptionalBlock `json:"optionalBlocks"`
}
type ImportKeyOrDataUnderRSAPubKeyResp struct {
	InitializationValue string `json:"initializationValue"`
	Key                 string `json:"key"`
	KCV                 string `json:"kcv"`
}
