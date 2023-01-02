package interfaces

import "github.com/metalcorpe/payshield-rest-api/models"

type IHsmRepository interface {
	A0(models.GenerateKey) (res models.GenerateKeyResp, errcode string)
	A8(models.ExportKey) (res models.ExportKeyResp, errcode string)
	BW(models.Migrate) (res models.MigrateRes, errcode string)
	DA(models.PinVer) string
	EI(models.GeneratePair) (res models.GeneratePairResp, errcode string)
	EM(models.TranslatePrivate) (res models.TranslatePrivateResp, errcode string)
	GI(models.ImportKeyOrDataUnderRSAPubKey) (res models.ImportKeyOrDataUnderRSAPubKeyResp, errcode string)
	M0(models.InpEnc) (res string, errcode string)
	M2(models.InpDec) (res string, errcode string)
	NC() (lmk string, firmware string, errcode string)
}
