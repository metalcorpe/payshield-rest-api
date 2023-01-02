package interfaces

import "github.com/metalcorpe/payshield-rest-api/models"

type IHsmRepository interface {
	A0(models.GenerateKey) (errcode string, res models.GenerateKeyResp)
	A8(models.ExportKey) (errcode string, res models.ExportKeyResp)
	BW(models.Migrate) (errcode string, res models.MigrateRes)
	DA(models.PinVer) string
	EI(models.GeneratePair) (errcode string, res models.GeneratePairResp)
	EM(models.TranslatePrivate) (errcode string, res models.TranslatePrivateResp)
	GI(models.ImportKeyOrDataUnderRSAPubKey) (errcode string, res models.ImportKeyOrDataUnderRSAPubKeyResp)
	M0(models.InpEnc) (errcode string, res string)
	M2(models.InpDec) (errcode string, res string)
	NC() (errcode string, lmk string, firmware string)
}
