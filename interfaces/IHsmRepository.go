package interfaces

import "github.com/metalcorpe/payshield-rest-api/models"

type IHsmRepository interface {
	DA(models.PinVer) string
	M0(models.InpEnc) (errcode string, res string)
	M2(models.InpDec) (errcode string, res string)
	NC() (errcode string, lmk string, firmware string)
	Token(models.InpToken) (errcode string, res string)
	Detoken(models.InpDetoken) (errcode string, res string)
	BW(models.Migrate) (errcode string, res models.MigrateRes)
	A0(models.GenerateKey) (errcode string, res models.GenerateKeyResp)
	A8(models.ExportKey) (errcode string, res models.ExportKeyResp)
	EI(models.GeneratePair) (errcode string, res models.GeneratePairResp)
	EM(models.TranslatePrivate) (errcode string, res models.TranslatePrivateResp)
}
