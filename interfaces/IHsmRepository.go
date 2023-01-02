package interfaces

import "github.com/metalcorpe/payshield-rest-gopher/models"

type IHsmRepository interface {
	A0(models.GenerateKey) (res models.GenerateKeyResp, errCode string)
	A8(models.ExportKey) (res models.ExportKeyResp, errCode string)
	BW(models.Migrate) (res models.MigrateRes, errCode string)
	DA(models.PinVer) string
	EI(models.GeneratePair) (res models.GeneratePairResp, errCode string)
	EM(models.TranslatePrivate) (res models.TranslatePrivateResp, errCode string)
	GI(models.ImportKeyOrDataUnderRSAPubKey) (res models.ImportKeyOrDataUnderRSAPubKeyResp, errCode string)
	M0(models.InpEnc) (res string, errCode string)
	M2(models.InpDec) (res string, errCode string)
	NC() (lmk string, firmware string, errCode string)
}
