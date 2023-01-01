package interfaces

import "github.com/metalcorpe/payshield-rest-api/models"

type IHsmService interface {
	NewVersionResponse() (models.VersionResponse, error)
	NewVerifypinResponse(r models.PinVer) error
	NewGenerateKeyPairResponse(p models.GeneratePair) (models.GeneratePairResp, error)
	NewMigrateResponse(r models.Migrate) (models.MigrateRes, error)
	NewMigratePrivateResponse(r models.TranslatePrivate) (models.TranslatePrivateResp, error)
	NewGenerateKeyResponse(r models.GenerateKey) (models.GenerateKeyResp, error)
	NewExportKeyResponse(r models.ExportKey) (models.ExportKeyResp, error)
}
