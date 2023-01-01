package interfaces

import "hsmapi/src/engine"

type IHsmService interface {
	NewVersionResponse() (engine.VersionResponse, error)
	NewGenerateKeyPairResponse(p engine.GeneratePair) (engine.GeneratePairResp, error)
	NewMigrateResponse(r engine.Migrate) (engine.MigrateRes, error)
	NewMigratePrivateResponse(r engine.TranslatePrivate) (engine.TranslatePrivateResp, error)
	NewGenerateKeyResponse(r engine.GenerateKey) (engine.GenerateKeyResp, error)
	NewExportKeyResponse(r engine.ExportKey) (engine.ExportKeyResp, error)
}
