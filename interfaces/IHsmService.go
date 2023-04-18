package interfaces

import "github.com/metalcorpe/payshield-rest-gopher/models"

type IHsmService interface {
	NewVersionResponse(r models.Diagnostics) (models.DiagnosticsRes, error)
	NewVerifyPinResponse(r models.PinVer) error
	NewGenerateKeyPairResponse(p models.GeneratePair) (models.GeneratePairResp, error)
	NewMigrateResponse(r models.Migrate) (models.MigrateRes, error)
	NewMigratePrivateResponse(r models.TranslatePrivate) (models.TranslatePrivateResp, error)
	NewGenerateKeyResponse(r models.GenerateKey) (models.GenerateKeyResp, error)
	NewExportKeyResponse(r models.ExportKey) (models.ExportKeyResp, error)
	ImportKeyRSAResponse(r models.ImportKeyOrDataUnderRSAPubKey) (models.ImportKeyOrDataUnderRSAPubKeyResp, error)
	ExportKeyRSAResponse(r models.ExportKeyUnderRSAPublicKey) (models.ExportKeyUnderRSAPublicKeyResp, error)
	ImportPublicKeyResponse(r models.ImportPublicKey) (models.ImportPublicKeyResp, error)
	ImportKeyResponse(r models.ImportKey) (models.ImportKeyResp, error)
	GenerateKCVResponse(r models.GenerateKCV) (models.GenerateKCVResp, error)
	GenerateVerifyMacDukptResponse(r models.GenerateVerifyMacDukpt) (models.GenerateVerifyMacDukptResp, error)
	EncryptDataBlockResponse(r models.EncryptDataBlock) (models.EncryptDataBlockResp, error)
}
