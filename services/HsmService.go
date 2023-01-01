package services

import (
	"errors"

	"github.com/metalcorpe/payshield-rest-api/interfaces"
	"github.com/metalcorpe/payshield-rest-api/models"
)

type HsmService struct {
	interfaces.IHsmRepository
}

func (service *HsmService) NewVerifypinResponse(r models.PinVer) error {
	ec := service.DA(r)
	if ec != "00" {
		return errors.New(ec)
	}
	return nil
}
func (service *HsmService) NewVersionResponse() (models.VersionResponse, error) {
	resp := models.VersionResponse{}
	ec, lmk, firmware := service.NC()
	if ec != "00" {
		return resp, errors.New(ec)
	}
	resp.LmkCheck = lmk
	resp.FirmwareNumber = firmware
	return resp, nil
}
func (service *HsmService) NewGenerateKeyPairResponse(r models.GeneratePair) (models.GeneratePairResp, error) {
	ec, resp := service.EI(r)
	if ec != "00" {
		return models.GeneratePairResp{}, errors.New(ec)
	}
	return resp, nil
}

func (service *HsmService) NewMigrateResponse(r models.Migrate) (models.MigrateRes, error) {
	ec, resp := service.BW(r)
	if ec != "00" {
		return models.MigrateRes{}, errors.New(ec)
	}
	return resp, nil
}

func (service *HsmService) NewMigratePrivateResponse(r models.TranslatePrivate) (models.TranslatePrivateResp, error) {
	ec, resp := service.EM(r)
	if ec != "00" {
		return models.TranslatePrivateResp{}, errors.New(ec)
	}
	return resp, nil
}

func (service *HsmService) NewGenerateKeyResponse(r models.GenerateKey) (models.GenerateKeyResp, error) {
	ec, resp := service.A0(r)
	if ec != "00" {
		return models.GenerateKeyResp{}, errors.New(ec)
	}
	return resp, nil
}

func (service *HsmService) NewExportKeyResponse(r models.ExportKey) (models.ExportKeyResp, error) {
	ec, resp := service.A8(r)
	if ec != "00" {
		return models.ExportKeyResp{}, errors.New(ec)
	}
	return resp, nil
}
