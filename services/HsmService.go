package services

import (
	"errors"
	"hsmapi/src/engine"
)

type HsmService struct {
	// interfaces.IHsmRepository
}

func (service *HsmService) NewVersionResponse() (engine.VersionResponse, error) {
	resp := engine.VersionResponse{}
	ec, lmk, firmware := engine.NC()
	if ec != "00" {
		return resp, errors.New(ec)
	}
	resp.LmkCheck = lmk
	resp.FirmwareNumber = firmware
	return resp, nil
}
func (service *HsmService) NewGenerateKeyPairResponse(r engine.GeneratePair) (engine.GeneratePairResp, error) {
	ec, resp := engine.EI(r)
	if ec != "00" {
		return engine.GeneratePairResp{}, errors.New(ec)
	}
	return resp, nil
}

func (service *HsmService) NewMigrateResponse(r engine.Migrate) (engine.MigrateRes, error) {
	ec, resp := engine.BW(r)
	if ec != "00" {
		return engine.MigrateRes{}, errors.New(ec)
	}
	return resp, nil
}

func (service *HsmService) NewMigratePrivateResponse(r engine.TranslatePrivate) (engine.TranslatePrivateResp, error) {
	ec, resp := engine.EM(r)
	if ec != "00" {
		return engine.TranslatePrivateResp{}, errors.New(ec)
	}
	return resp, nil
}

func (service *HsmService) NewGenerateKeyResponse(r engine.GenerateKey) (engine.GenerateKeyResp, error) {
	ec, resp := engine.A0(r)
	if ec != "00" {
		return engine.GenerateKeyResp{}, errors.New(ec)
	}
	return resp, nil
}

func (service *HsmService) NewExportKeyResponse(r engine.ExportKey) (engine.ExportKeyResp, error) {
	ec, resp := engine.A8(r)
	if ec != "00" {
		return engine.ExportKeyResp{}, errors.New(ec)
	}
	return resp, nil
}
