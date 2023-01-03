package controllers

import (
	"net/http"

	"github.com/metalcorpe/payshield-rest-gopher/interfaces"
	"github.com/metalcorpe/payshield-rest-gopher/models"

	"github.com/go-chi/render"
)

type HsmController struct {
	interfaces.IHsmService
}

func (controller *HsmController) VerifyPin(w http.ResponseWriter, r *http.Request) {
	var p models.PinVer
	err := render.DecodeJSON(r.Body, &p)
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
	err = controller.NewVerifyPinResponse(p)
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
}
func (controller *HsmController) Version(w http.ResponseWriter, r *http.Request) {
	var p models.Diagnostics
	err := render.DecodeJSON(r.Body, &p)
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
	resp, err := controller.NewVersionResponse(p)
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
	render.JSON(w, r, resp)
}
func (controller *HsmController) Migrate(w http.ResponseWriter, r *http.Request) {
	var p models.Migrate
	err := render.DecodeJSON(r.Body, &p)
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
	resp, err := controller.NewMigrateResponse(p)
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
	render.JSON(w, r, resp)
}
func (controller *HsmController) MigratePrivate(w http.ResponseWriter, r *http.Request) {
	var p models.TranslatePrivate
	err := render.DecodeJSON(r.Body, &p)
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
	resp, err := controller.NewMigratePrivateResponse(p)
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
	render.JSON(w, r, resp)
}

func (controller *HsmController) Generatekey(w http.ResponseWriter, r *http.Request) {
	var p models.GenerateKey
	err := render.DecodeJSON(r.Body, &p)
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
	resp, err := controller.NewGenerateKeyResponse(p)
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
	render.JSON(w, r, resp)
}
func (controller *HsmController) ExportKey(w http.ResponseWriter, r *http.Request) {
	var p models.ExportKey
	err := render.DecodeJSON(r.Body, &p)
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
	resp, err := controller.NewExportKeyResponse(p)
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
	render.JSON(w, r, resp)
}
func (controller *HsmController) GenerateKeyPair(w http.ResponseWriter, r *http.Request) {
	var p models.GeneratePair
	err := render.DecodeJSON(r.Body, p)
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
	resp, err := controller.NewGenerateKeyPairResponse(p)
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return

	}
	render.JSON(w, r, resp)
}
func (controller *HsmController) ImportKeyRSA(w http.ResponseWriter, r *http.Request) {
	var p models.ImportKeyOrDataUnderRSAPubKey
	err := render.DecodeJSON(r.Body, &p)
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
	resp, err := controller.ImportKeyRSAResponse(p)
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
	render.JSON(w, r, resp)
}
