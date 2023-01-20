package rest

import (
	"net/http"

	"github.com/metalcorpe/payshield-rest-gopher/controllers"
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
		render.JSON(w, r, controllers.ErrRender(err))
		return
	}
	err = controller.NewVerifyPinResponse(p)
	if err != nil {
		render.JSON(w, r, controllers.ErrRender(err))
		return
	}
}
func (controller *HsmController) Version(w http.ResponseWriter, r *http.Request) {
	var p models.Diagnostics
	err := render.DecodeJSON(r.Body, &p)
	if err != nil {
		render.JSON(w, r, controllers.ErrRender(err))
		return
	}
	resp, err := controller.NewVersionResponse(p)
	if err != nil {
		render.JSON(w, r, controllers.ErrRender(err))
		return
	}
	render.JSON(w, r, resp)
}
func (controller *HsmController) Migrate(w http.ResponseWriter, r *http.Request) {
	var p models.Migrate
	err := render.DecodeJSON(r.Body, &p)
	if err != nil {
		render.JSON(w, r, controllers.ErrRender(err))
		return
	}
	resp, err := controller.NewMigrateResponse(p)
	if err != nil {
		render.JSON(w, r, controllers.ErrRender(err))
		return
	}
	render.JSON(w, r, resp)
}
func (controller *HsmController) MigratePrivate(w http.ResponseWriter, r *http.Request) {
	var p models.TranslatePrivate
	err := render.DecodeJSON(r.Body, &p)
	if err != nil {
		render.JSON(w, r, controllers.ErrRender(err))
		return
	}
	resp, err := controller.NewMigratePrivateResponse(p)
	if err != nil {
		render.JSON(w, r, controllers.ErrRender(err))
		return
	}
	render.JSON(w, r, resp)
}

func (controller *HsmController) Generatekey(w http.ResponseWriter, r *http.Request) {
	var p models.GenerateKey
	err := render.DecodeJSON(r.Body, &p)
	if err != nil {
		render.JSON(w, r, controllers.ErrRender(err))
		return
	}
	resp, err := controller.NewGenerateKeyResponse(p)
	if err != nil {
		render.JSON(w, r, controllers.ErrRender(err))
		return
	}
	render.JSON(w, r, resp)
}
func (controller *HsmController) ExportKey(w http.ResponseWriter, r *http.Request) {
	var p models.ExportKey
	err := render.DecodeJSON(r.Body, &p)
	if err != nil {
		render.JSON(w, r, controllers.ErrRender(err))
		return
	}
	resp, err := controller.NewExportKeyResponse(p)
	if err != nil {
		render.JSON(w, r, controllers.ErrRender(err))
		return
	}
	render.JSON(w, r, resp)
}
func (controller *HsmController) GenerateKeyPair(w http.ResponseWriter, r *http.Request) {
	var p models.GeneratePair
	err := render.DecodeJSON(r.Body, p)
	if err != nil {
		render.JSON(w, r, controllers.ErrRender(err))
		return
	}
	resp, err := controller.NewGenerateKeyPairResponse(p)
	if err != nil {
		render.JSON(w, r, controllers.ErrRender(err))
		return

	}
	render.JSON(w, r, resp)
}
func (controller *HsmController) ImportKeyRSA(w http.ResponseWriter, r *http.Request) {
	var p models.ImportKeyOrDataUnderRSAPubKey
	err := render.DecodeJSON(r.Body, &p)
	if err != nil {
		render.JSON(w, r, controllers.ErrRender(err))
		return
	}
	resp, err := controller.ImportKeyRSAResponse(p)
	if err != nil {
		render.JSON(w, r, controllers.ErrRender(err))
		return
	}
	render.JSON(w, r, resp)
}
func (controller *HsmController) GenerateKCV(w http.ResponseWriter, r *http.Request) {
	var p models.GenerateKCV
	err := render.DecodeJSON(r.Body, &p)
	if err != nil {
		render.JSON(w, r, controllers.ErrRender(err))
		return
	}
	resp, err := controller.GenerateKCVResponce(p)
	if err != nil {
		render.JSON(w, r, controllers.ErrRender(err))
		return
	}
	render.JSON(w, r, resp)
}
func (controller *HsmController) ImportKey(w http.ResponseWriter, r *http.Request) {
	var p models.ImportKey
	err := render.DecodeJSON(r.Body, &p)
	if err != nil {
		render.JSON(w, r, controllers.ErrRender(err))
		return
	}
	resp, err := controller.ImportKeyResponse(p)
	if err != nil {
		render.JSON(w, r, controllers.ErrRender(err))
		return
	}
	render.JSON(w, r, resp)
}
func (controller *HsmController) GenerateMacDukpt(w http.ResponseWriter, r *http.Request) {
	var p models.GenerateVerifyMacDukpt
	err := render.DecodeJSON(r.Body, &p)
	if err != nil {
		render.JSON(w, r, controllers.ErrRender(err))
		return
	}
	resp, err := controller.GenerateVerifyMacDukptResponce(p)
	if err != nil {
		render.JSON(w, r, controllers.ErrRender(err))
		return
	}
	render.JSON(w, r, resp)
}
