package controllers

import (
	"errors"
	"hsmapi/src/engine"
	"net/http"
	"payshield-rest-api/interfaces"

	"github.com/go-chi/render"
)

func NewVerifypinResponse(r engine.PinVer) error {
	ec := engine.DA(r)
	if ec != "00" {
		return errors.New(ec)
	}
	return nil
}

type ErrResponse struct {
	Err            error `json:"-"` // low-level runtime error
	HTTPStatusCode int   `json:"-"` // http response status code

	StatusText string `json:"status"`          // user-level status message
	AppCode    int64  `json:"code,omitempty"`  // application-specific error code
	ErrorText  string `json:"error,omitempty"` // application-level error message, for debugging
}

func (e *ErrResponse) Render(w http.ResponseWriter, r *http.Request) error {
	render.Status(r, e.HTTPStatusCode)
	return nil
}

func ErrRender(err error) render.Renderer {
	return &ErrResponse{
		Err:            err,
		HTTPStatusCode: 422,
		StatusText:     engine.CheckErrorCode(err.Error()),
		ErrorText:      err.Error(),
	}
}

type HsmController struct {
	interfaces.IHsmService
}

func (controller *HsmController) VerifyPin(w http.ResponseWriter, r *http.Request) {
	var p engine.PinVer
	err := render.DecodeJSON(r.Body, &p)
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
	err = NewVerifypinResponse(p)
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
}
func (controller *HsmController) Version(w http.ResponseWriter, r *http.Request) {
	resp, err := controller.NewVersionResponse()
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
	render.JSON(w, r, resp)
}

func (controller *HsmController) Migrate(w http.ResponseWriter, r *http.Request) {
	var p engine.Migrate
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
	var p engine.TranslatePrivate
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
	var p engine.GenerateKey
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
	var p engine.ExportKey
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
	var p engine.GeneratePair
	err := render.DecodeJSON(r.Body, &p)
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
