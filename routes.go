package main

import (
	"errors"
	"hsmapi/src/engine"
	"net/http"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
)

func NewVerifypinResponse(r engine.PinVer) error {
	ec := engine.DA(r)
	if ec != "00" {
		return errors.New(ec)
	}
	return nil
}

func verifypin(w http.ResponseWriter, r *http.Request) {
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

type VersionResponce struct {
	LmkCheck       string `json:"lmkCheck"`
	FirmwareNumber string `json:"firmwareNumber"`
}

func (u *VersionResponce) Bind(r *http.Request) error {
	return nil
}

func (u *VersionResponce) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func NewVersionResponse() (*VersionResponce, error) {
	resp := &VersionResponce{}
	ec, lmk, firmware := engine.NC()
	if ec != "00" {
		return nil, errors.New(ec)
	}
	resp.LmkCheck = lmk
	resp.FirmwareNumber = firmware
	return resp, nil
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
func version(w http.ResponseWriter, r *http.Request) {
	resp, err := NewVersionResponse()
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
	render.JSON(w, r, resp)
}

func NewMigrateResponse(r engine.Migrate) (engine.MigrateRes, error) {
	ec, resp := engine.BW(r)
	if ec != "00" {
		return engine.MigrateRes{}, errors.New(ec)
	}
	return resp, nil
}

func migrate(w http.ResponseWriter, r *http.Request) {
	var p engine.Migrate
	err := render.DecodeJSON(r.Body, &p)
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
	resp, err := NewMigrateResponse(p)
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
	render.JSON(w, r, resp)
}

func NewMigratePrivateResponse(r engine.TranslatePrivate) (engine.TranslatePrivateResp, error) {
	ec, resp := engine.EM(r)
	if ec != "00" {
		return engine.TranslatePrivateResp{}, errors.New(ec)
	}
	return resp, nil
}

func migratePrivate(w http.ResponseWriter, r *http.Request) {
	var p engine.TranslatePrivate
	err := render.DecodeJSON(r.Body, &p)
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
	resp, err := NewMigratePrivateResponse(p)
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
	render.JSON(w, r, resp)
}

func NewGenerateKeyResponse(r engine.GenerateKey) (engine.GenerateKeyResp, error) {
	ec, resp := engine.A0(r)
	if ec != "00" {
		return engine.GenerateKeyResp{}, errors.New(ec)
	}
	return resp, nil
}

func generatekey(w http.ResponseWriter, r *http.Request) {
	var p engine.GenerateKey
	err := render.DecodeJSON(r.Body, &p)
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
	resp, err := NewGenerateKeyResponse(p)
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
	render.JSON(w, r, resp)
}

func NewExportKeyResponse(r engine.ExportKey) (engine.ExportKeyResp, error) {
	ec, resp := engine.A8(r)
	if ec != "00" {
		return engine.ExportKeyResp{}, errors.New(ec)
	}
	return resp, nil
}

func exportKey(w http.ResponseWriter, r *http.Request) {
	var p engine.ExportKey
	err := render.DecodeJSON(r.Body, &p)
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
	resp, err := NewExportKeyResponse(p)
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
	render.JSON(w, r, resp)
}

func NewGenerateKeyPairResponse(r engine.GeneratePair) (engine.GeneratePairResp, error) {
	ec, resp := engine.EI(r)
	if ec != "00" {
		return engine.GeneratePairResp{}, errors.New(ec)
	}
	return resp, nil
}

func generateKeyPair(w http.ResponseWriter, r *http.Request) {
	var p engine.GeneratePair
	err := render.DecodeJSON(r.Body, &p)
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
	resp, err := NewGenerateKeyPairResponse(p)
	if err != nil {
		render.JSON(w, r, ErrRender(err))
		return
	}
	render.JSON(w, r, resp)
}

func addRoutes(r *chi.Mux) {

}

type IChiRouter interface {
	InitRouter() *chi.Mux
}

type router struct{}

func (router *router) InitRouter() *chi.Mux {
	// playerController := ServiceContainer().InjectPlayerController()

	// r.HandleFunc("/getScore/{player1}/vs/{player2}", playerController.GetPlayerScore)
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.URLFormat)
	r.Use(render.SetContentType(render.ContentTypeJSON))
	r.Mount("/debug", middleware.Profiler())

	//Verify PIN
	r.Post("/verifypin", verifypin)
	//Version
	r.Get("/version", version)
	// //Migrate
	r.Post("/migrate", migrate)
	// //Migrate
	r.Post("/migrate/private", migratePrivate)
	// //Generate Key
	r.Post("/generatekey", generatekey)
	// //Generate Key
	r.Post("/exportkey", exportKey)
	//Generate Key
	r.Post("/generatekey/pair", generateKeyPair)
	return r
}

var (
	m          *router
	routerOnce sync.Once
)

func ChiRouter() IChiRouter {
	if m == nil {
		routerOnce.Do(func() {
			m = &router{}
		})
	}
	return m
}
