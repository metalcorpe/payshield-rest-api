package main

import (
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/metalcorpe/payshield-rest-api/misc"
	"go.uber.org/zap"
)

type IChiRouter interface {
	InitRouter() *chi.Mux
}

type router struct {
	log  *zap.Logger
	conf misc.Config
}

func (router *router) InitRouter() *chi.Mux {
	hsmController := ServiceContainer(router.log, router.conf).InjectHsmController()
	r := chi.NewRouter()

	router.log.Debug("Attaching middlewares")
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.URLFormat)
	r.Use(render.SetContentType(render.ContentTypeJSON))
	r.Mount("/debug", middleware.Profiler())

	router.log.Debug("Registering Controllers")
	//Verify PIN
	r.Post("/verifypin", hsmController.VerifyPin)
	//Version
	r.Get("/version", hsmController.Version)
	//Migrate
	r.Post("/migrate", hsmController.Migrate)
	//Migrate Private
	r.Post("/migrate/private", hsmController.MigratePrivate)
	//Generate Key
	r.Post("/generatekey", hsmController.Generatekey)
	//Export Key
	r.Post("/exportkey", hsmController.ExportKey)
	//Generate Key Pair
	r.Post("/generatekey/pair", hsmController.GenerateKeyPair)
	//Import Key or data under an RSA Public Key
	r.Post("/import/rsa", hsmController.ImportKeyRSA)

	return r
}

var (
	m          *router
	routerOnce sync.Once
)

func ChiRouter(log *zap.Logger, conf misc.Config) IChiRouter {
	if m == nil {
		routerOnce.Do(func() {
			m = &router{log: log, conf: conf}
		})
	}
	return m
}
