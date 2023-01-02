package main

import (
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
)

type IChiRouter interface {
	InitRouter() *chi.Mux
}

type router struct {
	conf config
}

func (router *router) InitRouter() *chi.Mux {
	hsmController := ServiceContainer(router.conf).InjectHsmController()

	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.URLFormat)
	r.Use(render.SetContentType(render.ContentTypeJSON))
	r.Mount("/debug", middleware.Profiler())

	//Verify PIN
	r.Post("/verifypin", hsmController.VerifyPin)
	//Version
	r.Get("/version", hsmController.Version)
	//Migrate
	r.Post("/migrate", hsmController.Migrate)
	//Migrate
	r.Post("/migrate/private", hsmController.MigratePrivate)
	//Generate Key
	r.Post("/generatekey", hsmController.Generatekey)
	//Generate Key
	r.Post("/exportkey", hsmController.ExportKey)
	//Generate Key
	r.Post("/generatekey/pair", hsmController.GenerateKeyPair)

	return r
}

var (
	m          *router
	routerOnce sync.Once
)

func ChiRouter(conf config) IChiRouter {
	if m == nil {
		routerOnce.Do(func() {
			m = &router{conf: conf}
		})
	}
	return m
}
