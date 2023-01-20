package main

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	"github.com/metalcorpe/payshield-rest-gopher/misc"
	"github.com/metalcorpe/payshield-rest-gopher/protobuf"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type IMuxRouter interface {
	InitMuxRouter() *chi.Mux
}
type IRpcRouter interface {
	InitRpcRouter() *grpc.Server
}

type muxRouter struct {
	log  *zap.Logger
	conf misc.Config
}

func (router *muxRouter) InitMuxRouter() *chi.Mux {
	hsmController := ServiceContainer(router.log, router.conf).InjectHsmController()
	r := chi.NewRouter()

	router.log.Debug("Attaching middleware")
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
	//Generate a Key Check Value
	r.Post("/generatekey/kcv", hsmController.GenerateKCV)
	//Import Key or data under an RSA Public Key
	r.Post("/import/key", hsmController.ImportKey)
	r.Post("/generate/mac/dukpt", hsmController.GenerateMacDukpt)
	r.Post("/verify/mac/dukpt", hsmController.GenerateMacDukpt)

	//the walking function
	chi.Walk(r, func(method string, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		fmt.Printf("[%s]: '%s' has %d middlewares\n", method, route, len(middlewares))
		return nil
	})

	return r
}

type rpcRouter struct {
	log  *zap.Logger
	conf misc.Config
}

func (router *rpcRouter) InitRpcRouter() *grpc.Server {
	rpcInit := ServiceContainer(router.log, router.conf).InjectHsmRpc()
	s := grpc.NewServer(
		grpc_middleware.WithUnaryServerChain(
			grpc_recovery.UnaryServerInterceptor(),
		),
		grpc_middleware.WithStreamServerChain(
			grpc_recovery.StreamServerInterceptor(),
		),
	)
	protobuf.RegisterHSMServer(s, rpcInit)
	reflection.Register(s)
	return s
}

var (
	m             *muxRouter
	muxRouterOnce sync.Once
	r             *rpcRouter
	rpcRouterOnce sync.Once
)

func MuxRouter(log *zap.Logger, conf misc.Config) IMuxRouter {
	if m == nil {
		muxRouterOnce.Do(func() {
			m = &muxRouter{log: log, conf: conf}
		})
	}
	return m
}
func RpcRouter(log *zap.Logger, conf misc.Config) IRpcRouter {
	if r == nil {
		rpcRouterOnce.Do(func() {
			r = &rpcRouter{log: log, conf: conf}
		})
	}
	return r
}
