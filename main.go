// RestAPI Thales payShield HSM using Golang
package main

import (
	"net/http"
	"strings"

	"github.com/metalcorpe/payshield-rest-gopher/misc"

	"go.uber.org/zap"
)

// GrpcHandlerFunc returns an http.Handler that delegates to grpcServer on incoming gRPC
// connections or otherHandler otherwise. Copied from cockroachdb.
func grpcHandlerFunc(grpcServer http.Handler, otherHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This is a partial recreation of gRPC's internal checks https://github.com/grpc/grpc-go/pull/514/files#diff-95e9a25b738459a2d3030e1e6fa2a718R61
		if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
		} else {
			otherHandler.ServeHTTP(w, r)
		}
	})
}

func main() {

	// configure log
	log, _ := zap.NewDevelopment(zap.WithCaller(true))
	defer func() {
		_ = log.Sync()
	}()

	conf := misc.GetConfig()

	addr := conf.Server.Host + ":" + conf.Server.Port
	log.Info("starting up API at: " + addr)

	protcolHandler := grpcHandlerFunc(RpcRouter(log, conf).InitRpcRouter(), MuxRouter(log, conf).InitMuxRouter())
	errHttp := http.ListenAndServeTLS(addr, conf.Server.ServerCert, conf.Server.ServerKey, protcolHandler)

	if errHttp != nil {
		log.Fatal(errHttp.Error())
		return
	}
}
