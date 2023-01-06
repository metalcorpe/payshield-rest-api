// RestAPI Thales payShield HSM using Golang
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/metalcorpe/payshield-rest-gopher/engine"
	"github.com/metalcorpe/payshield-rest-gopher/engine/mock"
	"github.com/metalcorpe/payshield-rest-gopher/misc"
	pb "github.com/metalcorpe/payshield-rest-gopher/protobuf"
	"github.com/metalcorpe/payshield-rest-gopher/services"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	"github.com/metalcorpe/payshield-rest-gopher/controllers/rpc"
	"go.uber.org/zap"
)

func main() {

	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", 50051))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer(
		grpc_middleware.WithUnaryServerChain(
			grpc_recovery.UnaryServerInterceptor(),
		),
		grpc_middleware.WithStreamServerChain(
			grpc_recovery.StreamServerInterceptor(),
		),
	)
	connectionPool := mock.TcpConnMock{}
	hsmRepository := &engine.HsmRepository{IConnectionHandler: &connectionPool}
	hsmService := &services.HsmService{IHsmRepository: hsmRepository}
	pb.RegisterHSMServer(s, &rpc.HsmRpcController{IHsmService: hsmService, UnimplementedHSMServer: pb.UnimplementedHSMServer{}})
	reflection.Register(s)
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}

	// configure log
	log, _ := zap.NewDevelopment(zap.WithCaller(true))
	defer func() {
		_ = log.Sync()
	}()

	conf := misc.GetConfig()

	addr := conf.Server.Host + ":" + conf.Server.Port
	log.Info("starting up API at: " + func(a bool, address string) string {
		if a {
			return "https://" + address
		} else {
			return "http://" + address
		}
	}(conf.Server.Tls, addr))

	var errHttp error
	if conf.Server.Tls {
		errHttp = http.ListenAndServeTLS(addr, conf.Server.ServerCert, conf.Server.ServerKey, ChiRouter(log, conf).InitRouter())
	} else {
		errHttp = http.ListenAndServe(addr, ChiRouter(log, conf).InitRouter())
	}

	if errHttp != nil {
		log.Fatal(errHttp.Error())
		return
	}
}
