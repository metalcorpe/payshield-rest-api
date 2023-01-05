// RestAPI Thales payShield HSM using Golang
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/metalcorpe/payshield-rest-gopher/misc"
	pb "github.com/metalcorpe/payshield-rest-gopher/protobuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"go.uber.org/zap"
)

type server struct {
	pb.UnimplementedHSMServer
}

func (s *server) Version(ctx context.Context, in *pb.Diagnostics) (*pb.DiagnosticsRes, error) {
	log.Printf("Received: %v", in.GetLMKmessage())
	return &pb.DiagnosticsRes{LMKCheck: "Hello " + in.GetLMKmessage()}, nil
}
func main() {

	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", 50051))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterHSMServer(s, &server{})
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
