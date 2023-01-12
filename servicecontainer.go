package main

import (
	"crypto/tls"
	"sync"

	"github.com/metalcorpe/payshield-rest-gopher/controllers/rest"
	"github.com/metalcorpe/payshield-rest-gopher/controllers/rpc"
	"github.com/metalcorpe/payshield-rest-gopher/engine"
	"github.com/metalcorpe/payshield-rest-gopher/interfaces"
	"github.com/metalcorpe/payshield-rest-gopher/misc"
	"github.com/metalcorpe/payshield-rest-gopher/protobuf"
	"github.com/metalcorpe/payshield-rest-gopher/services"
	"go.uber.org/zap"
)

type IServiceContainer interface {
	InjectHsmController() rest.HsmController
	InjectHsmRpc() *rpc.HsmRpcController
}
type ITcpContainer interface {
	InjectTcpPool() interfaces.IConnectionHandler
}

type kernel struct {
	log  *zap.Logger
	conf misc.Config
}

func (k *kernel) InjectHsmController() rest.HsmController {
	hsmRepository := &engine.HsmRepository{IConnectionHandler: TcpContainer().InjectTcpPool()}
	hsmService := &services.HsmService{IHsmRepository: hsmRepository}
	hsmController := rest.HsmController{IHsmService: hsmService}
	return hsmController
}
func (k *kernel) InjectHsmRpc() *rpc.HsmRpcController {
	hsmRepository := &engine.HsmRepository{IConnectionHandler: TcpContainer().InjectTcpPool()}
	hsmService := &services.HsmService{IHsmRepository: hsmRepository}
	hsmController := &rpc.HsmRpcController{IHsmService: hsmService, UnimplementedHSMServer: protobuf.UnimplementedHSMServer{}}
	return hsmController
}

type tcpConn struct {
}

func (t *tcpConn) InjectTcpPool() interfaces.IConnectionHandler {
	k.log.Debug("Injecting Dependencies")
	cert, _ := tls.LoadX509KeyPair(k.conf.Hsm.ClientCert, k.conf.Hsm.ClientKey)
	config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
	tcpConfig := engine.TcpConfig{Host: k.conf.Hsm.Ip, Port: k.conf.Hsm.Port, TlsConfig: &config, MaxIdleConns: 2, MaxOpenConn: 64}
	connectionPool, _ := engine.CreateTcpConnPool(&tcpConfig)
	// return &mock.TcpConnMock{}
	return connectionPool
}

var (
	k              *kernel
	containerOnce  sync.Once
	t              *tcpConn
	tContainerOnce sync.Once
)

func ServiceContainer(log *zap.Logger, conf misc.Config) IServiceContainer {
	if k == nil {
		containerOnce.Do(func() {
			k = &kernel{log: log, conf: conf}
		})
	}
	return k
}
func TcpContainer() ITcpContainer {
	if t == nil {
		tContainerOnce.Do(func() {
			t = &tcpConn{}
		})
	}
	return t
}
