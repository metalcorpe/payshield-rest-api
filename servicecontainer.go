package main

import (
	"crypto/tls"
	"sync"

	"github.com/metalcorpe/payshield-rest-api/controllers"
	"github.com/metalcorpe/payshield-rest-api/engine"
	"github.com/metalcorpe/payshield-rest-api/services"
)

type IServiceContainer interface {
	InjectHsmController() controllers.HsmController
}

type kernel struct {
	conf config
}

func (k *kernel) InjectHsmController() controllers.HsmController {
	cert, _ := tls.LoadX509KeyPair(k.conf.Hsm.ClientCert, k.conf.Hsm.ClientKey)

	config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}

	tcpConfig := engine.TcpConfig{Host: k.conf.Hsm.Ip, Port: k.conf.Hsm.Port, TlsConfig: &config, MaxIdleConns: 2, MaxOpenConn: 64}
	connectionPool, _ := engine.CreateTcpConnPool(&tcpConfig)

	hsmRepository := &engine.HsmRepository{connectionPool}
	hsmService := &services.HsmService{hsmRepository}
	hsmController := controllers.HsmController{IHsmService: hsmService}
	return hsmController
}

var (
	k             *kernel
	containerOnce sync.Once
)

func ServiceContainer(conf config) IServiceContainer {
	if k == nil {
		containerOnce.Do(func() {
			k = &kernel{conf: conf}
		})
	}
	return k
}
