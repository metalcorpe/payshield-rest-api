package main

import (
	"sync"

	"github.com/metalcorpe/payshield-rest-api/controllers"
	"github.com/metalcorpe/payshield-rest-api/services"
)

type IServiceContainer interface {
	InjectHsmController() controllers.HsmController
}

type kernel struct{}

func (k *kernel) InjectHsmController() controllers.HsmController {

	hsmService := &services.HsmService{}
	hsmController := controllers.HsmController{IHsmService: hsmService}
	return hsmController
}

var (
	k             *kernel
	containerOnce sync.Once
)

func ServiceContainer() IServiceContainer {
	if k == nil {
		containerOnce.Do(func() {
			k = &kernel{}
		})
	}
	return k
}
