// RestAPI Thales payShield HSM using Golang
package main

import (
	"net/http"

	"github.com/metalcorpe/payshield-rest-gopher/misc"

	"go.uber.org/zap"
)

func main() {
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
