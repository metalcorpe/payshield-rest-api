package misc

import (
	"log"

	"github.com/spf13/viper"
)

// Create private data struct to hold config options.
type server struct {
	Host       string
	Port       string
	Tls        bool
	ServerCert string
	ServerKey  string
}
type hsm struct {
	Ip           string
	Port         int
	PortVariant  int
	PortKeyBlock int
	Tls          bool
	ClientCert   string
	ClientKey    string
}
type Config struct {
	Server server
	Hsm    hsm
}

func GetConfig() Config {
	viper.SetConfigType("yaml")
	viper.AddConfigPath("config")
	viper.SetConfigName("service.yaml")

	err := viper.ReadInConfig()
	if err != nil {
		log.Panic(err.Error())
		// return
	}

	conf := &Config{}
	err = viper.Unmarshal(conf)
	if err != nil {
		log.Panic(err.Error())
		// return
	}
	return *conf
}
