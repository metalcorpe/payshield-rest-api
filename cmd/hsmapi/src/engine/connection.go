// Copyright PT Dymar Jaya Indonesia
// Date February 2020
// RestAPI Thales payShield HSM using Golang
// Code by Mudito Adi Pranowo
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package engine

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net"

	"github.com/spf13/viper"
)

func Join(s ...[]byte) []byte {
	n := 0
	for _, v := range s {
		n += len(v)
	}

	b, i := make([]byte, n), 0
	for _, v := range s {
		i += copy(b[i:], v)
	}
	return b
}

func Connect(address string, commandMessage []byte) []byte {

	tls_b, cert, key := loadConfHSMTLS()

	// net.Conn is an interface, tls.Conn is a struct, so a pointer to tls.Conn is perfectly assignable to net.Conn, see: http://play.golang.org/p/eM_33Bud-c
	var conn net.Conn

	if tls_b {
		cert, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			log.Fatalf("server: loadkeys: %s", err)
		}
		config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}

		conn, _ = tls.Dial("tcp", address, &config)

	} else {
		conn, _ = net.Dial("tcp", address)
	}

	defer conn.Close()

	commandLength := make([]byte, 2)
	if len(commandMessage) > 255 {
		commandLength[0] = byte(len(commandMessage) / 256)
		commandLength[1] = byte(len(commandMessage) % 256)
	} else {
		commandLength[0] = byte(0)
		commandLength[1] = byte(len(commandMessage))
	}

	var tcpCommandMessage []byte
	tcpCommandMessage = append(commandLength, commandMessage...)

	fmt.Println(hex.Dump(tcpCommandMessage))

	conn.Write([]byte(tcpCommandMessage))
	buff := make([]byte, 2048)
	n, _ := conn.Read(buff)

	return buff[:n]
}

func loadConfHSMVariant() string {
	viper.SetConfigType("yaml")
	viper.AddConfigPath("../config")
	viper.SetConfigName("hsm.conf")

	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println("Load file config HSM keyblock error")
	}

	return viper.GetString("hsm.ip") + ":" + viper.GetString("hsm.portvariant")
}

func loadConfHSMKeyblock() string {
	viper.SetConfigType("yaml")
	viper.AddConfigPath("../config")
	viper.SetConfigName("hsm.conf")

	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println("Load file config HSM keyblock error")
	}

	return viper.GetString("hsm.ip") + ":" + viper.GetString("hsm.portkeyblock")
}

func loadConfHSMTLS() (bool, string, string) {
	viper.SetConfigType("yaml")
	viper.AddConfigPath("../config")
	viper.SetConfigName("hsm.conf")

	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println("Load file config TLS error")
	}

	return viper.GetBool("hsm.tls"), viper.GetString("hsm.clientcert"), viper.GetString("hsm.clientkey")
}
