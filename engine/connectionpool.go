package engine

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strconv"

	"github.com/go-baa/pool"
	"github.com/metalcorpe/payshield-rest-api/interfaces"
)

type ConnectionPool struct {
	interfaces.IConnectionHandler
	Ip        string
	Port      int
	TlsConfig *tls.Config
	conn      net.Conn
	pool      *pool.Pool
}

func (s *ConnectionPool) IntiPool() {
	var conn net.Conn
	var err error
	port := strconv.FormatInt(int64(s.Port), 10)
	if s.TlsConfig != nil {
		s.conn, err = tls.Dial("tcp", s.Ip+":"+port, s.TlsConfig)
	} else {
		s.conn, err = net.Dial("tcp", s.Ip+":"+port)
	}
	if err != nil {
		println(err.Error())
	}
	s.conn = conn
	s.pool, err = pool.New(2, 10, func() interface{} {
		addr, _ := net.ResolveTCPAddr("tcp4", s.Ip+":"+port)

		cli, err := net.DialTCP("tcp4", nil, addr)
		if err != nil {
			log.Fatalf("create client connection error: %v\n", err)
		}
		return cli
	})
	if err != nil {
		log.Fatalf("create pool error: %v\n", err)
	}
}
func (s *ConnectionPool) WriteRequest(buff []byte) []byte {
	// get conn from pool
	c, err := s.pool.Get()
	if err != nil {
		log.Printf("get client error: %v\n", err)
	}
	conn := c.(*net.TCPConn)

	commandLength := calculateCommandLen(&buff)

	tcpCommandMessage := append(commandLength, buff...)

	fmt.Println(hex.Dump(tcpCommandMessage))
	conn.Write(tcpCommandMessage)
	result := make([]byte, 2048)
	n, err := conn.Read(buff)
	if err != nil || n < 4 {
		log.Printf("read data error: %v, size: %d\n", err, n)
	}
	log.Printf("got data: %s\n", result)

	// put, back for reuse
	s.pool.Put(conn)

	// len
	log.Printf("total connections: %d\n", s.pool.Len())

	// // destroy, close all connections
	// pl.Destroy()
	return result[:n]
}
