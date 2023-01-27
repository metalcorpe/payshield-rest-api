package engine

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/metalcorpe/payshield-rest-gopher/interfaces"
)

const (
	maxQueueLength   = 10_000
	numberOfAttempts = 3
)

// TcpConfig is a set of configuration for a TCP connection pool
type TcpConfig struct {
	Host         string
	Port         int
	TlsConfig    *tls.Config
	MaxIdleConns int
	MaxOpenConn  int
}

// TcpConnPool represents a pool of tcp connections
type TcpConnPool struct {
	interfaces.IConnectionHandler

	host         string
	port         int
	tlsConfig    *tls.Config
	mu           sync.Mutex          // mutex to prevent race conditions
	idleConns    map[string]*tcpConn // holds the idle connections
	requestChan  chan *connRequest   // A queue of connection requests
	numOpen      int                 // counter that tracks open connections
	maxOpenCount int
	maxIdleCount int
}

// tcpConn is a wrapper for a single tcp connection
type tcpConn struct {
	id   string       // A unique id to identify a connection
	pool *TcpConnPool // The TCP connecion pool
	conn net.Conn     // The underlying TCP connection
}

// connRequest wraps a channel to receive a connection
// and a channel to receive an error
type connRequest struct {
	connChan chan *tcpConn
	errChan  chan error
}

// put() attempts to return a used connection back to the pool
// It closes the connection if it can't do so
func (p *TcpConnPool) put(c *tcpConn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.maxIdleCount > 0 && p.maxIdleCount > len(p.idleConns) {
		p.idleConns[c.id] = c // put into the pool
	} else {
		c.conn.Close()
		c.pool.numOpen--
	}
}

// get() retrieves a TCP connection
func (p *TcpConnPool) get() (*tcpConn, error) {
	p.mu.Lock()

	// Case 1: Gets a free connection from the pool if any
	numIdle := len(p.idleConns)
	if numIdle > 0 {
		// Loop map to get one conn
		for _, c := range p.idleConns {
			// remove from pool
			delete(p.idleConns, c.id)
			p.mu.Unlock()
			return c, nil
		}
	}

	// Case 2: Queue a connection request
	if p.maxOpenCount > 0 && p.numOpen >= p.maxOpenCount {
		// Create the request
		req := &connRequest{
			connChan: make(chan *tcpConn, 1),
			errChan:  make(chan error, 1),
		}

		// Queue the request
		p.requestChan <- req

		p.mu.Unlock()

		// Waits for either
		// 1. Request fulfilled, or
		// 2. An error is returned
		select {
		case tcpConn := <-req.connChan:
			return tcpConn, nil
		case err := <-req.errChan:
			return nil, err
		}
	}
	// Case 3: Open a new connection
	p.numOpen++
	p.mu.Unlock()

	newTcpConn, err := p.openNewTcpConnection()
	if err != nil {
		p.mu.Lock()
		p.numOpen--
		p.mu.Unlock()
		return nil, err
	}

	return newTcpConn, nil
}

func (p *TcpConnPool) clear() (result bool) {
	p.mu.Lock()
	numIdle := len(p.idleConns)
	if numIdle > 0 {
		// Loop map to get one conn
		for _, c := range p.idleConns {
			// remove from pool
			delete(p.idleConns, c.id)
		}
		p.numOpen = 0
		result = true
	} else {
		result = false
	}
	p.mu.Unlock()
	return
}

// openNewTcpConnection() creates a new TCP connection at p.host and p.port
func (p *TcpConnPool) openNewTcpConnection() (*tcpConn, error) {
	var c net.Conn
	var err error
	addr := fmt.Sprintf("%s:%d", p.host, p.port)

	if p.tlsConfig != nil {
		c, err = tls.Dial("tcp", addr, p.tlsConfig)
	} else {
		c, err = net.Dial("tcp", addr)
	}
	if err != nil {
		println(err.Error())
	}
	if err != nil {
		return nil, err
	}

	return &tcpConn{
		// Use unix time as id
		id:   fmt.Sprintf("%v", time.Now().UnixNano()),
		conn: c,
		pool: p,
	}, nil
}

func (p *TcpConnPool) defaulthandleConnectionRequestCase(req *connRequest, requestDone *bool) {
	p.mu.Lock()

	// First, we try to get an idle conn.
	// If fail, we try to open a new conn.
	// If both does not work, we try again in the next loop until timeout.
	numIdle := len(p.idleConns)
	if numIdle > 0 {
		for _, c := range p.idleConns {
			delete(p.idleConns, c.id)
			p.mu.Unlock()
			req.connChan <- c // give conn
			*requestDone = true
			break
		}
	} else if p.maxOpenCount > 0 && p.numOpen < p.maxOpenCount {
		p.numOpen++
		p.mu.Unlock()

		c, err := p.openNewTcpConnection()
		if err != nil {
			p.mu.Lock()
			p.numOpen--
			p.mu.Unlock()
		} else {
			req.connChan <- c // give conn
			*requestDone = true
		}
	} else {
		p.mu.Unlock()
	}
}

// handleConnectionRequest() listens to the request queue
// and attempts to fulfil any incoming requests
func (p *TcpConnPool) handleConnectionRequest() {
	for req := range p.requestChan {
		var (
			requestDone = false
			hasTimeout  = false

			// start a 3-second timeout
			timeoutChan = time.After(3 * time.Second)
		)

		for {
			if requestDone || hasTimeout {
				break
			}
			select {
			// request timeout
			case <-timeoutChan:
				hasTimeout = true
				req.errChan <- errors.New("connection request timeout")
			default:
				p.defaulthandleConnectionRequestCase(req, &requestDone)
			}
		}
	}
}

// CreateTcpConnPool() creates a connection pool
// and starts the worker that handles connection request
func CreateTcpConnPool(cfg *TcpConfig) (*TcpConnPool, error) {
	pool := &TcpConnPool{
		host:      cfg.Host,
		port:      cfg.Port,
		tlsConfig: cfg.TlsConfig,

		idleConns:    make(map[string]*tcpConn),
		requestChan:  make(chan *connRequest, maxQueueLength),
		maxOpenCount: cfg.MaxOpenConn,
		maxIdleCount: cfg.MaxIdleConns,
	}

	go pool.handleConnectionRequest()

	return pool, nil
}

// 4 bytes
const prefixSize = 4

// createTcpBuffer() implements the TCP protocol used in this application
// A stream of TCP data to be sent over has two parts: a prefix and the actual data itself
// The prefix is a fixed length byte that states how much data is being transferred over
func createTcpBuffer(data []byte) []byte {
	// Create a buffer with size enough to hold a prefix and actual data
	buf := make([]byte, prefixSize+len(data))

	// State the total number of bytes (including prefix) to be transferred over
	binary.BigEndian.PutUint32(buf[:prefixSize], uint32(prefixSize+len(data)))

	// Copy data into the remaining buffer
	copy(buf[prefixSize:], data[:])

	return buf
}

// Read() reads the data from the underlying TCP connection
func (c *tcpConn) Read() ([]byte, error) {
	prefix := make([]byte, prefixSize)

	// Read the prefix, which contains the length of data expected
	_, err := io.ReadFull(c.conn, prefix)
	if err != nil {
		return nil, err
	}

	totalDataLength := binary.BigEndian.Uint32(prefix[:])

	// Buffer to store the actual data
	data := make([]byte, totalDataLength-prefixSize)

	// Read actual data without prefix
	_, err = io.ReadFull(c.conn, data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (p *TcpConnPool) BuildAndWriteBuffer(buff []byte) (res []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered. Error: ", r)
		}
	}()
	conn, err := p.get()
	if err != nil {
		println(err.Error())
	}
	commandLength := calculateCommandLen(&buff)

	tcpCommandMessage := append(commandLength, buff...)
	fmt.Println(hex.Dump(tcpCommandMessage))

	conn.conn.Write(tcpCommandMessage)
	result := make([]byte, 2048)
	n, err := conn.conn.Read(result)
	if err != nil {
		println(err.Error())
		return nil, err
	}
	p.put(conn)

	//log
	fmt.Println(hex.Dump(result[:n]))
	return result[:n], nil
}

func (p *TcpConnPool) WriteRequest(buff []byte) (res []byte) {
	waitBetweenRetriesInMilisec := rand.Intn(1000) // Make sure we don’t have more than one second between retries
	timeToSleep := time.Duration(waitBetweenRetriesInMilisec) * time.Millisecond
	var err error
	for i := 0; i < numberOfAttempts; i++ {
		res, err = p.BuildAndWriteBuffer(buff)
		if err == nil { // Connected to socket!
			return res
		} else {
			p.clear()
		}
		// Make sure that on the final attempt we won't wait
		if i != numberOfAttempts-1 {
			time.Sleep(timeToSleep)
			timeToSleep *= 2
		}
	}
	// If we reached here it means we failed to connect in all the atttempts
	return nil
}
