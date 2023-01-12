package mock

import (
	"github.com/metalcorpe/payshield-rest-gopher/interfaces"
)

type TcpConnMock struct {
	interfaces.IConnectionHandler
}

func (p *TcpConnMock) WriteRequest(buff []byte) []byte {
	return buff
}
