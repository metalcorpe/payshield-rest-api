package interfaces

type IConnectionHandler interface {
	WriteRequest(buff []byte) []byte
}
