package interfaces

type IConnectionHandler interface {
	WriteRequest(buff []byte) (n int, err error)
	ReadResponce(buff []byte) (n int, err error)
}
