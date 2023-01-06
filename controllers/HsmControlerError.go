package controllers

import (
	"net/http"

	"github.com/go-chi/render"
	"github.com/metalcorpe/payshield-rest-gopher/engine"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ErrResponse struct {
	Err            error `js:"-"`   // low-level runtime error
	HTTPStatusCode int   `json:"-"` // http response status code

	StatusText string `json:"status"`          // user-level status message
	AppCode    int64  `json:"code,omitempty"`  // application-specific error code
	ErrorText  string `json:"error,omitempty"` // application-level error message, for debugging
}

func (e *ErrResponse) Render(w http.ResponseWriter, r *http.Request) error {
	render.Status(r, e.HTTPStatusCode)
	return nil
}

func ErrRender(err error) render.Renderer {
	return &ErrResponse{
		Err:            err,
		HTTPStatusCode: 422,
		StatusText:     engine.CheckErrorCode(err.Error()),
		ErrorText:      err.Error(),
	}
}

func ErrRenderGrpc(err error) error {
	return status.Error(codes.FailedPrecondition, engine.CheckErrorCode(err.Error()))
}
