package httpx

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Error carries both the message shown to the client and the status it maps to.
// Handlers return it through c.Error; the middleware renders it.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string {
	return e.Message
}

// NewError builds a client-visible error. The server logger is not touched here;
// Fail decides what gets recorded.
func NewError(status int, message string) *Error {
	return &Error{Status: status, Message: message}
}

var (
	ErrNotFound       = NewError(http.StatusNotFound, "resource not found")
	ErrUnauthorized   = NewError(http.StatusUnauthorized, "unauthorized")
	ErrForbidden      = NewError(http.StatusForbidden, "forbidden")
	ErrInvalidRequest = NewError(http.StatusBadRequest, "invalid request")
	ErrInternal       = NewError(http.StatusInternalServerError, "internal server error")
)

// Fail renders err as the unified body. Anything that is not an *Error becomes a
// generic 500 so internal details never reach the client.
//
// 5xx responses are logged with the original error: the client is told nothing,
// so the log is the only place the cause survives. 4xx are client mistakes and
// would only add noise.
func Fail(c *gin.Context, err error) {
	var apiErr *Error
	if !errors.As(err, &apiErr) {
		apiErr = ErrInternal
	}
	if apiErr.Status >= http.StatusInternalServerError {
		slog.Error("request failed",
			"request_id", RequestID(c.Request.Context()),
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"err", err)
	}
	c.AbortWithStatusJSON(apiErr.Status, Response{
		Code:    apiErr.Status,
		Message: apiErr.Message,
	})
}
