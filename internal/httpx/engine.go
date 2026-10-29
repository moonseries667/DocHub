package httpx

import (
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/gin-gonic/gin"
)

// NewEngine builds the gin engine with the middleware every handler relies on.
// Routes are registered by the caller; this only guarantees the response shape.
func NewEngine(logger *slog.Logger) *gin.Engine {
	engine := gin.New()
	// requestID runs first: both loggers below attach the id to their lines, and
	// an id assigned after them would be missing from the record of exactly the
	// failures it is meant to identify.
	engine.Use(requestID(), recovery(logger), errorHandler())

	engine.NoRoute(func(c *gin.Context) {
		_ = c.Error(ErrNotFound)
	})
	return engine
}

func errorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if len(c.Errors) == 0 || c.Writer.Written() {
			return
		}
		Fail(c, c.Errors.Last().Err)
	}
}

func recovery(logger *slog.Logger) gin.HandlerFunc {
	return gin.CustomRecoveryWithWriter(nil, func(c *gin.Context, err any) {
		logger.Error("panic recovered",
			"request_id", RequestID(c.Request.Context()),
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"err", err,
			"stack", string(debug.Stack()))
		c.AbortWithStatusJSON(http.StatusInternalServerError, Response{
			Code:    http.StatusInternalServerError,
			Message: ErrInternal.Message,
		})
	})
}
