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
	engine.Use(recovery(logger), errorHandler())

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
		logger.Error("panic recovered", "err", err, "stack", string(debug.Stack()))
		c.AbortWithStatusJSON(http.StatusInternalServerError, Response{
			Code:    http.StatusInternalServerError,
			Message: ErrInternal.Message,
		})
	})
}
