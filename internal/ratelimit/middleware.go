package ratelimit

import (
	"log/slog"
	"math"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"godochub/internal/httpx"
	"godochub/internal/tenant"
)

// Middleware takes one token per request from the caller's tenant bucket.
//
// The limiter is per tenant, not per user or IP: the product constraint is that
// one tenant cannot starve the others, and a user-level bucket would just move
// the fairness problem one level down.
func Middleware(limiter *Limiter, logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		ident, ok := tenant.FromContext(c.Request.Context())
		if !ok {
			// Unauthenticated requests never reach here (auth runs first), but a
			// route mounted without auth must not silently skip the limit.
			_ = c.Error(httpx.ErrUnauthorized)
			return
		}

		result, err := limiter.Allow(c.Request.Context(), ident.TenantID)
		if err != nil {
			// Failing open keeps the API usable when Redis is down; the error is
			// logged so a real outage is still visible.
			logger.Error("rate limit check failed, allowing request", "err", err, "tenant", ident.TenantID)
			c.Next()
			return
		}

		c.Header("X-RateLimit-Limit", strconv.Itoa(int(limiter.capacity)))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))

		if !result.Allowed {
			seconds := int(math.Ceil(result.RetryAfter.Seconds()))
			if seconds < 1 {
				seconds = 1
			}
			c.Header("Retry-After", strconv.Itoa(seconds))
			c.Abort()
			_ = c.Error(httpx.NewError(http.StatusTooManyRequests,
				"tenant rate limit exceeded, retry after "+strconv.Itoa(seconds)+"s"))
			return
		}
		c.Next()
	}
}
