package httpx

import (
	"context"
	"crypto/rand"
	"encoding/hex"

	"github.com/gin-gonic/gin"
)

// RequestIDHeader carries the correlation id in and out of the service.
const RequestIDHeader = "X-Request-Id"

// requestIDKey is unexported so nothing outside this package can collide with it
// or forge a value; the id is read through RequestID.
type requestIDKey struct{}

// maxRequestIDLen bounds a caller-supplied id. A header long enough to bloat
// every log line is not a correlation id, it is a payload.
const maxRequestIDLen = 64

// RequestID returns the id attached to ctx, or "" when there is none (a code path
// that never went through the engine, such as a direct service call in a test).
func RequestID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// withRequestID stores the id on ctx.
func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// requestID accepts the caller's id when it is well formed and generates one
// otherwise, then echoes the value back.
//
// Accepting the caller's id is what makes a trace span multiple services; the
// sanitising is what stops it becoming a log-injection vector. Header values are
// attacker-controlled: without the character filter, a newline in the id would
// split a structured log entry in two.
func requestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := sanitizeRequestID(c.GetHeader(RequestIDHeader))
		if id == "" {
			id = newRequestID()
		}
		c.Request = c.Request.WithContext(withRequestID(c.Request.Context(), id))
		c.Header(RequestIDHeader, id)
		c.Next()
	}
}

// sanitizeRequestID keeps only characters that are safe in a log field and a
// header, and drops anything longer than the limit.
func sanitizeRequestID(raw string) string {
	if raw == "" || len(raw) > maxRequestIDLen {
		return ""
	}
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == ':':
		default:
			return ""
		}
	}
	return raw
}

// newRequestID returns 16 hex characters. Collisions across one service's logs
// are not a concern; this is a correlation handle, not a unique key.
func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is not something this middleware can fix, and an
		// empty id is still better than a panic in the request path.
		return ""
	}
	return hex.EncodeToString(b[:])
}
