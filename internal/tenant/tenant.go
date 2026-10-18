// Package tenant carries the tenant a request belongs to: the identity type and
// the request-context accessors. It holds no state and no SQL on purpose — every
// package that touches data reads the tenant id from here and scopes its query.
package tenant

import "context"

// Identity is who is calling and for which tenant. It is the only thing the
// token is decoded into, and the only thing handlers should trust.
type Identity struct {
	UserID   int64  `json:"user_id"`
	TenantID int64  `json:"tenant_id"`
	Username string `json:"username"`
	Name     string `json:"name"`
}

type ctxKey struct{}

// WithIdentity pins the caller's identity to the request context.
func WithIdentity(ctx context.Context, ident Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, ident)
}

// FromContext returns the identity set by the auth middleware.
func FromContext(ctx context.Context) (Identity, bool) {
	ident, ok := ctx.Value(ctxKey{}).(Identity)
	return ident, ok
}
