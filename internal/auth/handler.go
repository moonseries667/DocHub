package auth

import (
	"errors"

	"github.com/gin-gonic/gin"

	"godochub/internal/httpx"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

type loginRequest struct {
	TenantCode string `json:"tenant_code" binding:"required"`
	Username   string `json:"username" binding:"required"`
	Password   string `json:"password" binding:"required"`
}

type loginResponse struct {
	Token string `json:"token"`
	// ExpiresIn is seconds, so clients do not have to parse the token to refresh.
	ExpiresIn int64 `json:"expires_in"`
	User      any   `json:"user"`
}

// Login trades credentials for a token. Both the response and the logs carry the
// identity only; the password and its hash never leave this function.
func (h *Handler) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(httpx.ErrInvalidRequest)
		return
	}

	token, ident, err := h.service.Login(c.Request.Context(), req.TenantCode, req.Username, req.Password)
	if err != nil {
		// Only a genuine credential mismatch is a 401. Anything else — the
		// database being unreachable, a broken connection pool — is a server
		// fault and must not be reported as "wrong password": that tells the
		// caller to check something they cannot fix, and because 4xx responses
		// are deliberately not logged, the real cause would leave no trace.
		if errors.Is(err, ErrInvalidCredentials) {
			_ = c.Error(httpx.ErrUnauthorized)
			return
		}
		_ = c.Error(err)
		return
	}

	httpx.OK(c, loginResponse{
		Token:     token,
		ExpiresIn: int64(h.service.ttl.Seconds()),
		User:      ident,
	})
}
