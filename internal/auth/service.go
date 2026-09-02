package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/bcrypt"

	"godochub/internal/httpx"
	"godochub/internal/tenant"
)

var (
	ErrInvalidCredentials = errors.New("auth: invalid credentials")
	ErrInvalidToken       = errors.New("auth: invalid token")
)

// userRecord is the row the login flow needs; the hash never leaves this package.
type userRecord struct {
	ID           int64  `db:"id"`
	TenantID     int64  `db:"tenant_id"`
	Username     string `db:"username"`
	PasswordHash string `db:"password_hash"`
	DisplayName  string `db:"display_name"`
}

type Service struct {
	db     *sqlx.DB
	secret []byte
	ttl    time.Duration
}

func NewService(db *sqlx.DB, secret string, ttl time.Duration) *Service {
	return &Service{db: db, secret: []byte(secret), ttl: ttl}
}

// CloseForTest closes the underlying pool so a caller can observe how the
// service behaves against an unreachable database. That path is otherwise only
// reachable by stopping a real MySQL instance, which a test cannot do portably.
func (s *Service) CloseForTest() {
	if s.db != nil {
		_ = s.db.Close()
	}
}

// Login verifies the password and returns a signed token plus the identity it
// encodes. A wrong username and a wrong password answer identically: telling
// them apart hands out a user enumeration oracle for free.
//
// Usernames are unique per tenant, not globally, so the login request carries
// the tenant code and the query joins through it.
func (s *Service) Login(ctx context.Context, tenantCode, username, password string) (string, tenant.Identity, error) {
	var u userRecord
	err := s.db.GetContext(ctx, &u, `
		SELECT u.id, u.tenant_id, u.username, u.password_hash, u.display_name
		FROM `+"`user`"+` u
		JOIN tenant t ON t.id = u.tenant_id
		WHERE t.code = ? AND u.username = ? AND u.status = 1
		LIMIT 1`, tenantCode, username)
	if errors.Is(err, sql.ErrNoRows) {
		return "", tenant.Identity{}, ErrInvalidCredentials
	}
	if err != nil {
		return "", tenant.Identity{}, fmt.Errorf("query user: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return "", tenant.Identity{}, ErrInvalidCredentials
	}

	ident := tenant.Identity{UserID: u.ID, TenantID: u.TenantID, Username: u.Username, Name: u.DisplayName}
	token, err := s.Issue(ident, s.ttl)
	if err != nil {
		return "", tenant.Identity{}, err
	}
	return token, ident, nil
}

type claims struct {
	TenantID int64  `json:"tid"`
	Username string `json:"usr"`
	Name     string `json:"nam"`
	jwt.RegisteredClaims
}

// Issue signs a token for ident with the given lifetime. A negative ttl yields
// an already-expired token, which is how the expiry test gets one.
func (s *Service) Issue(ident tenant.Identity, ttl time.Duration) (string, error) {
	now := time.Now()
	c := claims{
		TenantID: ident.TenantID,
		Username: ident.Username,
		Name:     ident.Name,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   fmt.Sprintf("%d", ident.UserID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(s.secret)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return token, nil
}

// Parse validates signature and expiry, then rebuilds the identity.
func (s *Service) Parse(token string) (tenant.Identity, error) {
	var c claims
	_, err := jwt.ParseWithClaims(token, &c, func(t *jwt.Token) (any, error) {
		return s.secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		return tenant.Identity{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	var userID int64
	if _, err := fmt.Sscanf(c.Subject, "%d", &userID); err != nil || userID == 0 {
		return tenant.Identity{}, fmt.Errorf("%w: bad subject", ErrInvalidToken)
	}
	if c.TenantID == 0 {
		return tenant.Identity{}, fmt.Errorf("%w: missing tenant", ErrInvalidToken)
	}
	return tenant.Identity{
		UserID:   userID,
		TenantID: c.TenantID,
		Username: c.Username,
		Name:     c.Name,
	}, nil
}

// Middleware rejects anything without a valid bearer token and pins the
// resulting identity to the request context for downstream handlers.
//
// Abort is not optional: gin's Next() is a loop, so a middleware that merely
// returns lets the next handler run anyway. Without it, a handler that parses
// path parameters before reading the identity answers 400 instead of 401 — and
// one that forgets to re-check becomes an unauthenticated entry point.
func Middleware(s *Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := bearerToken(c.GetHeader("Authorization"))
		if err != nil {
			c.Abort()
			_ = c.Error(httpx.ErrUnauthorized)
			return
		}
		ident, err := s.Parse(token)
		if err != nil {
			c.Abort()
			_ = c.Error(httpx.ErrUnauthorized)
			return
		}
		c.Request = c.Request.WithContext(tenant.WithIdentity(c.Request.Context(), ident))
		c.Next()
	}
}

func bearerToken(header string) (string, error) {
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", errors.New("auth: missing bearer token")
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return "", errors.New("auth: empty bearer token")
	}
	return token, nil
}
