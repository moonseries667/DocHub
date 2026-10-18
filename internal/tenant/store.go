package tenant

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"
)

// ErrNotFound means the user does not exist in this tenant. It is deliberately
// distinct from "the user exists but holds no roles", which is a normal 200 with
// an empty list: answering 404 there would claim the user is in another tenant.
var ErrNotFound = errors.New("tenant: not found")

// Store reads tenant-owned rows. Every method takes the tenant id first: a query
// that forgets to scope by tenant is the bug this project cannot afford, so the
// signature makes the scope impossible to overlook.
type Store struct {
	db *sqlx.DB
}

func NewStore(db *sqlx.DB) *Store {
	return &Store{db: db}
}

// RolesOf returns the role codes of one user, only if that user belongs to tenantID.
// A user with no roles yields an empty slice and a nil error.
func (s *Store) RolesOf(ctx context.Context, tenantID, userID int64) ([]string, error) {
	var exists int
	err := s.db.GetContext(ctx, &exists,
		"SELECT 1 FROM `user` WHERE id = ? AND tenant_id = ? LIMIT 1", userID, tenantID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("check user %d: %w", userID, err)
	}

	roles := []string{}
	if err := s.db.SelectContext(ctx, &roles, `
		SELECT r.code
		FROM role r
		JOIN user_role ur ON ur.role_id = r.id
		WHERE ur.user_id = ? AND r.tenant_id = ?
		ORDER BY r.code`, userID, tenantID); err != nil {
		return nil, fmt.Errorf("query roles: %w", err)
	}
	return roles, nil
}
