package tenant

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	mysqldriver "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUsernameTaken = errors.New("tenant: username already used in this tenant")
	ErrRoleNotFound  = errors.New("tenant: role not found in this tenant")
	ErrQuotaExceeded = errors.New("tenant: storage quota exceeded")
)

// User is one account in a tenant. The password hash never leaves this package:
// every exported shape here omits it, so a handler cannot leak it by accident.
type User struct {
	ID          int64  `db:"id" json:"id"`
	Username    string `db:"username" json:"username"`
	DisplayName string `db:"display_name" json:"display_name"`
	Status      int    `db:"status" json:"status"`
	CreatedAt   string `db:"created_at" json:"created_at"`
}

// Usage is one tenant's storage footprint against its quota.
type Usage struct {
	TenantID   int64 `db:"tenant_id" json:"tenant_id"`
	FileCount  int64 `db:"file_count" json:"file_count"`
	UsedBytes  int64 `db:"used_bytes" json:"used_bytes"`
	QuotaBytes int64 `db:"quota_bytes" json:"quota_bytes"`
	// Unlimited is explicit rather than "quota_bytes == 0": a client that renders
	// a progress bar should not have to know the sentinel.
	Unlimited bool `json:"unlimited"`
}

// Remaining reports how much room is left, or -1 when the tenant has no quota.
func (u Usage) Remaining() int64 {
	if u.Unlimited {
		return -1
	}
	if u.QuotaBytes <= u.UsedBytes {
		return 0
	}
	return u.QuotaBytes - u.UsedBytes
}

// CreateUser adds an account to tenantID. The caller passes a plaintext password
// that is hashed here: a handler that hashed it itself would be a second place
// where the bcrypt cost could drift.
func (s *Store) CreateUser(ctx context.Context, tenantID int64, username, displayName, password string) (*User, error) {
	if len(password) < MinPasswordLength {
		return nil, fmt.Errorf("tenant: password shorter than %d characters", MinPasswordLength)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	res, err := s.db.ExecContext(ctx, `
		INSERT INTO `+"`user`"+` (tenant_id, username, password_hash, display_name)
		VALUES (?, ?, ?, ?)`, tenantID, username, string(hash), displayName)
	if err != nil {
		if isDuplicate(err) {
			return nil, ErrUsernameTaken
		}
		return nil, fmt.Errorf("create user %q: %w", username, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("user id of %q: %w", username, err)
	}
	return &User{ID: id, Username: username, DisplayName: displayName, Status: 1}, nil
}

// ListUsers returns the accounts of one tenant. The query is tenant-scoped like
// every other read in this package: a missing WHERE clause here would turn the
// endpoint into a cross-tenant directory.
func (s *Store) ListUsers(ctx context.Context, tenantID int64, limit, offset int) ([]User, error) {
	out := []User{}
	if err := s.db.SelectContext(ctx, &out, `
		SELECT id, username, display_name, status,
		       DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%sZ') AS created_at
		FROM `+"`user`"+`
		WHERE tenant_id = ?
		ORDER BY id
		LIMIT ? OFFSET ?`, tenantID, limit, offset); err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return out, nil
}

// AssignRole grants one role of this tenant to one user of this tenant. Both
// sides are checked against tenantID: a role id from another tenant would
// otherwise grant permissions that tenant defined, which is the isolation the
// whole ACL layer rests on.
func (s *Store) AssignRole(ctx context.Context, tenantID, userID, roleID int64) error {
	var exists int
	err := s.db.GetContext(ctx, &exists,
		"SELECT 1 FROM role WHERE id = ? AND tenant_id = ? LIMIT 1", roleID, tenantID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrRoleNotFound
	}
	if err != nil {
		return fmt.Errorf("check role %d: %w", roleID, err)
	}
	if err := s.checkUser(ctx, tenantID, userID); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx,
		"INSERT IGNORE INTO user_role (user_id, role_id) VALUES (?, ?)", userID, roleID); err != nil {
		return fmt.Errorf("assign role %d to user %d: %w", roleID, userID, err)
	}
	return nil
}

// RevokeRole removes one grant. A grant that is not there is not an error: the
// caller asked for the end state, and the end state holds.
func (s *Store) RevokeRole(ctx context.Context, tenantID, userID, roleID int64) (bool, error) {
	if err := s.checkUser(ctx, tenantID, userID); err != nil {
		return false, err
	}
	res, err := s.db.ExecContext(ctx,
		"DELETE FROM user_role WHERE user_id = ? AND role_id = ?", userID, roleID)
	if err != nil {
		return false, fmt.Errorf("revoke role %d from user %d: %w", roleID, userID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("count revoked grants: %w", err)
	}
	return n > 0, nil
}

// RolesOfTenant lists the roles defined by one tenant, so a client can pick a
// role id without reading the database.
func (s *Store) RolesOfTenant(ctx context.Context, tenantID int64) ([]Role, error) {
	out := []Role{}
	if err := s.db.SelectContext(ctx, &out,
		"SELECT id, code, name FROM role WHERE tenant_id = ? ORDER BY id", tenantID); err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	return out, nil
}

// Role is one role row as the API exposes it.
type Role struct {
	ID   int64  `db:"id" json:"id"`
	Code string `db:"code" json:"code"`
	Name string `db:"name" json:"name"`
}

// checkUser confirms the user belongs to tenantID before any write touches it.
func (s *Store) checkUser(ctx context.Context, tenantID, userID int64) error {
	var exists int
	err := s.db.GetContext(ctx, &exists,
		"SELECT 1 FROM `user` WHERE id = ? AND tenant_id = ? LIMIT 1", userID, tenantID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("check user %d: %w", userID, err)
	}
	return nil
}

// Usage reports one tenant's footprint and ceiling.
func (s *Store) Usage(ctx context.Context, tenantID int64) (Usage, error) {
	var u Usage
	err := s.db.GetContext(ctx, &u, `
		SELECT t.id AS tenant_id,
		       COALESCE(f.file_count, 0) AS file_count,
		       COALESCE(f.used_bytes, 0) AS used_bytes,
		       t.quota_bytes             AS quota_bytes
		FROM tenant t
		LEFT JOIN (
		    SELECT tenant_id, COUNT(*) AS file_count, COALESCE(SUM(size), 0) AS used_bytes
		    FROM file
		    WHERE tenant_id = ?
		    GROUP BY tenant_id
		) f ON f.tenant_id = t.id
		WHERE t.id = ?`, tenantID, tenantID)
	if errors.Is(err, sql.ErrNoRows) {
		return Usage{}, ErrNotFound
	}
	if err != nil {
		return Usage{}, fmt.Errorf("query usage: %w", err)
	}
	u.Unlimited = u.QuotaBytes == 0
	return u, nil
}

// ReserveBytes reports whether size more bytes fit in the tenant's quota.
//
// It is a check, not a reservation: two concurrent uploads can both pass and
// both land, overshooting the quota by up to one file each. Making it exact
// would need a row lock held across the object write, which would serialise
// every upload of a tenant behind a database transaction for a limit that is
// advisory in the first place. The check is here so a tenant cannot quietly fill
// the bucket; the residual overrun is bounded and documented.
func (s *Store) ReserveBytes(ctx context.Context, tenantID, size int64) error {
	u, err := s.Usage(ctx, tenantID)
	if err != nil {
		return err
	}
	if u.Unlimited {
		return nil
	}
	if u.UsedBytes+size > u.QuotaBytes {
		return fmt.Errorf("%w: %d of %d bytes used, %d requested",
			ErrQuotaExceeded, u.UsedBytes, u.QuotaBytes, size)
	}
	return nil
}

// MinPasswordLength is the floor the create-user path enforces. It lives here so
// the rule sits next to the hashing that makes it meaningful.
const MinPasswordLength = 8

// isDuplicate reports whether err is MySQL's unique-key violation (1062).
//
// The driver exposes the code as a field on *mysql.MySQLError, not as a method,
// so errors.As against a numbered interface silently never matches. Matching the
// driver's type is the honest way to do this; importing it here keeps the
// knowledge of "1062 means duplicate" in one place instead of string-matching an
// error message.
func isDuplicate(err error) bool {
	var mysqlErr *mysqldriver.MySQLError
	if errors.As(err, &mysqlErr) {
		return mysqlErr.Number == 1062
	}
	return false
}
