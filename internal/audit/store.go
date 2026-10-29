// Package audit records who changed a permission, and when.
//
// It exists because acl_entry and role_permission only hold the current state.
// "Who revoked this and when" is the first question after a dispute, and the
// only place it can come from is a trail written as the change happens.
//
// This package has no HTTP surface of its own: it is a store, imported by the two
// packages that mutate permissions (perm and tenant) and by the tenant handler
// that exposes the trail. Keeping gin out of it is what lets perm import it —
// perm already imports tenant for the request identity, so an audit package that
// reached back into tenant would close a cycle.
package audit

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"
)

// Actions. Constants rather than literals so a typo is a compile error instead of
// a row nobody can query.
const (
	ActionACLSet     = "acl_set"
	ActionACLDelete  = "acl_delete"
	ActionRoleCreate = "role_create"
	ActionRoleDelete = "role_delete"
	ActionRoleGrant  = "role_grant"
	ActionRoleRevoke = "role_revoke"
	// ActionRolePermissions covers a rewrite of a role's permission set.
	ActionRolePermissions = "role_permissions"
)

// Entry is one recorded change. The zero value of the fields that do not apply to
// a given action is stored as-is, so a role grant carries an empty path and a
// role id in Detail.
type Entry struct {
	ID            int64  `db:"id" json:"id"`
	TenantID      int64  `db:"tenant_id" json:"tenant_id"`
	ActorUserID   int64  `db:"actor_user_id" json:"actor_user_id"`
	ActorUsername string `db:"actor_username" json:"actor_username"`
	Action        string `db:"action" json:"action"`
	SubjectKind   string `db:"subject_kind" json:"subject_kind"`
	SubjectID     int64  `db:"subject_id" json:"subject_id"`
	Path          string `db:"path" json:"path,omitempty"`
	AllowMask     int    `db:"allow_mask" json:"allow_mask,omitempty"`
	DenyMask      int    `db:"deny_mask" json:"deny_mask,omitempty"`
	Detail        string `db:"detail" json:"detail,omitempty"`
	CreatedAt     string `db:"created_at" json:"created_at"`
}

// Store writes and reads the trail.
type Store struct {
	db *sqlx.DB
}

func NewStore(db *sqlx.DB) *Store {
	return &Store{db: db}
}

// Record appends one row.
//
// The caller decides what to do with an error. The handlers log it and finish the
// request anyway: the change has already been applied by the time this runs, so
// failing the response would invite the caller to retry a mutation that happened,
// which is worse than a gap in the trail.
func (s *Store) Record(ctx context.Context, e Entry) error {
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO permission_audit
			(tenant_id, actor_user_id, actor_username, action,
			 subject_kind, subject_id, path, allow_mask, deny_mask, detail)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.TenantID, e.ActorUserID, e.ActorUsername, e.Action,
		e.SubjectKind, e.SubjectID, e.Path, e.AllowMask, e.DenyMask, e.Detail); err != nil {
		return fmt.Errorf("record audit %q: %w", e.Action, err)
	}
	return nil
}

// List returns one tenant's trail, newest first. Tenant scoping is not optional:
// the trail names paths and users, so a missing WHERE here would leak both.
func (s *Store) List(ctx context.Context, tenantID int64, limit, offset int) ([]Entry, error) {
	out := []Entry{}
	if err := s.db.SelectContext(ctx, &out, `
		SELECT id, tenant_id, actor_user_id, actor_username, action,
		       subject_kind, subject_id, path, allow_mask, deny_mask, detail,
		       DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%sZ') AS created_at
		FROM permission_audit
		WHERE tenant_id = ?
		ORDER BY id DESC
		LIMIT ? OFFSET ?`, tenantID, limit, offset); err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	return out, nil
}
