package integration

import (
	"context"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"

	"godochub/internal/auth"
	"godochub/internal/migrate"
	"godochub/internal/tenant"
)

// containsAll reports whether body contains every substring.
func containsAll(body string, wants ...string) bool {
	for _, w := range wants {
		if !strings.Contains(body, w) {
			return false
		}
	}
	return true
}

// urlQuery escapes one query parameter value.
func urlQuery(v string) string { return url.QueryEscape(v) }

// newForger builds a Service with a secret the server under test does not use,
// so a token it signs must be rejected no matter how well-formed it looks.
func newForger(t *testing.T, otherSecret string) *auth.Service {
	t.Helper()
	return auth.NewService(nil, otherSecret, time.Hour)
}

// authWithSecret signs an identity with a secret the server does not use.
func authWithSecret(t *testing.T, otherSecret string) string {
	t.Helper()
	token, err := newForger(t, otherSecret).Issue(
		tenant.Identity{UserID: 1, TenantID: 1, Username: "alice"}, time.Hour)
	if err != nil {
		t.Fatalf("forge token: %v", err)
	}
	return token
}

// setupAgain re-applies migrations on an already migrated database to prove that
// running the server twice does not corrupt the seed data.
func setupAgain(t *testing.T) *sqlx.DB {
	t.Helper()
	db, err := sqlx.Open("mysql", testDSN())
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := migrate.Apply(ctx, db, filepath.Join("..", "..", "migrations")); err != nil {
		t.Fatalf("re-apply migrations: %v", err)
	}
	return db
}

func countRows(t *testing.T, db *sqlx.DB, query string) int {
	t.Helper()
	var n int
	if err := db.Get(&n, query); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// carolID is the id seedUserWithoutRole always creates.
const carolID int64 = 9

// openTestDB opens the already-migrated test database. It is the escape hatch for
// fixtures the API does not expose yet, such as ACL grants.
func openTestDB(t *testing.T) *sqlx.DB {
	t.Helper()
	db, err := sqlx.Open("mysql", testDSN())
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	return db
}

// ageSession pushes an upload session's lease back, so the reclaimer can be
// exercised without sleeping for hours.
func ageSession(t *testing.T, uploadID int64, hours int) {
	t.Helper()
	db, err := sqlx.Open("mysql", testDSN())
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(
		"UPDATE upload_session SET updated_at = (NOW() - INTERVAL ? HOUR) WHERE id = ?",
		hours, uploadID); err != nil {
		t.Fatalf("age upload session %d: %v", uploadID, err)
	}
}

// seedPasswordHash is what migrations/0001_init.sql stores for the seed users, so
// a fixture user built with it can log in with seedPassword.
const seedPasswordHash = "$2a$10$DeflL3mpnEEEcABJvoZMPeyjkrNNd.GIP/CqObNFw6aKhHI8FIinq"

// seedUserWithoutRole inserts a user that holds no role, so the "exists but has
// no roles" path can be told apart from "not in this tenant".
func seedUserWithoutRole(t *testing.T, username string, tenantID int64) {
	t.Helper()
	db, err := sqlx.Open("mysql", testDSN())
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`
		INSERT INTO `+"`user`"+` (id, tenant_id, username, password_hash, display_name)
		VALUES (?, ?, ?, ?, ?)`,
		carolID, tenantID, username, seedPasswordHash, username)
	if err != nil {
		t.Fatalf("seed user %q: %v", username, err)
	}
}

// seedRoleWithoutPermission creates a role that grants no permission code and a
// user holding it. It returns both ids, so a test can add an ACL allow that the
// RBAC layer is supposed to veto.
func seedRoleWithoutPermission(t *testing.T, tenantID int64, roleCode, username string) (roleID, userID int64) {
	t.Helper()
	db, err := sqlx.Open("mysql", testDSN())
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	defer db.Close()

	res, err := db.Exec("INSERT INTO role (tenant_id, code, name) VALUES (?, ?, ?)",
		tenantID, roleCode, roleCode)
	if err != nil {
		t.Fatalf("seed role %q: %v", roleCode, err)
	}
	if roleID, err = res.LastInsertId(); err != nil {
		t.Fatalf("role id of %q: %v", roleCode, err)
	}

	res, err = db.Exec(`
		INSERT INTO `+"`user`"+` (tenant_id, username, password_hash, display_name)
		VALUES (?, ?, ?, ?)`,
		tenantID, username, seedPasswordHash, username)
	if err != nil {
		t.Fatalf("seed user %q: %v", username, err)
	}
	if userID, err = res.LastInsertId(); err != nil {
		t.Fatalf("user id of %q: %v", username, err)
	}

	if _, err := db.Exec("INSERT INTO user_role (user_id, role_id) VALUES (?, ?)", userID, roleID); err != nil {
		t.Fatalf("assign role %d to user %d: %v", roleID, userID, err)
	}
	return roleID, userID
}
