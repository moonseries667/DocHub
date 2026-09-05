package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestLoginWithCorrectPassword(t *testing.T) {
	env := newTestEnv(t)

	body := env.login(t, "east", "alice", seedPassword)
	if body.Code != 0 {
		t.Fatalf("login code = %d, want 0", body.Code)
	}
	if body.Data.Token == "" {
		t.Fatal("token is empty")
	}
	ident, err := env.auth.Parse(body.Data.Token)
	if err != nil {
		t.Fatalf("token does not parse: %v", err)
	}
	if ident.TenantID != 1 || ident.Username != "alice" {
		t.Fatalf("identity = %+v, want tenant 1 / alice", ident)
	}
	if body.Data.ExpiresIn != int64(time.Hour.Seconds()) {
		t.Fatalf("expires_in = %d, want %d", body.Data.ExpiresIn, int64(time.Hour.Seconds()))
	}
}

func TestLoginWithWrongPassword(t *testing.T) {
	env := newTestEnv(t)

	rec := doJSON(t, env.engine, http.MethodPost, "/api/v1/login", "", map[string]string{
		"tenant_code": "east",
		"username":    "alice",
		"password":    "wrong-password",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if strings.Contains(rec.Body.String(), seedPassword) || strings.Contains(rec.Body.String(), "password") {
		t.Fatalf("response leaks password material: %s", rec.Body.String())
	}
}

// A wrong username and a wrong password must be indistinguishable, otherwise the
// endpoint tells an attacker which usernames exist.
func TestLoginUnknownUserLooksLikeWrongPassword(t *testing.T) {
	env := newTestEnv(t)

	unknown := doJSON(t, env.engine, http.MethodPost, "/api/v1/login", "", map[string]string{
		"tenant_code": "east",
		"username":    "nobody",
		"password":    seedPassword,
	})
	wrongPass := doJSON(t, env.engine, http.MethodPost, "/api/v1/login", "", map[string]string{
		"tenant_code": "east",
		"username":    "alice",
		"password":    "wrong-password",
	})
	if unknown.Code != wrongPass.Code || unknown.Body.String() != wrongPass.Body.String() {
		t.Fatalf("responses differ:\n unknown=%d %s\n wrongpass=%d %s",
			unknown.Code, unknown.Body.String(), wrongPass.Code, wrongPass.Body.String())
	}
}

// The same username in another tenant must not log in: usernames are scoped, not global.
func TestLoginRequiresMatchingTenant(t *testing.T) {
	env := newTestEnv(t)

	rec := doJSON(t, env.engine, http.MethodPost, "/api/v1/login", "", map[string]string{
		"tenant_code": "south",
		"username":    "alice",
		"password":    seedPassword,
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a user that belongs to another tenant", rec.Code)
	}
}

func TestProtectedRouteWithoutToken(t *testing.T) {
	env := newTestEnv(t)

	rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/me", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["code"] != float64(http.StatusUnauthorized) {
		t.Fatalf("body = %v, want unified 401 envelope", body)
	}
}

func TestProtectedRouteWithGarbageToken(t *testing.T) {
	env := newTestEnv(t)

	rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/me", "not-a-token", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestProtectedRouteWithExpiredToken(t *testing.T) {
	env := newTestEnv(t)

	token, _, err := env.auth.Login(t.Context(), "east", "alice", seedPassword)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	ident, err := env.auth.Parse(token)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	expired, err := env.auth.Issue(ident, -time.Minute)
	if err != nil {
		t.Fatalf("issue expired token: %v", err)
	}
	if _, err := env.auth.Parse(expired); err == nil {
		t.Fatal("expired token parsed without error")
	}

	rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/me", expired, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestTokenSignedWithAnotherSecretIsRejected(t *testing.T) {
	env := newTestEnv(t)

	forged := authWithSecret(t, "some-other-secret")
	rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/me", forged, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestMeReportsCallerIdentity(t *testing.T) {
	env := newTestEnv(t)

	token := env.login(t, "east", "alice", seedPassword).Data.Token
	rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/me", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"tenant_id":1`) || !strings.Contains(rec.Body.String(), `"username":"alice"`) {
		t.Fatalf("body = %s, want caller identity", rec.Body.String())
	}
}

// The example protected resource: alice (tenant 1) asking about bob (tenant 2)
// must not be served, and must not be told the row exists either.
func TestCrossTenantResourceIsDenied(t *testing.T) {
	env := newTestEnv(t)

	aliceToken := env.login(t, "east", "alice", seedPassword).Data.Token
	bobToken := env.login(t, "south", "bob", seedPassword).Data.Token

	// Each user sees their own roles: proves the route works at all.
	own := doJSON(t, env.engine, http.MethodGet, "/api/v1/users/1/roles", aliceToken, nil)
	if own.Code != http.StatusOK {
		t.Fatalf("own roles status = %d, want 200 (body=%s)", own.Code, own.Body.String())
	}
	if !strings.Contains(own.Body.String(), `"roles":["admin"]`) {
		t.Fatalf("own roles body = %s, want admin", own.Body.String())
	}

	// alice asking for bob's roles: bob's id exists, but not in her tenant.
	cross := doJSON(t, env.engine, http.MethodGet, "/api/v1/users/2/roles", aliceToken, nil)
	if cross.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant status = %d, want 404 (body=%s)", cross.Code, cross.Body.String())
	}
	if strings.Contains(cross.Body.String(), "admin") {
		t.Fatalf("cross-tenant response leaks role data: %s", cross.Body.String())
	}

	// bob asking for the same id is fine: the route is not broken, just scoped.
	bobOwn := doJSON(t, env.engine, http.MethodGet, "/api/v1/users/2/roles", bobToken, nil)
	if bobOwn.Code != http.StatusOK {
		t.Fatalf("bob own roles status = %d, want 200 (body=%s)", bobOwn.Code, bobOwn.Body.String())
	}
}

// Migrations must be idempotent: the server re-runs them on every boot.
func TestMigrationsAreIdempotent(t *testing.T) {
	env := newTestEnv(t)
	_ = env

	db := setupAgain(t)
	if got := countRows(t, db, "SELECT COUNT(*) FROM tenant"); got != 2 {
		t.Fatalf("tenant rows after re-apply = %d, want 2", got)
	}
}

// The schema must not carry tables the code no longer knows about.
//
// 0005_index.sql created index_metadata and index_dead_letter for the AI
// enrichment pipeline; both the file and the pipeline are gone, and 0007 drops
// what an older database still had. This asserts the end state, so a future
// change that reintroduces those tables without a reader fails here rather than
// quietly leaving dead rows behind.
func TestSchemaHasNoOrphanTables(t *testing.T) {
	env := newTestEnv(t)
	_ = env

	db := setupAgain(t)
	for _, table := range []string{"index_metadata", "index_dead_letter"} {
		var n int
		if err := db.Get(&n, `
			SELECT COUNT(*) FROM information_schema.tables
			WHERE table_schema = DATABASE() AND table_name = ?`, table); err != nil {
			t.Fatalf("check table %q: %v", table, err)
		}
		if n != 0 {
			t.Fatalf("table %q still exists although no code references it", table)
		}
	}

	// The applied set must not claim a migration file that no longer ships.
	var stale int
	if err := db.Get(&stale,
		"SELECT COUNT(*) FROM schema_migrations WHERE version = '0005_index.sql'"); err != nil {
		t.Fatalf("check stale migration row: %v", err)
	}
	if stale != 0 {
		t.Fatal("schema_migrations still records the removed 0005_index.sql")
	}
}
