package integration

import (
	"net/http"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"

	"godochub/internal/auth"
	"godochub/internal/httpx"
)

// A database outage during login must not look like a wrong password.
//
// The handler used to map every error from the login service to 401. That tells
// the caller to check credentials they typed correctly, and because 4xx
// responses are deliberately not logged, a real outage left no trace in the
// logs — the operator would see a stream of "wrong password" and no error line.
//
// The fault is injected by pointing a login service at a database handle whose
// DSN is unreachable, rather than by closing the shared pool: the rest of the
// env keeps working, and the failure mode is the same one a dead MySQL produces.
func TestLoginDuringDatabaseOutageIsNot401(t *testing.T) {
	env := newTestEnv(t)

	dead, err := sqlx.Open("mysql", "root:rootpass@tcp(127.0.0.1:1)/none?parseTime=true&timeout=2s")
	if err != nil {
		t.Fatalf("open unreachable pool: %v", err)
	}
	t.Cleanup(func() { _ = dead.Close() })

	// Swap in a service bound to the dead pool for the duration of one request.
	brokenAuth := auth.NewService(dead, "test-secret-not-for-production", time.Hour)
	engine := httpx.NewEngine(testLogger())
	engine.POST("/api/v1/login", auth.NewHandler(brokenAuth).Login)

	rec := doJSON(t, engine, http.MethodPost, "/api/v1/login", "", map[string]string{
		"tenant_code": "east",
		"username":    "alice",
		"password":    seedPassword,
	})
	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("login with the database down = 401, which reads as a wrong password; body=%s", rec.Body.String())
	}
	if rec.Code < 500 {
		t.Fatalf("login with the database down = %d, want a 5xx (body=%s)", rec.Code, rec.Body.String())
	}
	_ = env
}

// The same distinction on the happy path: a genuinely wrong password stays 401.
func TestWrongPasswordIsStill401(t *testing.T) {
	env := newTestEnv(t)
	rec := doJSON(t, env.engine, http.MethodPost, "/api/v1/login", "", map[string]string{
		"tenant_code": "east",
		"username":    "alice",
		"password":    "definitely-not-it",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password = %d, want 401 (body=%s)", rec.Code, rec.Body.String())
	}
}
