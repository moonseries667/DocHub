package integration

import (
	"encoding/json"
	"net/http"
	"testing"
)

// "No roles" and "not in this tenant" are different answers: the first is a 200
// with an empty list, the second is a 404.
func TestUserWithoutRolesIsNot404(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	// carol exists in tenant 1 and holds no role.
	seedUserWithoutRole(t, "carol", 1)

	rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/users/"+itoa(carolID)+"/roles", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("roleless user = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	var body struct {
		Data struct {
			Roles []string `json:"roles"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Data.Roles == nil {
		t.Fatalf("roles is null, want an empty array: %s", rec.Body.String())
	}
	if len(body.Data.Roles) != 0 {
		t.Fatalf("roles = %v, want empty", body.Data.Roles)
	}

	// A user from another tenant is still a 404.
	cross := doJSON(t, env.engine, http.MethodGet, "/api/v1/users/2/roles", token, nil)
	if cross.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant user = %d, want 404", cross.Code)
	}
}

// Listing echoes the normalized directory and answers [] for an empty one.
func TestListEchoesNormalizedDirAndEmptyArray(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/files?dir=a//b/", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	var body struct {
		Data struct {
			Dir   string            `json:"dir"`
			Files []json.RawMessage `json:"files"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Data.Dir != "/a/b" {
		t.Fatalf("dir = %q, want the normalized /a/b", body.Data.Dir)
	}
	if body.Data.Files == nil {
		t.Fatalf("files is null, want []: %s", rec.Body.String())
	}
	if len(body.Data.Files) != 0 {
		t.Fatalf("files = %d entries, want 0", len(body.Data.Files))
	}
}
