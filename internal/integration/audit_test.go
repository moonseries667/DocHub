package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"godochub/internal/httpx"
	"godochub/internal/perm"
)

type auditList struct {
	Data struct {
		Entries []struct {
			ActorUsername string `json:"actor_username"`
			Action        string `json:"action"`
			SubjectKind   string `json:"subject_kind"`
			SubjectID     int64  `json:"subject_id"`
			Path          string `json:"path"`
			AllowMask     int    `json:"allow_mask"`
			DenyMask      int    `json:"deny_mask"`
			Detail        string `json:"detail"`
		} `json:"entries"`
		Limit int `json:"limit"`
	} `json:"data"`
}

// fetchAudit reads the tenant's trail through the API.
func fetchAudit(t *testing.T, env *testEnv, token string) auditList {
	t.Helper()
	rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/audit?limit=200", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list audit = %d (body=%s)", rec.Code, rec.Body.String())
	}
	var out auditList
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode audit: %v", err)
	}
	return out
}

// An ACL change must leave a row naming who did it. The table it mutates holds
// only the current state, so this is the only record that the change happened.
func TestAuditRecordsACLChanges(t *testing.T) {
	env := newTestEnv(t)
	alice := env.login(t, "east", "alice", seedPassword).Data.Token

	setACL(t, env, alice, "user", 2, "/audited", []string{"read", "write"}, true)

	list := fetchAudit(t, env, alice)
	if len(list.Data.Entries) == 0 {
		t.Fatal("an ACL write produced no audit row")
	}
	first := list.Data.Entries[0]
	if first.Action != "acl_set" {
		t.Fatalf("action = %q, want acl_set", first.Action)
	}
	if first.ActorUsername != "alice" {
		t.Fatalf("actor = %q, want alice", first.ActorUsername)
	}
	if first.Path != "/audited" || first.SubjectKind != "user" || first.SubjectID != 2 {
		t.Fatalf("row does not describe the change: %+v", first)
	}
	if first.DenyMask != 3 {
		t.Fatalf("deny_mask = %d, want 3 (read|write)", first.DenyMask)
	}

	// Removing the row is a separate event, and the trail keeps both.
	if rec := doJSON(t, env.engine, http.MethodDelete,
		"/api/v1/permissions/acl?subject_kind=user&subject_id=2&path=%2Faudited", alice, nil); rec.Code != http.StatusOK {
		t.Fatalf("delete acl = %d (body=%s)", rec.Code, rec.Body.String())
	}
	list = fetchAudit(t, env, alice)
	if len(list.Data.Entries) < 2 {
		t.Fatalf("trail has %d rows, want the set and the delete", len(list.Data.Entries))
	}
	if list.Data.Entries[0].Action != "acl_delete" {
		t.Fatalf("newest action = %q, want acl_delete", list.Data.Entries[0].Action)
	}
	if !containsAll(list.Data.Entries[0].Detail, "removed=true") {
		t.Fatalf("delete row detail = %q, want removed=true", list.Data.Entries[0].Detail)
	}
}

// Role lifecycle and grants are also permission changes.
func TestAuditRecordsRoleChanges(t *testing.T) {
	env := newTestEnv(t)
	alice := env.login(t, "east", "alice", seedPassword).Data.Token

	roleRec := doJSON(t, env.engine, http.MethodPost, "/api/v1/roles", alice, map[string]any{
		"code": "auditor", "permissions": []string{perm.PermRead},
	})
	var role struct {
		Data struct {
			ID int64 `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(roleRec.Body.Bytes(), &role); err != nil {
		t.Fatalf("decode role: %v", err)
	}
	userID := createUserWithRole(t, env, alice, "audra", role.Data.ID)

	if rec := doJSON(t, env.engine, http.MethodPut, "/api/v1/roles/"+itoa(role.Data.ID)+"/permissions",
		alice, map[string]any{"permissions": []string{perm.PermRead, perm.PermWrite}}); rec.Code != http.StatusOK {
		t.Fatalf("update permissions = %d", rec.Code)
	}
	if rec := doJSON(t, env.engine, http.MethodDelete,
		"/api/v1/users/"+itoa(userID)+"/roles/"+itoa(role.Data.ID), alice, nil); rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d", rec.Code)
	}
	if rec := doJSON(t, env.engine, http.MethodDelete, "/api/v1/roles/"+itoa(role.Data.ID), alice, nil); rec.Code != http.StatusOK {
		t.Fatalf("delete role = %d", rec.Code)
	}

	want := []string{"role_delete", "role_revoke", "role_permissions", "role_grant", "role_create"}
	entries := fetchAudit(t, env, alice).Data.Entries
	if len(entries) < len(want) {
		t.Fatalf("trail has %d rows, want at least %d", len(entries), len(want))
	}
	for i, action := range want {
		if entries[i].Action != action {
			t.Fatalf("entry %d action = %q, want %q (whole trail: %+v)", i, entries[i].Action, action, entries)
		}
	}
	// The grant names the role it handed out, since user_role itself keeps no
	// history of how the row got there.
	if !containsAll(entries[3].Detail, "role_id="+itoa(role.Data.ID)) {
		t.Fatalf("grant detail = %q, want role_id=%d", entries[3].Detail, role.Data.ID)
	}
}

// The trail is tenant-scoped and privileged: it names paths and users.
func TestAuditIsTenantScopedAndPrivileged(t *testing.T) {
	env := newTestEnv(t)
	alice := env.login(t, "east", "alice", seedPassword).Data.Token
	bob := env.login(t, "south", "bob", seedPassword).Data.Token

	setACL(t, env, alice, "user", 2, "/east-only", []string{"read"}, true)

	// Tenant 2 sees none of tenant 1's trail.
	for _, e := range fetchAudit(t, env, bob).Data.Entries {
		if e.Path == "/east-only" {
			t.Fatal("tenant 2 read tenant 1's audit trail")
		}
	}

	// A user without perm.manage cannot read it at all.
	weak := seedRoleWithPermissions(t, 1, "weak-audit", perm.PermRead)
	createUserWithRole(t, env, alice, "wilma", weak)
	wilma := env.login(t, "east", "wilma", "long-enough-pass").Data.Token
	if rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/audit", wilma, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("audit without perm.manage = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
}

// The id must reach the client and be honoured when the caller supplies one, so a
// trace can span services. A hostile value is replaced rather than echoed.
func TestRequestIDIsEchoedAndSanitized(t *testing.T) {
	env := newTestEnv(t)

	// Generated when absent.
	rec := doJSON(t, env.engine, http.MethodGet, "/healthz", "", nil)
	generated := rec.Header().Get(httpx.RequestIDHeader)
	if generated == "" {
		t.Fatal("no request id was generated")
	}
	if len(generated) != 16 {
		t.Fatalf("generated id = %q, want 16 hex characters", generated)
	}

	// Honoured when supplied.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set(httpx.RequestIDHeader, "trace-abc.123")
	echoed := doRequest(env.engine, req).Header().Get(httpx.RequestIDHeader)
	if echoed != "trace-abc.123" {
		t.Fatalf("supplied id = %q, want it echoed back", echoed)
	}

	// Replaced when it contains characters that would split a log line.
	bad := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	bad.Header.Set(httpx.RequestIDHeader, "abc\ndef")
	if got := doRequest(env.engine, bad).Header().Get(httpx.RequestIDHeader); got == "abc\ndef" {
		t.Fatalf("a header value with a newline was echoed back: %q", got)
	}
}
