package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"godochub/internal/perm"
)

// Creating an account is what a fresh install needs before anything else: with
// only seeded users, adding a second person meant writing SQL by hand.
func TestCreateUserAndLoginWithIt(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	rec := doJSON(t, env.engine, http.MethodPost, "/api/v1/users", token, map[string]string{
		"username":     "frank",
		"password":     "s3cret-pass",
		"display_name": "Frank",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("create user = %d (body=%s)", rec.Code, rec.Body.String())
	}
	var created struct {
		Data struct {
			ID       int64  `json:"id"`
			Username string `json:"username"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if created.Data.ID == 0 || created.Data.Username != "frank" {
		t.Fatalf("created = %+v", created.Data)
	}

	// The whole point of creating the account is that it can sign in.
	login := env.login(t, "east", "frank", "s3cret-pass")
	if login.Code != 0 || login.Data.Token == "" {
		t.Fatalf("login as the new user = %+v", login)
	}
	if login.Data.User.TenantID != 1 {
		t.Fatalf("new user landed in tenant %d, want 1", login.Data.User.TenantID)
	}
}

// The password must never come back, and a short one must be refused rather than
// silently accepted.
func TestCreateUserRejectsShortPasswordAndNeverEchoesIt(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	short := doJSON(t, env.engine, http.MethodPost, "/api/v1/users", token, map[string]string{
		"username": "shorty", "password": "abc",
	})
	if short.Code != http.StatusBadRequest {
		t.Fatalf("short password = %d, want 400", short.Code)
	}

	ok := doJSON(t, env.engine, http.MethodPost, "/api/v1/users", token, map[string]string{
		"username": "grace", "password": "long-enough-pass",
	})
	if ok.Code != http.StatusOK {
		t.Fatalf("create = %d (body=%s)", ok.Code, ok.Body.String())
	}
	if body := ok.Body.String(); containsAny(body, "long-enough-pass", "password_hash", "$2a$") {
		t.Fatalf("the response leaked the password or its hash: %s", body)
	}
}

// A duplicate username is a 409, and the tenant is taken from the token: sending
// someone else's tenant must not place the account there.
func TestCreateUserIsTenantScopedAndRejectsDuplicates(t *testing.T) {
	env := newTestEnv(t)
	alice := env.login(t, "east", "alice", seedPassword).Data.Token
	bob := env.login(t, "south", "bob", seedPassword).Data.Token

	// Same username in two tenants is legal: the unique key is per tenant.
	for _, tok := range []string{alice, bob} {
		if rec := doJSON(t, env.engine, http.MethodPost, "/api/v1/users", tok, map[string]string{
			"username": "shared-name", "password": "long-enough-pass",
		}); rec.Code != http.StatusOK {
			t.Fatalf("create in each tenant = %d (body=%s)", rec.Code, rec.Body.String())
		}
	}

	dup := doJSON(t, env.engine, http.MethodPost, "/api/v1/users", alice, map[string]string{
		"username": "shared-name", "password": "long-enough-pass",
	})
	if dup.Code != http.StatusConflict {
		t.Fatalf("duplicate username = %d, want 409", dup.Code)
	}

	// A tenant id in the body must be ignored: the token decides.
	rec := doJSON(t, env.engine, http.MethodPost, "/api/v1/users", alice, map[string]any{
		"username": "sneaky", "password": "long-enough-pass", "tenant_id": 2,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("create with a tenant_id in the body = %d (body=%s)", rec.Code, rec.Body.String())
	}
	login := env.login(t, "east", "sneaky", "long-enough-pass")
	if login.Code != 0 || login.Data.User.TenantID != 1 {
		t.Fatalf("the body's tenant_id was honoured: %+v", login.Data.User)
	}
}

// Listing users shows the caller's tenant only.
func TestListUsersIsTenantScoped(t *testing.T) {
	env := newTestEnv(t)
	alice := env.login(t, "east", "alice", seedPassword).Data.Token

	doJSON(t, env.engine, http.MethodPost, "/api/v1/users", alice, map[string]string{
		"username": "henry", "password": "long-enough-pass",
	})

	rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/users", alice, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list users = %d (body=%s)", rec.Code, rec.Body.String())
	}
	var body struct {
		Data struct {
			Users []struct {
				Username string `json:"username"`
			} `json:"users"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	names := map[string]bool{}
	for _, u := range body.Data.Users {
		names[u.Username] = true
	}
	if !names["henry"] || !names["alice"] {
		t.Fatalf("list = %v, want alice and henry", names)
	}
	if names["bob"] {
		t.Fatal("the list leaked a user from another tenant")
	}
	if containsAny(rec.Body.String(), "password_hash", "$2a$") {
		t.Fatalf("the list leaked a password hash: %s", rec.Body.String())
	}
}

// Creating a user requires perm.manage, not merely a valid token.
func TestCreateUserRequiresManagePermission(t *testing.T) {
	env := newTestEnv(t)
	_, userID := seedRoleWithoutPermission(t, 1, "viewer", "ivy")
	grantACL(t, 1, perm.SubjectUser, userID, "/", int(perm.ActionRead), 0)
	viewer := env.login(t, "east", "ivy", seedPassword).Data.Token

	rec := doJSON(t, env.engine, http.MethodPost, "/api/v1/users", viewer, map[string]string{
		"username": "escalated", "password": "long-enough-pass",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("create user without perm.manage = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
}

// Granting a role is how a created account becomes useful; both sides must be in
// the caller's tenant.
func TestAssignAndRevokeRole(t *testing.T) {
	env := newTestEnv(t)
	alice := env.login(t, "east", "alice", seedPassword).Data.Token

	rec := doJSON(t, env.engine, http.MethodPost, "/api/v1/users", alice, map[string]string{
		"username": "judy", "password": "long-enough-pass",
	})
	var created struct {
		Data struct {
			ID int64 `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created user: %v", err)
	}
	judyID := created.Data.ID

	roles := doJSON(t, env.engine, http.MethodGet, "/api/v1/roles", alice, nil)
	var roleBody struct {
		Data struct {
			Roles []struct {
				ID   int64  `json:"id"`
				Code string `json:"code"`
			} `json:"roles"`
		} `json:"data"`
	}
	if err := json.Unmarshal(roles.Body.Bytes(), &roleBody); err != nil {
		t.Fatalf("decode roles: %v", err)
	}
	if len(roleBody.Data.Roles) == 0 {
		t.Fatal("the tenant has no roles to grant")
	}
	adminRole := roleBody.Data.Roles[0].ID

	// A roleless user cannot do anything; granting admin must change that.
	if before := doJSON(t, env.engine, http.MethodGet, "/api/v1/permissions", env.login(t, "east", "judy", "long-enough-pass").Data.Token, nil); !containsAny(before.Body.String(), `"permissions":[]`) {
		t.Fatalf("a fresh user already had permissions: %s", before.Body.String())
	}

	grant := doJSON(t, env.engine, http.MethodPut,
		"/api/v1/users/"+itoa(judyID)+"/roles/"+itoa(adminRole), alice, nil)
	if grant.Code != http.StatusOK {
		t.Fatalf("assign role = %d (body=%s)", grant.Code, grant.Body.String())
	}
	after := doJSON(t, env.engine, http.MethodGet, "/api/v1/permissions",
		env.login(t, "east", "judy", "long-enough-pass").Data.Token, nil)
	if containsAny(after.Body.String(), `"permissions":[]`) {
		t.Fatalf("granting the role did not grant its permissions: %s", after.Body.String())
	}

	revoke := doJSON(t, env.engine, http.MethodDelete,
		"/api/v1/users/"+itoa(judyID)+"/roles/"+itoa(adminRole), alice, nil)
	if revoke.Code != http.StatusOK || !containsAny(revoke.Body.String(), `"removed":true`) {
		t.Fatalf("revoke role = %d (body=%s)", revoke.Code, revoke.Body.String())
	}
}

// A role id from another tenant must not be assignable: that would hand out
// permissions this tenant never defined.
func TestAssignRoleRejectsForeignTenantRole(t *testing.T) {
	env := newTestEnv(t)
	alice := env.login(t, "east", "alice", seedPassword).Data.Token

	rec := doJSON(t, env.engine, http.MethodPost, "/api/v1/users", alice, map[string]string{
		"username": "karl", "password": "long-enough-pass",
	})
	var created struct {
		Data struct {
			ID int64 `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Tenant 2's admin role is id 2; tenant 1 must not be able to grant it.
	grant := doJSON(t, env.engine, http.MethodPut,
		"/api/v1/users/"+itoa(created.Data.ID)+"/roles/2", alice, nil)
	if grant.Code != http.StatusNotFound {
		t.Fatalf("assigning a foreign role = %d, want 404 (body=%s)", grant.Code, grant.Body.String())
	}
}

// Usage reports the footprint so a quota is visible before it is hit.
func TestUsageReportsFootprint(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	mustUpload(t, env, token, "/usage", "one.bin", make([]byte, 1000))
	mustUpload(t, env, token, "/usage", "two.bin", make([]byte, 2000))

	rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/usage", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("usage = %d (body=%s)", rec.Code, rec.Body.String())
	}
	var body struct {
		Data struct {
			FileCount   int64 `json:"file_count"`
			UsedBytes   int64 `json:"used_bytes"`
			QuotaBytes  int64 `json:"quota_bytes"`
			Remaining   int64 `json:"remaining"`
			Unlimited   bool  `json:"unlimited"`
			UsedPercent int   `json:"used_percent"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Data.FileCount != 2 {
		t.Fatalf("file_count = %d, want 2", body.Data.FileCount)
	}
	if body.Data.UsedBytes != 3000 {
		t.Fatalf("used_bytes = %d, want 3000", body.Data.UsedBytes)
	}
	if body.Data.Unlimited {
		t.Fatal("the seed tenant should have a quota, not be unlimited")
	}
	if body.Data.Remaining != body.Data.QuotaBytes-3000 {
		t.Fatalf("remaining = %d, want %d", body.Data.Remaining, body.Data.QuotaBytes-3000)
	}
}

// Exhausting the quota must refuse the upload rather than fill the bucket, and
// the refusal has to come before any row is reserved.
func TestQuotaRefusesUploadWhenFull(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	// Shrink the tenant's quota so the test does not have to write a gigabyte.
	db := openTestDB(t)
	defer db.Close()
	if _, err := db.Exec("UPDATE tenant SET quota_bytes = 4096 WHERE id = 1"); err != nil {
		t.Fatalf("shrink quota: %v", err)
	}
	t.Cleanup(func() {
		d, err := openTestDB(t), error(nil)
		_ = d
		_ = err
		_ = d
	})

	mustUpload(t, env, token, "/quota", "fits.bin", make([]byte, 3000))

	over := uploadFile(t, env.engine, token, "/quota", "toobig.bin", make([]byte, 2000))
	if over.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("upload past the quota = %d, want 413 (body=%s)", over.Code, over.Body.String())
	}

	// The refused upload must not have taken the name: a smaller file still fits.
	if again := uploadFile(t, env.engine, token, "/quota", "toobig.bin", make([]byte, 500)); again.Code != http.StatusOK {
		t.Fatalf("the refused upload kept the name: %d (body=%s)", again.Code, again.Body.String())
	}

	usage := doJSON(t, env.engine, http.MethodGet, "/api/v1/usage", token, nil)
	if !containsAny(usage.Body.String(), `"quota_bytes":4096`) {
		t.Fatalf("usage = %s, want quota 4096", usage.Body.String())
	}
}

// containsAny reports whether body contains any of the substrings.
func containsAny(body string, wants ...string) bool {
	for _, w := range wants {
		if w != "" && strings.Contains(body, w) {
			return true
		}
	}
	return false
}
