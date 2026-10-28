package integration

import (
	"encoding/json"
	"net/http"
	"testing"

	"godochub/internal/perm"
)

// Changing what a role grants must take effect on the very next request.
//
// The permission decision is cached per (user, path, action), so without an
// explicit invalidation a tightened role would keep working for up to the cache
// TTL. This test warms the cache with an allow and then removes the code.
func TestUpdateRolePermissionsTakesEffectImmediately(t *testing.T) {
	env := newTestEnv(t)
	alice := env.login(t, "east", "alice", seedPassword).Data.Token

	roleRec := doJSON(t, env.engine, http.MethodPost, "/api/v1/roles", alice, map[string]any{
		"code": "worker", "permissions": []string{perm.PermRead, perm.PermWrite},
	})
	if roleRec.Code != http.StatusOK {
		t.Fatalf("create role = %d (body=%s)", roleRec.Code, roleRec.Body.String())
	}
	var role struct {
		Data struct {
			ID int64 `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(roleRec.Body.Bytes(), &role); err != nil {
		t.Fatalf("decode role: %v", err)
	}

	createUserWithRole(t, env, alice, "wojtek", role.Data.ID)
	wojtek := env.login(t, "east", "wojtek", "long-enough-pass").Data.Token
	grantACL(t, 1, perm.SubjectRole, role.Data.ID, "/work", int(perm.ActionRead|perm.ActionWrite), 0)
	envForCache(t)

	// Warm the cache with an allowed write.
	if rec := uploadFile(t, env.engine, wojtek, "/work", "first.bin", []byte("x")); rec.Code != http.StatusOK {
		t.Fatalf("upload while the role has file.write = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	// Drop file.write. The answer must flip without restarting or clearing Redis.
	upd := doJSON(t, env.engine, http.MethodPut, "/api/v1/roles/"+itoa(role.Data.ID)+"/permissions", alice,
		map[string]any{"permissions": []string{perm.PermRead}})
	if upd.Code != http.StatusOK {
		t.Fatalf("update permissions = %d (body=%s)", upd.Code, upd.Body.String())
	}
	if !containsAll(upd.Body.String(), `"permissions":["file.read"]`) {
		t.Fatalf("updated role = %s, want only file.read", upd.Body.String())
	}

	if rec := uploadFile(t, env.engine, wojtek, "/work", "second.bin", []byte("x")); rec.Code != http.StatusForbidden {
		t.Fatalf("upload after file.write was removed = %d, want 403 — the cached allow outlived the change", rec.Code)
	}
	// Reading is still fine: only the write bit was taken away.
	if rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/files?dir=/work", wojtek, nil); rec.Code != http.StatusOK {
		t.Fatalf("list after narrowing the role = %d, want 200", rec.Code)
	}
}

// Duplicate and empty permission lists are refused, and a refused update leaves
// the previous set intact.
func TestUpdateRolePermissionsRejectsBadInput(t *testing.T) {
	env := newTestEnv(t)
	alice := env.login(t, "east", "alice", seedPassword).Data.Token

	roleRec := doJSON(t, env.engine, http.MethodPost, "/api/v1/roles", alice, map[string]any{
		"code": "steady", "permissions": []string{perm.PermRead},
	})
	var role struct {
		Data struct {
			ID int64 `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(roleRec.Body.Bytes(), &role); err != nil {
		t.Fatalf("decode role: %v", err)
	}
	path := "/api/v1/roles/" + itoa(role.Data.ID) + "/permissions"

	for _, c := range []struct {
		name string
		body map[string]any
	}{
		{"unknown code", map[string]any{"permissions": []string{"file.raed"}}},
		{"empty set", map[string]any{"permissions": []string{}}},
	} {
		if rec := doJSON(t, env.engine, http.MethodPut, path, alice, c.body); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s = %d, want 400 (body=%s)", c.name, rec.Code, rec.Body.String())
		}
	}

	// The role still grants exactly what it did before the refused updates.
	list := doJSON(t, env.engine, http.MethodGet, "/api/v1/roles", alice, nil)
	if !containsAll(list.Body.String(), `"code":"steady"`, `"permissions":["file.read"]`) {
		t.Fatalf("role after refused updates = %s, want the original file.read", list.Body.String())
	}
}

// A role nobody holds can be deleted; one that is still assigned cannot, because
// deleting it would silently revoke it from everyone through the cascade.
func TestDeleteRoleRefusesWhileAssigned(t *testing.T) {
	env := newTestEnv(t)
	alice := env.login(t, "east", "alice", seedPassword).Data.Token

	roleRec := doJSON(t, env.engine, http.MethodPost, "/api/v1/roles", alice, map[string]any{
		"code": "temp", "permissions": []string{perm.PermRead},
	})
	var role struct {
		Data struct {
			ID int64 `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(roleRec.Body.Bytes(), &role); err != nil {
		t.Fatalf("decode role: %v", err)
	}

	userID := createUserWithRole(t, env, alice, "tessa", role.Data.ID)

	if rec := doJSON(t, env.engine, http.MethodDelete, "/api/v1/roles/"+itoa(role.Data.ID), alice, nil); rec.Code != http.StatusConflict {
		t.Fatalf("delete an assigned role = %d, want 409 (body=%s)", rec.Code, rec.Body.String())
	}

	// Revoke first, then the delete goes through.
	if rec := doJSON(t, env.engine, http.MethodDelete,
		"/api/v1/users/"+itoa(userID)+"/roles/"+itoa(role.Data.ID), alice, nil); rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d (body=%s)", rec.Code, rec.Body.String())
	}
	if rec := doJSON(t, env.engine, http.MethodDelete, "/api/v1/roles/"+itoa(role.Data.ID), alice, nil); rec.Code != http.StatusOK {
		t.Fatalf("delete after revoke = %d (body=%s)", rec.Code, rec.Body.String())
	}
	if list := doJSON(t, env.engine, http.MethodGet, "/api/v1/roles", alice, nil); containsAll(list.Body.String(), `"code":"temp"`) {
		t.Fatalf("the deleted role is still listed: %s", list.Body.String())
	}
}

// Revoking a role must also drop the cached decisions, or the revocation would
// only bite after the TTL.
func TestRevokeRoleTakesEffectImmediately(t *testing.T) {
	env := newTestEnv(t)
	alice := env.login(t, "east", "alice", seedPassword).Data.Token

	roleRec := doJSON(t, env.engine, http.MethodPost, "/api/v1/roles", alice, map[string]any{
		"code": "reader2", "permissions": []string{perm.PermRead},
	})
	var role struct {
		Data struct {
			ID int64 `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(roleRec.Body.Bytes(), &role); err != nil {
		t.Fatalf("decode role: %v", err)
	}

	userID := createUserWithRole(t, env, alice, "ryan", role.Data.ID)
	ryan := env.login(t, "east", "ryan", "long-enough-pass").Data.Token
	grantACL(t, 1, perm.SubjectRole, role.Data.ID, "/pub2", int(perm.ActionRead), 0)
	envForCache(t)

	// Warm the cache: reading is allowed while the role is held.
	if rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/files?dir=/pub2", ryan, nil); rec.Code != http.StatusOK {
		t.Fatalf("list while holding the role = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	if rec := doJSON(t, env.engine, http.MethodDelete,
		"/api/v1/users/"+itoa(userID)+"/roles/"+itoa(role.Data.ID), alice, nil); rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d (body=%s)", rec.Code, rec.Body.String())
	}

	if rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/files?dir=/pub2", ryan, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("list after the role was revoked = %d, want 403 — the cached allow outlived the revocation", rec.Code)
	}
}

// Both new routes are privileged.
func TestRoleMutationRequiresManage(t *testing.T) {
	env := newTestEnv(t)
	alice := env.login(t, "east", "alice", seedPassword).Data.Token

	roleRec := doJSON(t, env.engine, http.MethodPost, "/api/v1/roles", alice, map[string]any{
		"code": "target", "permissions": []string{perm.PermRead},
	})
	var role struct {
		Data struct {
			ID int64 `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(roleRec.Body.Bytes(), &role); err != nil {
		t.Fatalf("decode role: %v", err)
	}

	weak := seedRoleWithPermissions(t, 1, "weak", perm.PermRead)
	createUserWithRole(t, env, alice, "nina", weak)
	nina := env.login(t, "east", "nina", "long-enough-pass").Data.Token

	if rec := doJSON(t, env.engine, http.MethodPut,
		"/api/v1/roles/"+itoa(role.Data.ID)+"/permissions", nina,
		map[string]any{"permissions": []string{perm.PermManage}}); rec.Code != http.StatusForbidden {
		t.Fatalf("update permissions without perm.manage = %d, want 403", rec.Code)
	}
	if rec := doJSON(t, env.engine, http.MethodDelete,
		"/api/v1/roles/"+itoa(role.Data.ID), nina, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("delete role without perm.manage = %d, want 403", rec.Code)
	}
}

// A role id from another tenant is a 404, not a cross-tenant edit.
func TestRoleMutationRejectsForeignTenant(t *testing.T) {
	env := newTestEnv(t)
	alice := env.login(t, "east", "alice", seedPassword).Data.Token

	// Tenant 2's admin role is id 2.
	if rec := doJSON(t, env.engine, http.MethodPut, "/api/v1/roles/2/permissions", alice,
		map[string]any{"permissions": []string{perm.PermRead}}); rec.Code != http.StatusNotFound {
		t.Fatalf("update a foreign role = %d, want 404 (body=%s)", rec.Code, rec.Body.String())
	}
	if rec := doJSON(t, env.engine, http.MethodDelete, "/api/v1/roles/2", alice, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("delete a foreign role = %d, want 404 (body=%s)", rec.Code, rec.Body.String())
	}
}
