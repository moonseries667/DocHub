package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"godochub/internal/perm"
)

// Defining a role needs both halves in one request: without the permission codes
// the role would be a selectable object that grants nothing.
func TestCreateRoleGrantsItsPermissions(t *testing.T) {
	env := newTestEnv(t)
	alice := env.login(t, "east", "alice", seedPassword).Data.Token

	rec := doJSON(t, env.engine, http.MethodPost, "/api/v1/roles", alice, map[string]any{
		"code":        "auditor",
		"name":        "审计员",
		"permissions": []string{perm.PermRead},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("create role = %d (body=%s)", rec.Code, rec.Body.String())
	}
	var created struct {
		Data struct {
			ID          int64    `json:"id"`
			Code        string   `json:"code"`
			Permissions []string `json:"permissions"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created role: %v", err)
	}
	if created.Data.ID == 0 || created.Data.Code != "auditor" {
		t.Fatalf("created role = %+v", created.Data)
	}
	if len(created.Data.Permissions) != 1 || created.Data.Permissions[0] != perm.PermRead {
		t.Fatalf("permissions = %v, want [file.read]", created.Data.Permissions)
	}

	// The role must be visible in the listing, with its permissions, so a client
	// can choose it without reading the database.
	list := doJSON(t, env.engine, http.MethodGet, "/api/v1/roles", alice, nil)
	if !containsAll(list.Body.String(), `"code":"auditor"`, `"permissions":["file.read"]`) {
		t.Fatalf("listing = %s, want the new role with its permissions", list.Body.String())
	}
}

// The point of defining a role is that assigning it changes what a user can do.
func TestCreatedRoleTakesEffectWhenAssigned(t *testing.T) {
	env := newTestEnv(t)
	alice := env.login(t, "east", "alice", seedPassword).Data.Token

	roleRec := doJSON(t, env.engine, http.MethodPost, "/api/v1/roles", alice, map[string]any{
		"code":        "uploader",
		"permissions": []string{perm.PermRead, perm.PermWrite},
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

	createUserWithRole(t, env, alice, "olga", role.Data.ID)
	olga := env.login(t, "east", "olga", "long-enough-pass").Data.Token

	// The role's codes are what make the upload possible; the ACL allow is the
	// other half, and both must be present.
	grantACL(t, 1, perm.SubjectRole, role.Data.ID, "/drop", int(perm.ActionRead|perm.ActionWrite), 0)
	envForCache(t)

	if rec := uploadFile(t, env.engine, olga, "/drop", "from-olga.txt", []byte("hello")); rec.Code != http.StatusOK {
		t.Fatalf("upload with the new role = %d (body=%s)", rec.Code, rec.Body.String())
	}

	// file.delete was not among the role's codes, so RBAC alone must refuse the
	// delete — no ACL deny needed, and adding one here would overwrite the allow
	// row above (the unique key is per subject and path).
	up := mustUpload(t, env, olga, "/drop", "another.txt", []byte("x"))
	if rec := doJSON(t, env.engine, http.MethodDelete,
		"/api/v1/files/"+itoa(up.Data.ID), olga, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("delete without file.delete = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
}

// A definition that cannot work must be refused, not stored half-applied.
func TestCreateRoleRejectsBadDefinitions(t *testing.T) {
	env := newTestEnv(t)
	alice := env.login(t, "east", "alice", seedPassword).Data.Token

	cases := []struct {
		name string
		body map[string]any
		want int
		why  string
	}{
		{
			name: "unknown permission code",
			body: map[string]any{"code": "typo", "permissions": []string{"file.raed"}},
			want: http.StatusBadRequest,
			why:  "a typo must be named, not turned into a foreign key 500",
		},
		{
			name: "no permissions",
			body: map[string]any{"code": "empty", "permissions": []string{}},
			want: http.StatusBadRequest,
			why:  "a role that grants nothing is not a usable object",
		},
		{
			name: "empty code",
			body: map[string]any{"code": "", "permissions": []string{perm.PermRead}},
			want: http.StatusBadRequest,
			why:  "the code is the identifier a client passes around",
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			rec := doJSON(t, env.engine, http.MethodPost, "/api/v1/roles", alice, c.body)
			if rec.Code != c.want {
				t.Fatalf("%s: status = %d, want %d (body=%s)", c.why, rec.Code, c.want, rec.Body.String())
			}
		})
	}

	// Nothing above may have been written: two roles exist (admin, and whichever
	// the bad requests might have created).
	list := doJSON(t, env.engine, http.MethodGet, "/api/v1/roles", alice, nil)
	if strings.Contains(list.Body.String(), `"code":"typo"`) || strings.Contains(list.Body.String(), `"code":"empty"`) {
		t.Fatalf("a refused role was stored: %s", list.Body.String())
	}
}

// A duplicate code is a 409, and the tenant boundary decides which codes collide.
func TestCreateRoleRejectsDuplicateCode(t *testing.T) {
	env := newTestEnv(t)
	alice := env.login(t, "east", "alice", seedPassword).Data.Token
	bob := env.login(t, "south", "bob", seedPassword).Data.Token

	first := doJSON(t, env.engine, http.MethodPost, "/api/v1/roles", alice, map[string]any{
		"code": "viewer", "permissions": []string{perm.PermRead},
	})
	if first.Code != http.StatusOK {
		t.Fatalf("first create = %d (body=%s)", first.Code, first.Body.String())
	}

	dup := doJSON(t, env.engine, http.MethodPost, "/api/v1/roles", alice, map[string]any{
		"code": "viewer", "permissions": []string{perm.PermWrite},
	})
	if dup.Code != http.StatusConflict {
		t.Fatalf("duplicate code = %d, want 409 (body=%s)", dup.Code, dup.Body.String())
	}

	// The same code in another tenant is legal: role codes are per tenant.
	other := doJSON(t, env.engine, http.MethodPost, "/api/v1/roles", bob, map[string]any{
		"code": "viewer", "permissions": []string{perm.PermRead},
	})
	if other.Code != http.StatusOK {
		t.Fatalf("same code in another tenant = %d (body=%s)", other.Code, other.Body.String())
	}
}

// Defining a role is a privileged act.
func TestCreateRoleRequiresManagePermission(t *testing.T) {
	env := newTestEnv(t)
	viewerRole := seedRoleWithPermissions(t, 1, "watcher", perm.PermRead)
	createUserWithRole(t, env, env.login(t, "east", "alice", seedPassword).Data.Token, "vera", viewerRole)
	vera := env.login(t, "east", "vera", "long-enough-pass").Data.Token

	rec := doJSON(t, env.engine, http.MethodPost, "/api/v1/roles", vera, map[string]any{
		"code": "sneaky", "permissions": []string{perm.PermManage},
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("create role without perm.manage = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
}
