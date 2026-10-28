package integration

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"godochub/internal/perm"
)

// seedRoleWithPermissions creates a role in tenantID and grants it the given
// permission codes. It returns the role id.
//
// The API can create users and grant roles, but it has no way to create a role:
// the permission codes a role carries are part of the tenant's configuration,
// seeded by SQL. That is why this helper writes the rows directly.
func seedRoleWithPermissions(t *testing.T, tenantID int64, code string, perms ...string) int64 {
	t.Helper()
	db := openTestDB(t)
	defer db.Close()

	res, err := db.Exec("INSERT INTO role (tenant_id, code, name) VALUES (?, ?, ?)", tenantID, code, code)
	if err != nil {
		t.Fatalf("seed role %q: %v", code, err)
	}
	roleID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("role id of %q: %v", code, err)
	}
	for _, p := range perms {
		if _, err := db.Exec(
			"INSERT INTO role_permission (tenant_id, role_id, permission) VALUES (?, ?, ?)",
			tenantID, roleID, p); err != nil {
			t.Fatalf("grant %q to role %d: %v", p, roleID, err)
		}
	}
	return roleID
}

// createUserWithRole creates an account through the API and grants it roleID.
// It returns the new user's id.
func createUserWithRole(t *testing.T, env *testEnv, adminToken, username string, roleID int64) int64 {
	t.Helper()

	rec := doJSON(t, env.engine, http.MethodPost, "/api/v1/users", adminToken, map[string]string{
		"username": username,
		"password": "long-enough-pass",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("create user %q = %d (body=%s)", username, rec.Code, rec.Body.String())
	}
	var created struct {
		Data struct {
			ID int64 `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created user: %v", err)
	}
	if roleID > 0 {
		if r := doJSON(t, env.engine, http.MethodPut,
			"/api/v1/users/"+itoa(created.Data.ID)+"/roles/"+itoa(roleID), adminToken, nil); r.Code != http.StatusOK {
			t.Fatalf("grant role %d to %q = %d (body=%s)", roleID, username, r.Code, r.Body.String())
		}
	}
	return created.Data.ID
}

// The scenario the project is meant to serve: several people in one tenant, each
// with a different permission boundary, sharing directories.
//
// The rest of the suite covers one dimension at a time — cross-tenant isolation,
// a roleless user, the action bit of a single user's deny. This one puts four
// users with four different reach levels against the same two directories and
// asserts what each of them can and cannot do, including under concurrency.
func TestMultiUserPermissionBoundaries(t *testing.T) {
	env := newTestEnv(t)
	alice := env.login(t, "east", "alice", seedPassword).Data.Token

	readerRole := seedRoleWithPermissions(t, 1, "reader", perm.PermRead)
	writerRole := seedRoleWithPermissions(t, 1, "writer", perm.PermRead, perm.PermWrite)

	// n1 deliberately gets no role: authenticated, but carries no permission code.
	createUserWithRole(t, env, alice, "r1", readerRole)
	createUserWithRole(t, env, alice, "w1", writerRole)
	createUserWithRole(t, env, alice, "n1", 0)

	r1 := env.login(t, "east", "r1", "long-enough-pass").Data.Token
	w1 := env.login(t, "east", "w1", "long-enough-pass").Data.Token
	n1 := env.login(t, "east", "n1", "long-enough-pass").Data.Token

	// Directory boundaries: /pub is shared, /hr is restricted to the admin.
	// Roles get a root allow so their permission codes have somewhere to apply,
	// then an explicit deny narrows /hr. Deny wins over the inherited allow —
	// that is the rule this test leans on.
	for _, c := range []struct {
		roleID int64
		path   string
		allow  int
		deny   int
	}{
		{readerRole, "/", int(perm.ActionRead), 0},
		{writerRole, "/", int(perm.ActionRead | perm.ActionWrite), 0},
		{readerRole, "/hr", 0, int(perm.ActionRead | perm.ActionWrite | perm.ActionDelete)},
		{writerRole, "/hr", 0, int(perm.ActionRead | perm.ActionWrite | perm.ActionDelete)},
	} {
		grantACL(t, 1, perm.SubjectRole, c.roleID, c.path, c.allow, c.deny)
	}
	envForCache(t)

	// Alice (admin, root allow 7) seeds one file in each directory.
	hr := mustUpload(t, env, alice, "/hr", "salary.bin", make([]byte, 512))
	pub := mustUpload(t, env, alice, "/pub", "notice.bin", make([]byte, 256))

	type expectation struct {
		readPub   int
		readHR    int
		listPub   int
		listHR    int
		uploadPub int
		deletePub int
	}
	cases := []struct {
		name  string
		token string
		want  expectation
	}{
		{"admin", alice, expectation{200, 200, 200, 200, 200, 200}},
		{"reader", r1, expectation{200, 403, 200, 403, 403, 403}},
		{"writer", w1, expectation{200, 403, 200, 403, 200, 403}},
		{"no-role", n1, expectation{403, 403, 403, 403, 403, 403}},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if got := statusOf(t, env, http.MethodGet, "/api/v1/files/"+itoa(pub.Data.ID)+"/download", c.token); got != c.want.readPub {
				t.Errorf("read /pub = %d, want %d", got, c.want.readPub)
			}
			if got := statusOf(t, env, http.MethodGet, "/api/v1/files/"+itoa(hr.Data.ID)+"/download", c.token); got != c.want.readHR {
				t.Errorf("read /hr = %d, want %d", got, c.want.readHR)
			}
			if got := statusOf(t, env, http.MethodGet, "/api/v1/files?dir=/pub", c.token); got != c.want.listPub {
				t.Errorf("list /pub = %d, want %d", got, c.want.listPub)
			}
			if got := statusOf(t, env, http.MethodGet, "/api/v1/files?dir=/hr", c.token); got != c.want.listHR {
				t.Errorf("list /hr = %d, want %d", got, c.want.listHR)
			}

			up := uploadFile(t, env.engine, c.token, "/pub", "by-"+c.name+".bin", make([]byte, 64))
			if up.Code != c.want.uploadPub {
				t.Errorf("upload /pub = %d, want %d (body=%s)", up.Code, c.want.uploadPub, up.Body.String())
			}

			// Delete runs on a file this caller created, so the assertion is about
			// permission and not about a missing row.
			if up.Code == http.StatusOK {
				var body struct {
					Data struct {
						ID int64 `json:"id"`
					} `json:"data"`
				}
				if err := json.Unmarshal(up.Body.Bytes(), &body); err != nil {
					t.Fatalf("decode upload: %v", err)
				}
				if got := statusOf(t, env, http.MethodDelete, "/api/v1/files/"+itoa(body.Data.ID), c.token); got != c.want.deletePub {
					t.Errorf("delete own file = %d, want %d", got, c.want.deletePub)
				}
			}
		})
	}

	// A denied write must leave nothing behind: the guard runs before the handler,
	// so no row and no object should exist for a request that was refused.
	if listed := listNames(t, env, alice, "/pub"); len(listed) != 2 {
		t.Fatalf("/pub holds %v, want only the admin's notice plus the writer's upload", listed)
	}
}

// TestMultiUserConcurrentBoundaries is the same matrix under load: several users
// hitting one server at the same time must each still get their own answer.
//
// This is the property that a single-user concurrency test cannot show — that
// per-request authorisation does not leak between requests sharing the process.
func TestMultiUserConcurrentBoundaries(t *testing.T) {
	env := newTestEnv(t)
	alice := env.login(t, "east", "alice", seedPassword).Data.Token

	readerRole := seedRoleWithPermissions(t, 1, "reader", perm.PermRead)
	writerRole := seedRoleWithPermissions(t, 1, "writer", perm.PermRead, perm.PermWrite)
	createUserWithRole(t, env, alice, "r1", readerRole)
	createUserWithRole(t, env, alice, "w1", writerRole)

	r1 := env.login(t, "east", "r1", "long-enough-pass").Data.Token
	w1 := env.login(t, "east", "w1", "long-enough-pass").Data.Token

	for _, c := range []struct {
		roleID int64
		allow  int
	}{
		{readerRole, int(perm.ActionRead)},
		{writerRole, int(perm.ActionRead | perm.ActionWrite)},
	} {
		grantACL(t, 1, perm.SubjectRole, c.roleID, "/", c.allow, 0)
	}
	envForCache(t)

	// Each user tries the same operation in the same instant; only those with
	// file.write may succeed.
	users := []struct {
		name  string
		token string
		want  int
	}{
		{"alice", alice, http.StatusOK},
		{"r1", r1, http.StatusForbidden},
		{"w1", w1, http.StatusOK},
	}

	for round := 1; round <= 3; round++ {
		round := round
		var wg sync.WaitGroup
		results := make([]int, len(users))
		for i, u := range users {
			i, u := i, u
			wg.Add(1)
			go func() {
				defer wg.Done()
				rec := uploadFile(t, env.engine, u.token, "/pub",
					"c"+itoa(int64(round))+"-"+u.name+".bin", make([]byte, 128))
				results[i] = rec.Code
			}()
		}
		wg.Wait()

		for i, u := range users {
			if results[i] != u.want {
				t.Errorf("round %d: %s upload = %d, want %d", round, u.name, results[i], u.want)
			}
		}
	}

	// One row per successful upload: 2 users × 3 rounds. The reader's three
	// attempts must have written nothing.
	if names := listNames(t, env, alice, "/pub"); len(names) != 6 {
		t.Fatalf("/pub holds %d files (%v), want 6: the reader's attempts must not land", len(names), names)
	}
}

// statusOf issues one request and returns the status code.
func statusOf(t *testing.T, env *testEnv, method, path, token string) int {
	t.Helper()
	return doJSON(t, env.engine, method, path, token, nil).Code
}

// listNames returns the file names in one directory of the caller's tenant.
func listNames(t *testing.T, env *testEnv, token, dir string) []string {
	t.Helper()
	rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/files?dir="+urlQuery(dir)+"&limit=200", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list %q = %d (body=%s)", dir, rec.Code, rec.Body.String())
	}
	var body struct {
		Data struct {
			Files []struct {
				Name string `json:"name"`
			} `json:"files"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	out := make([]string, 0, len(body.Data.Files))
	for _, f := range body.Data.Files {
		out = append(out, f.Name)
	}
	return out
}
