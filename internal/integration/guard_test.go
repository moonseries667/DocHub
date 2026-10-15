package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"godochub/internal/perm"
)

// The ACL guard on the file routes: a deny on a directory must stop the download
// even though the caller's role grants file.read.
func TestACLGuardBlocksDeniedPath(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	uploaded := mustUpload(t, env, token, "/guarded", "secret.txt", []byte("classified"))
	id := itoa(uploaded.Data.ID)

	// Baseline: the seeded root grant allows the download.
	if rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/files/"+id+"/download", token, nil); rec.Code != http.StatusOK {
		t.Fatalf("baseline download = %d (body=%s)", rec.Code, rec.Body.String())
	}

	grantACL(t, 1, perm.SubjectUser, 1, "/guarded", 0, int(perm.ActionRead))

	rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/files/"+id+"/download", token, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("download after deny = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
	// No bytes must leak in a 403 body.
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode 403: %v", err)
	}
	if body["code"] != float64(http.StatusForbidden) {
		t.Fatalf("body = %v, want unified 403", body)
	}
}

// Deleting is gated by the delete action, not by read.
func TestACLGuardUsesTheActionSpecificBit(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	uploaded := mustUpload(t, env, token, "/bits", "keep.txt", []byte("data"))
	id := itoa(uploaded.Data.ID)

	// Deny delete only: read must still work, delete must not.
	grantACL(t, 1, perm.SubjectUser, 1, "/bits", 0, int(perm.ActionDelete))

	if rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/files/"+id+"/download", token, nil); rec.Code != http.StatusOK {
		t.Fatalf("read under a delete-only deny = %d, want 200", rec.Code)
	}
	if rec := doJSON(t, env.engine, http.MethodDelete, "/api/v1/files/"+id, token, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("delete under a delete deny = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
}

// The permission endpoints report the caller's own view.
func TestPermissionEndpoints(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/permissions", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("permissions = %d (body=%s)", rec.Code, rec.Body.String())
	}
	var perms struct {
		Data struct {
			Permissions []string `json:"permissions"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &perms); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(perms.Data.Permissions) != 4 {
		t.Fatalf("permissions = %v, want the four seeded codes", perms.Data.Permissions)
	}

	check := doJSON(t, env.engine, http.MethodGet, "/api/v1/permissions/check?action=read&path=/anything", token, nil)
	if check.Code != http.StatusOK {
		t.Fatalf("check = %d (body=%s)", check.Code, check.Body.String())
	}
	if !strings.Contains(check.Body.String(), `"allowed":true`) {
		t.Fatalf("check body = %s, want allowed true", check.Body.String())
	}

	bad := doJSON(t, env.engine, http.MethodGet, "/api/v1/permissions/check?action=frobnicate&path=/x", token, nil)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("unknown action = %d, want 400", bad.Code)
	}
}

// The upload and list routes take their ACL path from the request body/query
// instead of a file id, so they need their own deny coverage: until the test
// route table matched main's, neither route ran a guard at all.
func TestGuardChecksWriteAndReadOnDirectoryRoutes(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	grantACL(t, 1, perm.SubjectUser, 1, "/nowrite", 0, int(perm.ActionWrite))
	if rec := uploadFile(t, env.engine, token, "/nowrite", "x.txt", []byte("x")); rec.Code != http.StatusForbidden {
		t.Fatalf("upload into a write-denied dir = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
	if objs := walkFiles(t, env.root); len(objs) != 0 {
		t.Fatalf("a denied upload wrote to storage: %v", objs)
	}
	// Only write is denied; reading the same directory is still allowed.
	if rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/files?dir=/nowrite", token, nil); rec.Code != http.StatusOK {
		t.Fatalf("list under a write-only deny = %d, want 200", rec.Code)
	}

	grantACL(t, 1, perm.SubjectUser, 1, "/noread", 0, int(perm.ActionRead))
	if rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/files?dir=/noread", token, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("list of a read-denied dir = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
	// And uploading there still works: the write bit is untouched.
	if rec := uploadFile(t, env.engine, token, "/noread", "x.txt", []byte("x")); rec.Code != http.StatusOK {
		t.Fatalf("upload under a read-only deny = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
}

// A malformed id under a valid token is a client error: answering 500 pollutes
// the 5xx log and tells the caller nothing.
func TestMalformedIDIs400(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/files/abc/download"},
		{http.MethodDelete, "/api/v1/files/abc"},
		{http.MethodGet, "/api/v1/uploads/abc"},
	}
	for _, c := range cases {
		rec := doJSON(t, env.engine, c.method, c.path, token, nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s %s = %d, want 400 (body=%s)", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
}
