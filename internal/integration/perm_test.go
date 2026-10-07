package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"

	"godochub/internal/perm"
	"godochub/internal/ratelimit"
)

// redisForTests opens a client against the same Redis the test env uses.
func redisForTests(t *testing.T) *redis.Client {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{Addr: redisAddr()})
	t.Cleanup(func() { rdb.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Skipf("redis not reachable at %s: %v", redisAddr(), err)
	}
	return rdb
}

func redisAddr() string {
	if v := getenv("GODOC_REDIS_ADDR"); v != "" {
		return v
	}
	return "127.0.0.1:6379"
}

// The permission matrix: role × resource × action, including the two paths the
// task card calls out — inherited grant and explicit child deny.
func TestPermissionMatrix(t *testing.T) {
	env := newTestEnv(t)

	// The seed grants admin full read/write/delete on "/", so the root works.
	if allowed, err := env.perm.Allowed(t.Context(), 1, 1, "/", perm.ActionRead); err != nil || !allowed {
		t.Fatalf("admin read on / = %v, %v; want true", allowed, err)
	}

	// A child directory inherits the root grant.
	if allowed, err := env.perm.Allowed(t.Context(), 1, 1, "/reports/2026", perm.ActionRead); err != nil || !allowed {
		t.Fatalf("inherited read = %v, %v; want true", allowed, err)
	}

	// An explicit deny on a child must beat the inherited allow.
	grantACL(t, 1, perm.SubjectUser, 1, "/reports/secret", 0, int(perm.ActionRead))
	if allowed, err := env.perm.Allowed(t.Context(), 1, 1, "/reports/secret", perm.ActionRead); err != nil || allowed {
		t.Fatalf("explicit deny = %v, %v; want false", allowed, err)
	}
	// The deny is scoped: its parent and siblings keep the inherited grant.
	if allowed, _ := env.perm.Allowed(t.Context(), 1, 1, "/reports", perm.ActionRead); !allowed {
		t.Fatal("deny on /reports/secret leaked to /reports")
	}
	if allowed, _ := env.perm.Allowed(t.Context(), 1, 1, "/reports/public", perm.ActionRead); !allowed {
		t.Fatal("deny on /reports/secret leaked to the sibling /reports/public")
	}

	// Tenant 2's admin is allowed on its own root: the deny is a tenant-1 row.
	// (The RBAC half of that decision is tested separately below.)
	if allowed, err := env.perm.Allowed(t.Context(), 2, 2, "/", perm.ActionRead); err != nil || !allowed {
		t.Fatalf("bob read on his own root = %v, %v; want true", allowed, err)
	}

	// Tenant 2 has no deny of its own on /reports/secret, so its inherited root
	// grant applies: alice's deny must not leak into bob's decisions. This is the
	// isolation property that matters — the deny is a tenant-1 row.
	if allowed, _ := env.perm.Allowed(t.Context(), 2, 2, "/reports/secret", perm.ActionRead); !allowed {
		t.Fatal("tenant 1's deny leaked into tenant 2's decisions")
	}

	// The reverse direction: a grant written for tenant 2 must not be readable by
	// tenant 1's resolver. Checking Allowed would be the wrong probe here — alice's
	// own root grant already covers every path, so it says nothing about the row's
	// tenant. The resolver's input is what has to be isolated.
	grantACL(t, 2, perm.SubjectUser, 2, "/south-only", int(perm.ActionRead), 0)
	entries, err := env.perm.EntriesForTest(t.Context(), 1, 1, "/south-only")
	if err != nil {
		t.Fatalf("load entries: %v", err)
	}
	for _, e := range entries {
		if e.Path == "/south-only" {
			t.Fatal("tenant 2's ACL row was returned to tenant 1's resolver")
		}
	}

	// And tenant 2's own resolver does see it.
	bobEntries, err := env.perm.EntriesForTest(t.Context(), 2, 2, "/south-only")
	if err != nil {
		t.Fatalf("load bob entries: %v", err)
	}
	found := false
	for _, e := range bobEntries {
		if e.Path == "/south-only" {
			found = true
		}
	}
	if !found {
		t.Fatal("tenant 2's own ACL row was not returned to its resolver")
	}
}

// The RBAC half of the decision, on its own: a role that grants no permission
// code is refused even where the ACL allows the path. Granting the code flips the
// answer, which proves the refusal came from RBAC and not from a missing ACL row.
func TestRBACDenialIsNotMaskedByACL(t *testing.T) {
	env := newTestEnv(t)
	roleID, userID := seedRoleWithoutPermission(t, 1, "viewer", "dave")

	grantACL(t, 1, perm.SubjectRole, roleID, "/", int(perm.ActionRead), 0)
	if allowed, err := env.perm.Allowed(t.Context(), 1, userID, "/reports", perm.ActionRead); err != nil || allowed {
		t.Fatalf("role without a permission code = %v, %v; want false", allowed, err)
	}

	db := openTestDB(t)
	defer db.Close()
	if _, err := db.Exec(
		"INSERT INTO role_permission (tenant_id, role_id, permission) VALUES (?, ?, ?)",
		1, roleID, perm.PermRead); err != nil {
		t.Fatalf("grant file.read to role %d: %v", roleID, err)
	}
	envForCache(t)
	if allowed, err := env.perm.Allowed(t.Context(), 1, userID, "/reports", perm.ActionRead); err != nil || !allowed {
		t.Fatalf("after granting file.read = %v, %v; want true", allowed, err)
	}
}

// The second check of the same (user, path, action) must not touch the database.
func TestPermissionCacheSkipsDatabaseOnSecondCall(t *testing.T) {
	env := newTestEnv(t)
	_ = env.login(t, "east", "alice", seedPassword).Data.Token

	first := env.perm.Queries()
	if allowed, err := env.perm.Allowed(t.Context(), 1, 1, "/cached/path", perm.ActionRead); err != nil || !allowed {
		t.Fatalf("first check = %v, %v", allowed, err)
	}
	afterFirst := env.perm.Queries()
	if afterFirst <= first {
		t.Fatalf("first check issued no query (%d -> %d)", first, afterFirst)
	}

	for i := 0; i < 5; i++ {
		if allowed, err := env.perm.Allowed(t.Context(), 1, 1, "/cached/path", perm.ActionRead); err != nil || !allowed {
			t.Fatalf("cached check %d = %v, %v", i, allowed, err)
		}
	}
	if after := env.perm.Queries(); after != afterFirst {
		t.Fatalf("cached checks issued %d more queries, want 0", after-afterFirst)
	}
}

// A revocation must not be masked by the cache.
func TestInvalidateSubjectDropsCachedDecisions(t *testing.T) {
	env := newTestEnv(t)

	if allowed, _ := env.perm.Allowed(t.Context(), 1, 1, "/dept", perm.ActionRead); !allowed {
		t.Fatal("baseline read should be allowed")
	}
	grantACL(t, 1, perm.SubjectUser, 1, "/dept", 0, int(perm.ActionRead))
	if allowed, _ := env.perm.Allowed(t.Context(), 1, 1, "/dept", perm.ActionRead); allowed {
		t.Fatal("deny was not applied after being written")
	}

	removeACL(t, 1, perm.SubjectUser, 1, "/dept")
	if err := env.perm.InvalidateSubject(t.Context(), 1, perm.SubjectUser, 1); err != nil {
		t.Fatalf("invalidate: %v", err)
	}
	if allowed, _ := env.perm.Allowed(t.Context(), 1, 1, "/dept", perm.ActionRead); !allowed {
		t.Fatal("cache outlived the revocation")
	}
}

// The burst must be exhausted into 429s, then recover once the window refills.
func TestTenantRateLimitBurstThenRecover(t *testing.T) {
	rdb := redisForTests(t)

	// A tiny bucket with a short window keeps the test under a few seconds.
	limiter, err := ratelimit.NewLimiter(rdb, 3, 2*time.Second)
	if err != nil {
		t.Fatalf("new limiter: %v", err)
	}
	const tenantID int64 = 424242
	if err := limiter.Reset(t.Context(), tenantID); err != nil {
		t.Fatalf("reset: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = limiter.Reset(ctx, tenantID)
	})

	for i := 0; i < 3; i++ {
		res, err := limiter.Allow(t.Context(), tenantID)
		if err != nil || !res.Allowed {
			t.Fatalf("request %d = %+v, %v; want allowed", i, res, err)
		}
	}

	blocked, err := limiter.Allow(t.Context(), tenantID)
	if err != nil {
		t.Fatalf("fourth request: %v", err)
	}
	if blocked.Allowed {
		t.Fatal("fourth request passed an exhausted bucket")
	}
	if blocked.RetryAfter <= 0 {
		t.Fatalf("retry-after = %v, want a positive hint", blocked.RetryAfter)
	}

	// Wait out the refill and the bucket must work again.
	time.Sleep(blocked.RetryAfter + 100*time.Millisecond)
	recovered, err := limiter.Allow(t.Context(), tenantID)
	if err != nil || !recovered.Allowed {
		t.Fatalf("after waiting = %+v, %v; want allowed", recovered, err)
	}
}

// One tenant exhausting its bucket must not slow another tenant down.
func TestRateLimitIsPerTenant(t *testing.T) {
	rdb := redisForTests(t)
	limiter, err := ratelimit.NewLimiter(rdb, 2, time.Minute)
	if err != nil {
		t.Fatalf("new limiter: %v", err)
	}
	const noisy, quiet int64 = 515151, 525252
	for _, id := range []int64{noisy, quiet} {
		if err := limiter.Reset(t.Context(), id); err != nil {
			t.Fatalf("reset %d: %v", id, err)
		}
	}

	for i := 0; i < 2; i++ {
		if res, _ := limiter.Allow(t.Context(), noisy); !res.Allowed {
			t.Fatalf("noisy tenant request %d unexpectedly blocked", i)
		}
	}
	if res, _ := limiter.Allow(t.Context(), noisy); res.Allowed {
		t.Fatal("noisy tenant was not blocked")
	}
	if res, err := limiter.Allow(t.Context(), quiet); err != nil || !res.Allowed {
		t.Fatalf("quiet tenant = %+v, %v; want allowed", res, err)
	}
}

// The HTTP path: an exhausted tenant gets 429 with a Retry-After header.
func TestRateLimitMiddlewareReturns429(t *testing.T) {
	// The bucket lives in Redis and is keyed by tenant, so this test must not
	// inherit whatever an earlier one left in tenant 1's bucket.
	resetTenantBucket(t, 1)

	env := newTestEnvWithLimit(t, 2, time.Minute)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	for i := 0; i < 2; i++ {
		rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/permissions", token, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d = %d (body=%s)", i, rec.Code, rec.Body.String())
		}
	}

	rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/permissions", token, nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("third request = %d, want 429 (body=%s)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Retry-After"); got == "" {
		t.Fatal("429 without a Retry-After header")
	}
	var body struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode 429: %v", err)
	}
	if body.Code != http.StatusTooManyRequests {
		t.Fatalf("body code = %d, want 429", body.Code)
	}
}

// The ACL management endpoint is what makes a revocation real: before it existed
// the only way to write a row was SQL plus a manual cache flush, so an operator
// revoking access saw it keep working until the TTL ran out.
func TestACLManagementRevokesThroughTheAPI(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	// Warm the cache: the file is readable through the inherited root grant.
	up := mustUpload(t, env, token, "/hr/2026", "salary.txt", []byte("confidential"))
	id := itoa(up.Data.ID)
	if rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/files/"+id+"/download", token, nil); rec.Code != http.StatusOK {
		t.Fatalf("baseline download = %d (body=%s)", rec.Code, rec.Body.String())
	}

	rec := doJSON(t, env.engine, http.MethodPut, "/api/v1/permissions/acl", token, map[string]any{
		"subject_kind": "user",
		"subject_id":   1,
		"path":         "/hr/2026",
		"actions":      []string{"read"},
		"deny":         true,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("write acl = %d (body=%s)", rec.Code, rec.Body.String())
	}

	// No manual cache flush anywhere in this test: the endpoint has to do it.
	if rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/files/"+id+"/download", token, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("download after the deny = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
	// The deny is scoped to the directory it names.
	if rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/permissions/check?action=read&path=%2Fhr%2F2026%2Fpublic", token, nil); rec.Code != http.StatusOK {
		t.Fatalf("check on a child path = %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// Deleting the row puts the inherited grant back, again without a manual flush.
func TestACLManagementRestoresAfterDelete(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	up := mustUpload(t, env, token, "/hr", "promo.txt", []byte("internal"))
	id := itoa(up.Data.ID)

	setACL(t, env, token, "user", 1, "/hr", []string{"read"}, true)
	if rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/files/"+id+"/download", token, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("download after deny = %d, want 403", rec.Code)
	}

	rec := doJSON(t, env.engine, http.MethodDelete,
		"/api/v1/permissions/acl?subject_kind=user&subject_id=1&path=%2Fhr", token, nil)
	if rec.Code != http.StatusOK || !containsAll(rec.Body.String(), `"removed":true`) {
		t.Fatalf("delete acl = %d (body=%s)", rec.Code, rec.Body.String())
	}
	if rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/files/"+id+"/download", token, nil); rec.Code != http.StatusOK {
		t.Fatalf("download after removing the deny = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
}

// Granting yourself access is the escalation the ACL exists to stop, so the
// endpoint requires perm.manage rather than merely being authenticated.
func TestACLManagementRequiresManagePermission(t *testing.T) {
	env := newTestEnv(t)
	_, userID := seedRoleWithoutPermission(t, 1, "viewer", "erin")
	grantACL(t, 1, perm.SubjectUser, userID, "/", int(perm.ActionRead), 0)

	// Give that user a login so the request carries a real token.
	db := openTestDB(t)
	defer db.Close()
	if _, err := db.Exec("UPDATE `user` SET password_hash = ? WHERE id = ?", seedPasswordHash, userID); err != nil {
		t.Fatalf("set password: %v", err)
	}
	viewer := env.login(t, "east", "erin", seedPassword).Data.Token

	rec := doJSON(t, env.engine, http.MethodPut, "/api/v1/permissions/acl", viewer, map[string]any{
		"subject_kind": "user",
		"subject_id":   userID,
		"path":         "/secret",
		"actions":      []string{"read", "write", "delete"},
		"deny":         false,
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("acl write without perm.manage = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}

	// Nothing was written: the caller is still refused on the path it tried to take.
	if allowed, err := env.perm.Allowed(t.Context(), 1, userID, "/secret", perm.ActionRead); err != nil {
		t.Fatalf("check: %v", err)
	} else if allowed {
		t.Fatal("the refused request still created an allow row")
	}
}

// setACL writes a grant through the API and fails the test if it is not accepted.
func setACL(t *testing.T, env *testEnv, token, kind string, subjectID int64, path string, actions []string, deny bool) {
	t.Helper()
	rec := doJSON(t, env.engine, http.MethodPut, "/api/v1/permissions/acl", token, map[string]any{
		"subject_kind": kind,
		"subject_id":   subjectID,
		"path":         path,
		"actions":      actions,
		"deny":         deny,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("write acl %s %d %q = %d (body=%s)", kind, subjectID, path, rec.Code, rec.Body.String())
	}
}

// grantACL writes one ACL row directly, standing in for the management API that
// is out of scope for this stage.
func grantACL(t *testing.T, tenantID int64, kind string, subjectID int64, path string, allow, deny int) {
	t.Helper()
	db := openTestDB(t)
	defer db.Close()

	normalized := perm.NormalizePath(path)
	if _, err := db.Exec(`
		INSERT INTO acl_entry (tenant_id, subject_kind, subject_id, path, allow_mask, deny_mask, depth)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE allow_mask = VALUES(allow_mask), deny_mask = VALUES(deny_mask)`,
		tenantID, kind, subjectID, normalized, allow, deny, perm.PathDepth(normalized)); err != nil {
		t.Fatalf("grant acl on %q: %v", path, err)
	}
	envForCache(t)
}

func removeACL(t *testing.T, tenantID int64, kind string, subjectID int64, path string) {
	t.Helper()
	db := openTestDB(t)
	defer db.Close()
	if _, err := db.Exec(`
		DELETE FROM acl_entry WHERE tenant_id = ? AND subject_kind = ? AND subject_id = ? AND path = ?`,
		tenantID, kind, subjectID, perm.NormalizePath(path)); err != nil {
		t.Fatalf("remove acl on %q: %v", path, err)
	}
}

// resetTenantBucket clears a tenant's token bucket so a test starts full.
func resetTenantBucket(t *testing.T, tenantID int64) {
	t.Helper()
	rdb := redisForTests(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := rdb.Del(ctx, fmt.Sprintf("ratelimit:tenant:%d", tenantID)).Err(); err != nil {
		t.Fatalf("reset bucket for tenant %d: %v", tenantID, err)
	}
}

func envForCache(t *testing.T) {
	t.Helper()
	// Writing permissions straight to MySQL bypasses the service layer, so the
	// cache must be cleared the way a real mutation would.
	rdb := redis.NewClient(&redis.Options{Addr: redisAddr()})
	defer rdb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	keys, err := rdb.Keys(ctx, "perm:*").Result()
	if err != nil || len(keys) == 0 {
		return
	}
	if err := rdb.Del(ctx, keys...).Err(); err != nil {
		t.Fatalf("clear permission cache: %v", err)
	}
}
