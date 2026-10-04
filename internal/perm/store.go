package perm

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/jmoiron/sqlx"
)

// cacheTTL bounds how long a stale permission snapshot can survive. Invalidation
// is explicit on top of this, so the TTL only matters if a delete is lost.
const cacheTTL = 10 * time.Minute

// Store reads the RBAC and ACL rows and caches the resolved answer.
//
// The cache is keyed per (tenant, user, path, action) and stores a single bool.
// That is deliberate: caching the inputs would mean re-resolving on every hit,
// while caching the decision is one Redis GET and zero SQL. Permissions change
// rarely and are revoked explicitly, so the trade is safe.
type Store struct {
	db  *sqlx.DB
	rdb *redis.Client
	// queries counts database round trips, which the cache test asserts against.
	// A counter is cheaper and more honest than wrapping the driver.
	queries int64
}

func NewStore(db *sqlx.DB, rdb *redis.Client) *Store {
	return &Store{db: db, rdb: rdb}
}

// Queries reports how many database queries this store has issued.
func (s *Store) Queries() int64 {
	return atomic.LoadInt64(&s.queries)
}

func cacheKey(tenantID, userID int64, path string, action Action) string {
	return fmt.Sprintf("perm:%d:%d:%s:%d", tenantID, userID, path, int(action))
}

// Permissions returns the permission codes granted to a user's roles.
//
// It does not check the user's tenant beyond the role join: a user whose id is
// passed with a foreign tenant simply has no rows, which is the same answer as
// having no roles.
func (s *Store) Permissions(ctx context.Context, tenantID, userID int64) ([]string, error) {
	atomic.AddInt64(&s.queries, 1)
	var codes []string
	err := s.db.SelectContext(ctx, &codes, `
		SELECT DISTINCT rp.permission
		FROM user_role ur
		JOIN role_permission rp ON rp.role_id = ur.role_id AND rp.tenant_id = ?
		WHERE ur.user_id = ?
		ORDER BY rp.permission`, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("query permissions of user %d: %w", userID, err)
	}
	return codes, nil
}

// loadEntries fetches every ACL row on the ancestor chain of path, nearest first.
func (s *Store) loadEntries(ctx context.Context, tenantID, userID int64, path string) ([]Entry, error) {
	atomic.AddInt64(&s.queries, 1)
	paths := Ancestors(path)

	// sqlx.In expands slice arguments in the order their placeholders appear, so
	// the arguments follow the query's own order: tenant, paths, user, user again
	// for the roles subquery.
	//
	// The roles subquery is scoped by tenant as well. Without that, a user id from
	// another tenant would match rows granted to that tenant's role and the ACL
	// would leak across tenants — which is exactly what the isolation test caught.
	query, args, err := sqlx.In(`
		SELECT subject_kind, subject_id, path, allow_mask, deny_mask, depth
		FROM acl_entry
		WHERE tenant_id = ?
		  AND path IN (?)
		  AND (
		      (subject_kind = 'user' AND subject_id = ?)
		   OR (subject_kind = 'role' AND subject_id IN (
		          SELECT ur.role_id
		          FROM user_role ur
		          JOIN role r ON r.id = ur.role_id AND r.tenant_id = ?
		          WHERE ur.user_id = ?
		      ))
		  )
		ORDER BY depth DESC`, tenantID, paths, userID, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("build acl query: %w", err)
	}

	var out []Entry
	if err := s.db.SelectContext(ctx, &out, s.db.Rebind(query), args...); err != nil {
		return nil, fmt.Errorf("query acl for %q: %w", path, err)
	}
	return out, nil
}

// Allowed answers whether userID may perform action on path in tenantID.
func (s *Store) Allowed(ctx context.Context, tenantID, userID int64, path string, action Action) (bool, error) {
	path = NormalizePath(path)

	if cached, err := s.rdb.Get(ctx, cacheKey(tenantID, userID, path, action)).Result(); err == nil {
		return cached == "1", nil
	} else if err != redis.Nil {
		// A cache outage must not become an outage of the check itself: fall
		// through to the database and let the error surface only there.
		_ = err
	}

	permCode, err := PermissionFor(action)
	if err != nil {
		return false, err
	}

	perms, err := s.Permissions(ctx, tenantID, userID)
	if err != nil {
		return false, err
	}
	if !contains(perms, permCode) {
		s.remember(ctx, tenantID, userID, path, action, false)
		return false, nil
	}

	entries, err := s.loadEntries(ctx, tenantID, userID, path)
	if err != nil {
		return false, err
	}
	ok := Resolve(entries, path, action)
	s.remember(ctx, tenantID, userID, path, action, ok)
	return ok, nil
}

// EntriesForTest exposes the ACL rows a resolver would see for (tenant, user,
// path). It exists so a test can assert tenant scoping on the resolver's input,
// which a plain Allowed() call cannot show: a user with a root grant is allowed
// everywhere in their own tenant regardless of whose row granted it.
func (s *Store) EntriesForTest(ctx context.Context, tenantID, userID int64, path string) ([]Entry, error) {
	return s.loadEntries(ctx, tenantID, userID, path)
}

// remember stores a decision; a Redis failure is not worth failing a request
// over, since the answer was already computed from the database.
func (s *Store) remember(ctx context.Context, tenantID, userID int64, path string, action Action, allowed bool) {
	value := "0"
	if allowed {
		value = "1"
	}
	_ = s.rdb.Set(ctx, cacheKey(tenantID, userID, path, action), value, cacheTTL).Err()
}

// InvalidateSubject drops the cached decisions that could involve a user or a
// role. Called from any permission mutation, which is what keeps the cache from
// outliving a revocation.
func (s *Store) InvalidateSubject(ctx context.Context, tenantID int64, subjectKind string, subjectID int64) error {
	var users []int64
	if subjectKind == SubjectUser {
		users = []int64{subjectID}
	} else {
		if err := s.db.SelectContext(ctx, &users,
			"SELECT user_id FROM user_role WHERE role_id = ?", subjectID); err != nil {
			return fmt.Errorf("query users of role %d: %w", subjectID, err)
		}
	}
	for _, u := range users {
		pattern := fmt.Sprintf("perm:%d:%d:*", tenantID, u)
		keys, err := s.rdb.Keys(ctx, pattern).Result()
		if err != nil {
			return fmt.Errorf("scan permission cache: %w", err)
		}
		if len(keys) > 0 {
			if err := s.rdb.Del(ctx, keys...).Err(); err != nil {
				return fmt.Errorf("drop permission cache: %w", err)
			}
		}
	}
	return nil
}

// SetEntry writes one ACL row and drops the cached decisions it can affect.
//
// The write and the invalidation belong together: a row that lands while the old
// decision is still cached gives an operator a revoke that appears to do nothing
// until the TTL expires, which is the exact failure the Stage 4 report recorded.
func (s *Store) SetEntry(ctx context.Context, tenantID int64, subjectKind string, subjectID int64, path string, allowMask, denyMask int) error {
	normalized := NormalizePath(path)
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO acl_entry (tenant_id, subject_kind, subject_id, path, allow_mask, deny_mask, depth)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE allow_mask = VALUES(allow_mask), deny_mask = VALUES(deny_mask)`,
		tenantID, subjectKind, subjectID, normalized, allowMask, denyMask, PathDepth(normalized)); err != nil {
		return fmt.Errorf("write acl entry for %q: %w", normalized, err)
	}
	return s.InvalidateSubject(ctx, tenantID, subjectKind, subjectID)
}

// DeleteEntry removes one ACL row. A missing row is not an error: the caller
// asked for "no entry here" and that is now true. It reports whether a row went
// away so the handler can still say something useful.
func (s *Store) DeleteEntry(ctx context.Context, tenantID int64, subjectKind string, subjectID int64, path string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM acl_entry
		WHERE tenant_id = ? AND subject_kind = ? AND subject_id = ? AND path = ?`,
		tenantID, subjectKind, subjectID, NormalizePath(path))
	if err != nil {
		return false, fmt.Errorf("delete acl entry: %w", err)
	}
	removed, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("count deleted acl entries: %w", err)
	}
	// Even a no-op delete invalidates: the caller may be correcting a row written
	// by hand outside the API, and a stale allow is the expensive mistake here.
	if err := s.InvalidateSubject(ctx, tenantID, subjectKind, subjectID); err != nil {
		return removed > 0, err
	}
	return removed > 0, nil
}

// HasPermission reports whether one user's roles carry a permission code. It is
// the RBAC half on its own, for routes that need a capability rather than a
// directory decision.
func (s *Store) HasPermission(ctx context.Context, tenantID, userID int64, code string) (bool, error) {
	perms, err := s.Permissions(ctx, tenantID, userID)
	if err != nil {
		return false, err
	}
	return contains(perms, code), nil
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
