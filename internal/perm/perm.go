// Package perm answers one question: may this caller act on this path?
//
// It combines two layers. RBAC says whether the caller's roles can perform the
// action at all; ACL says whether they are allowed on this particular path, with
// entries inherited down the directory tree. Deny entries win over inherited
// allows, which is what makes an exception expressible.
package perm

import (
	"errors"
	"fmt"
	"strings"
)

// Action is one bit in the ACL mask. The values are stored in the database, so
// they must never be renumbered.
type Action int

const (
	ActionRead Action = 1 << iota
	ActionWrite
	ActionDelete
)

var ErrInvalidAction = errors.New("perm: invalid action")

// Permission codes, matching migrations/0004_perm.sql.
const (
	PermRead   = "file.read"
	PermWrite  = "file.write"
	PermDelete = "file.delete"
	// PermManage gates writes to the ACL itself.
	PermManage = "perm.manage"
)

// PermissionFor maps an action to the RBAC permission that must back it.
func PermissionFor(a Action) (string, error) {
	switch a {
	case ActionRead:
		return PermRead, nil
	case ActionWrite:
		return PermWrite, nil
	case ActionDelete:
		return PermDelete, nil
	}
	return "", fmt.Errorf("%w: %d", ErrInvalidAction, int(a))
}

// Subject kinds.
const (
	SubjectUser = "user"
	SubjectRole = "role"
)

// Entry is one ACL row. Depth is the path depth, precomputed so ordering by
// specificity does not require string work per request.
type Entry struct {
	SubjectKind string `db:"subject_kind"`
	SubjectID   int64  `db:"subject_id"`
	Path        string `db:"path"`
	AllowMask   int    `db:"allow_mask"`
	DenyMask    int    `db:"deny_mask"`
	Depth       int    `db:"depth"`
}

// PathDepth counts the segments of a normalised path: "/" is 0, "/a" is 1.
func PathDepth(p string) int {
	return strings.Count(strings.Trim(p, "/"), "/") + boolToInt(p != "/" && strings.Trim(p, "/") != "")
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Ancestors returns the paths that cover target, nearest first: "/a/b/c",
// "/a/b", "/a", "/". The ACL resolves by walking this list.
func Ancestors(target string) []string {
	target = NormalizePath(target)
	if target == "/" {
		return []string{"/"}
	}
	out := []string{target}
	cur := target
	for cur != "/" {
		idx := strings.LastIndex(cur, "/")
		if idx <= 0 {
			cur = "/"
		} else {
			cur = cur[:idx]
		}
		out = append(out, cur)
	}
	return out
}

// NormalizePath mirrors file.NormalizeDir's output shape without importing the
// file package (perm must stay usable for resources that are not files).
func NormalizePath(p string) string {
	if p == "" || p == "/" {
		return "/"
	}
	clean := "/" + strings.Trim(p, "/")
	for strings.Contains(clean, "//") {
		clean = strings.ReplaceAll(clean, "//", "/")
	}
	return clean
}

// Resolve applies the ACL entries that cover target.
//
// Rules, in this order:
//  1. If any entry on target's ancestor chain denies the action, the answer is
//     deny. A deny deep in the tree must not be overridden by a broader allow,
//     and it must not leak to siblings either — only paths that actually contain
//     target are considered.
//  2. Otherwise, an allow on the most specific path wins.
//  3. No matching allow means no access: silence is not permission.
func Resolve(entries []Entry, target string, action Action) bool {
	bit := int(action)
	target = NormalizePath(target)

	covering := make([]Entry, 0, len(entries))
	for _, e := range entries {
		if covers(e.Path, target) {
			covering = append(covering, e)
		}
	}

	// Deny first: a narrower allow cannot outvote a deny that covers the path.
	for _, e := range covering {
		if e.DenyMask&bit != 0 {
			return false
		}
	}

	best := -1
	for i, e := range covering {
		if e.AllowMask&bit == 0 {
			continue
		}
		if best == -1 || e.Depth > covering[best].Depth {
			best = i
		}
	}
	return best != -1
}

// covers reports whether entryPath is target or an ancestor of it. Both are
// already normalised, so the check is a prefix match on a path boundary: "/a"
// covers "/a/b" but not "/ab".
func covers(entryPath, target string) bool {
	entryPath = NormalizePath(entryPath)
	if entryPath == "/" {
		return true
	}
	if entryPath == target {
		return true
	}
	return strings.HasPrefix(target, entryPath+"/")
}
