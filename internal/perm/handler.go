package perm

import (
	"errors"
	"strconv"

	"github.com/gin-gonic/gin"

	"godochub/internal/file"
	"godochub/internal/httpx"
	"godochub/internal/tenant"
)

// Handler exposes the permission checks the API needs.
type Handler struct {
	store *Store
}

func NewHandler(store *Store) *Handler {
	return &Handler{store: store}
}

// Guard rejects a request when the caller's roles and ACL do not allow action on
// the path taken from the request.
//
// pathOf decides which path the check applies to, so the same guard serves
// routes that name a file id and routes that name a directory.
//
// A pathOf error goes through mapResolveError rather than becoming a flat 400:
// a malformed id resolves to 400, a row that does not exist to 404, so a foreign
// id and a malformed one stay distinguishable to the client.
func Guard(store *Store, action Action, pathOf func(*gin.Context) (string, error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		ident, ok := tenant.FromContext(c.Request.Context())
		if !ok {
			c.Abort()
			_ = c.Error(httpx.ErrUnauthorized)
			return
		}
		path, err := pathOf(c)
		if err != nil {
			c.Abort()
			// A resolver reports "no such row" and "bad id" with its own sentinel
			// errors; only the generic ones need translating here, and anything
			// else is an internal failure httpx will render as 500.
			_ = c.Error(mapResolveError(err))
			return
		}

		allowed, err := store.Allowed(c.Request.Context(), ident.TenantID, ident.UserID, path, action)
		if err != nil {
			c.Abort()
			_ = c.Error(err)
			return
		}
		if !allowed {
			c.Abort()
			_ = c.Error(httpx.ErrForbidden)
			return
		}
		c.Next()
	}
}

// RequireManage rejects a request whose caller's roles do not carry perm.manage.
//
// It exists for routes that need a capability rather than a directory decision
// (creating accounts, granting roles): there is no path to resolve there, so the
// ACL half of the model does not apply and Guard would be the wrong tool.
func RequireManage(store *Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		ident, ok := tenant.FromContext(c.Request.Context())
		if !ok {
			c.Abort()
			_ = c.Error(httpx.ErrUnauthorized)
			return
		}
		ok, err := store.HasPermission(c.Request.Context(), ident.TenantID, ident.UserID, PermManage)
		if err != nil {
			c.Abort()
			_ = c.Error(err)
			return
		}
		if !ok {
			c.Abort()
			_ = c.Error(httpx.ErrForbidden)
			return
		}
		c.Next()
	}
}

// MyPermissions reports the caller's effective permission codes, which makes the
// RBAC half of the decision inspectable without reading the database.
func (h *Handler) MyPermissions(c *gin.Context) {
	ident, ok := tenant.FromContext(c.Request.Context())
	if !ok {
		_ = c.Error(httpx.ErrUnauthorized)
		return
	}
	perms, err := h.store.Permissions(c.Request.Context(), ident.TenantID, ident.UserID)
	if err != nil {
		_ = c.Error(err)
		return
	}
	if perms == nil {
		perms = []string{}
	}
	httpx.OK(c, gin.H{"permissions": perms})
}

// Check is the query endpoint: it answers whether the caller may do action on
// path, and nothing else. Useful for clients that want to render before acting.
func (h *Handler) Check(c *gin.Context) {
	ident, ok := tenant.FromContext(c.Request.Context())
	if !ok {
		_ = c.Error(httpx.ErrUnauthorized)
		return
	}
	actionCode, err := parseAction(c.Query("action"))
	if err != nil {
		_ = c.Error(httpx.ErrInvalidRequest)
		return
	}
	path := c.Query("path")

	allowed, err := h.store.Allowed(c.Request.Context(), ident.TenantID, ident.UserID, path, actionCode)
	if err != nil {
		_ = c.Error(err)
		return
	}
	httpx.OK(c, gin.H{"path": NormalizePath(path), "action": c.Query("action"), "allowed": allowed})
}

// SetACL writes one directory grant. It requires perm.manage: granting yourself
// access is exactly the escalation an ACL is for, so the capability is checked
// before the row is touched and the subject is always the caller's tenant.
func (h *Handler) SetACL(c *gin.Context) {
	ident, ok := tenant.FromContext(c.Request.Context())
	if !ok {
		_ = c.Error(httpx.ErrUnauthorized)
		return
	}
	if !h.requireManage(c) {
		return
	}

	var body struct {
		SubjectKind string   `json:"subject_kind"`
		SubjectID   int64    `json:"subject_id"`
		Path        string   `json:"path"`
		Actions     []string `json:"actions"`
		Deny        bool     `json:"deny"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		_ = c.Error(httpx.ErrInvalidRequest)
		return
	}
	if body.SubjectKind != SubjectUser && body.SubjectKind != SubjectRole {
		_ = c.Error(httpx.ErrInvalidRequest)
		return
	}
	if body.SubjectID <= 0 || len(body.Actions) == 0 {
		_ = c.Error(httpx.ErrInvalidRequest)
		return
	}
	mask, err := actionMask(body.Actions)
	if err != nil {
		_ = c.Error(httpx.ErrInvalidRequest)
		return
	}

	// A path is the unit of an ACL row, so an empty one means the root rather than
	// "no path": NormalizePath already collapses it, and saying so explicitly keeps
	// the caller from silently granting "/" by accident.
	path := NormalizePath(body.Path)
	allow, deny := mask, 0
	if body.Deny {
		allow, deny = 0, mask
	}
	if err := h.store.SetEntry(c.Request.Context(), ident.TenantID,
		body.SubjectKind, body.SubjectID, path, allow, deny); err != nil {
		_ = c.Error(err)
		return
	}
	httpx.OK(c, gin.H{
		"tenant_id":    ident.TenantID,
		"subject_kind": body.SubjectKind,
		"subject_id":   body.SubjectID,
		"path":         path,
		"allow_mask":   allow,
		"deny_mask":    deny,
	})
}

// DeleteACL removes one directory grant, with the same capability check.
func (h *Handler) DeleteACL(c *gin.Context) {
	ident, ok := tenant.FromContext(c.Request.Context())
	if !ok {
		_ = c.Error(httpx.ErrUnauthorized)
		return
	}
	if !h.requireManage(c) {
		return
	}

	subjectKind := c.Query("subject_kind")
	if subjectKind != SubjectUser && subjectKind != SubjectRole {
		_ = c.Error(httpx.ErrInvalidRequest)
		return
	}
	subjectID, err := strconv.ParseInt(c.Query("subject_id"), 10, 64)
	if err != nil || subjectID <= 0 {
		_ = c.Error(httpx.ErrInvalidRequest)
		return
	}
	if c.Query("path") == "" {
		_ = c.Error(httpx.ErrInvalidRequest)
		return
	}

	removed, err := h.store.DeleteEntry(c.Request.Context(), ident.TenantID,
		subjectKind, subjectID, c.Query("path"))
	if err != nil {
		_ = c.Error(err)
		return
	}
	httpx.OK(c, gin.H{"removed": removed, "path": NormalizePath(c.Query("path"))})
}

// requireManage enforces perm.manage and writes the error itself, so the two ACL
// handlers cannot forget it.
func (h *Handler) requireManage(c *gin.Context) bool {
	ident, ok := tenant.FromContext(c.Request.Context())
	if !ok {
		_ = c.Error(httpx.ErrUnauthorized)
		return false
	}
	ok, err := h.store.HasPermission(c.Request.Context(), ident.TenantID, ident.UserID, PermManage)
	if err != nil {
		_ = c.Error(err)
		return false
	}
	if !ok {
		_ = c.Error(httpx.ErrForbidden)
		return false
	}
	return true
}

// actionMask turns the public action names into the stored bitmask.
func actionMask(names []string) (int, error) {
	mask := 0
	for _, n := range names {
		a, err := parseAction(n)
		if err != nil {
			return 0, err
		}
		mask |= int(a)
	}
	return mask, nil
}

// mapResolveError translates the errors a path resolver can return into the
// unified client-facing ones. Anything else stays as-is and becomes a 500.
func mapResolveError(err error) error {
	var apiErr *httpx.Error
	if errors.As(err, &apiErr) {
		return err
	}
	if errors.Is(err, file.ErrNotFound) {
		return httpx.ErrNotFound
	}
	if errors.Is(err, file.ErrInvalidPath) {
		return httpx.ErrInvalidRequest
	}
	return err
}

// parseAction maps the public action names onto the bitmask.
func parseAction(s string) (Action, error) {
	switch s {
	case "read":
		return ActionRead, nil
	case "write":
		return ActionWrite, nil
	case "delete":
		return ActionDelete, nil
	default:
		return 0, errors.New("perm: unknown action " + s)
	}
}
