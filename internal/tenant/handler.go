package tenant

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"godochub/internal/httpx"
)

type Handler struct {
	store *Store
}

func NewHandler(store *Store) *Handler {
	return &Handler{store: store}
}

// ME answers "who am I and which tenant do I belong to" for the caller.
func (h *Handler) ME(c *gin.Context) {
	ident, ok := FromContext(c.Request.Context())
	if !ok {
		_ = c.Error(httpx.ErrUnauthorized)
		return
	}
	roles, err := h.store.RolesOf(c.Request.Context(), ident.TenantID, ident.UserID)
	if errors.Is(err, ErrNotFound) {
		// The caller is authenticated but no longer has a row: the token outlived
		// the user. An empty list keeps the response shape stable.
		roles = []string{}
	} else if err != nil {
		_ = c.Error(err)
		return
	}
	httpx.OK(c, gin.H{"identity": ident, "roles": roles})
}

// UserRoles is the sample protected resource: it exposes another user's roles
// and must only ever answer for the caller's own tenant. A cross-tenant id looks
// exactly like a missing one — answering 403 would confirm the id exists.
func (h *Handler) UserRoles(c *gin.Context) {
	ident, ok := FromContext(c.Request.Context())
	if !ok {
		_ = c.Error(httpx.ErrUnauthorized)
		return
	}
	userID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || userID <= 0 {
		_ = c.Error(httpx.ErrInvalidRequest)
		return
	}

	roles, err := h.store.RolesOf(c.Request.Context(), ident.TenantID, userID)
	if errors.Is(err, ErrNotFound) {
		_ = c.Error(httpx.ErrNotFound)
		return
	}
	if err != nil {
		_ = c.Error(err)
		return
	}
	httpx.OK(c, gin.H{"user_id": userID, "roles": roles})
}

// CreateUser adds an account to the caller's own tenant.
//
// The tenant is taken from the token, never from the body: accepting it would
// let any authenticated caller mint accounts in someone else's tenant, which is
// the one thing the tenant boundary exists to prevent.
func (h *Handler) CreateUser(c *gin.Context) {
	ident, ok := FromContext(c.Request.Context())
	if !ok {
		_ = c.Error(httpx.ErrUnauthorized)
		return
	}
	var body struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		DisplayName string `json:"display_name"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		_ = c.Error(httpx.ErrInvalidRequest)
		return
	}
	if body.Username == "" {
		_ = c.Error(httpx.ErrInvalidRequest)
		return
	}
	if body.DisplayName == "" {
		body.DisplayName = body.Username
	}

	u, err := h.store.CreateUser(c.Request.Context(), ident.TenantID, body.Username, body.DisplayName, body.Password)
	if errors.Is(err, ErrUsernameTaken) {
		_ = c.Error(httpx.NewError(http.StatusConflict, "this username is already used in the tenant"))
		return
	}
	if err != nil {
		_ = c.Error(mapAdminError(err))
		return
	}
	httpx.OK(c, u)
}

// ListUsers reports the accounts of the caller's tenant.
func (h *Handler) ListUsers(c *gin.Context) {
	ident, ok := FromContext(c.Request.Context())
	if !ok {
		_ = c.Error(httpx.ErrUnauthorized)
		return
	}
	limit, offset, err := pageParams(c)
	if err != nil {
		_ = c.Error(httpx.ErrInvalidRequest)
		return
	}
	users, err := h.store.ListUsers(c.Request.Context(), ident.TenantID, limit, offset)
	if err != nil {
		_ = c.Error(err)
		return
	}
	body := gin.H{"users": users, "limit": limit}
	if len(users) == limit {
		body["next_offset"] = offset + limit
	}
	httpx.OK(c, body)
}

// AssignRole grants a role to a user, both from the caller's tenant.
//
// The role is named in the path, so there is no body to bind: a client that sends
// one anyway is not an error, it is simply ignored.
func (h *Handler) AssignRole(c *gin.Context) {
	ident, ok := FromContext(c.Request.Context())
	if !ok {
		_ = c.Error(httpx.ErrUnauthorized)
		return
	}
	userID, err := parsePathID(c.Param("id"))
	if err != nil {
		_ = c.Error(httpx.ErrInvalidRequest)
		return
	}
	roleID, err := parsePathID(c.Param("role_id"))
	if err != nil {
		_ = c.Error(httpx.ErrInvalidRequest)
		return
	}
	if err := h.store.AssignRole(c.Request.Context(), ident.TenantID, userID, roleID); err != nil {
		_ = c.Error(mapAdminError(err))
		return
	}
	httpx.OK(c, gin.H{"user_id": userID, "role_id": roleID, "granted": true})
}

// RevokeRole removes a grant.
func (h *Handler) RevokeRole(c *gin.Context) {
	ident, ok := FromContext(c.Request.Context())
	if !ok {
		_ = c.Error(httpx.ErrUnauthorized)
		return
	}
	userID, err := parsePathID(c.Param("id"))
	if err != nil {
		_ = c.Error(httpx.ErrInvalidRequest)
		return
	}
	roleID, err := parsePathID(c.Param("role_id"))
	if err != nil {
		_ = c.Error(httpx.ErrInvalidRequest)
		return
	}
	removed, err := h.store.RevokeRole(c.Request.Context(), ident.TenantID, userID, roleID)
	if err != nil {
		_ = c.Error(mapAdminError(err))
		return
	}
	httpx.OK(c, gin.H{"user_id": userID, "role_id": roleID, "removed": removed})
}

// ListRoles reports the roles the caller's tenant defines, so a client can pick
// a role id without reading the database.
// CreateRole defines a role and the permission codes it grants.
//
// Both halves arrive in one request because a role without permissions is not a
// usable object: it would show up in the list, be assignable, and silently deny
// everything. Requiring perm.manage keeps role definition with the other
// privileged acts — defining a role is deciding what people may do.
func (h *Handler) CreateRole(c *gin.Context) {
	ident, ok := FromContext(c.Request.Context())
	if !ok {
		_ = c.Error(httpx.ErrUnauthorized)
		return
	}
	var body struct {
		Code        string   `json:"code"`
		Name        string   `json:"name"`
		Permissions []string `json:"permissions"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		_ = c.Error(httpx.ErrInvalidRequest)
		return
	}

	role, err := h.store.CreateRole(c.Request.Context(), ident.TenantID, body.Code, body.Name, body.Permissions)
	if err != nil {
		_ = c.Error(mapAdminError(err))
		return
	}
	httpx.OK(c, role)
}

func (h *Handler) ListRoles(c *gin.Context) {
	ident, ok := FromContext(c.Request.Context())
	if !ok {
		_ = c.Error(httpx.ErrUnauthorized)
		return
	}
	roles, err := h.store.RolesOfTenant(c.Request.Context(), ident.TenantID)
	if err != nil {
		_ = c.Error(err)
		return
	}
	httpx.OK(c, gin.H{"roles": roles})
}

// Usage reports the tenant's footprint against its quota.
func (h *Handler) Usage(c *gin.Context) {
	ident, ok := FromContext(c.Request.Context())
	if !ok {
		_ = c.Error(httpx.ErrUnauthorized)
		return
	}
	u, err := h.store.Usage(c.Request.Context(), ident.TenantID)
	if err != nil {
		_ = c.Error(mapAdminError(err))
		return
	}
	httpx.OK(c, gin.H{
		"tenant_id":    u.TenantID,
		"file_count":   u.FileCount,
		"used_bytes":   u.UsedBytes,
		"quota_bytes":  u.QuotaBytes,
		"remaining":    u.Remaining(),
		"unlimited":    u.Unlimited,
		"used_percent": percent(u.UsedBytes, u.QuotaBytes),
	})
}

// percent renders usage as a rounded whole percentage; 0 when unlimited, since
// there is no denominator to divide by.
func percent(used, quota int64) int {
	if quota <= 0 {
		return 0
	}
	p := used * 100 / quota
	if p > 100 {
		return 100
	}
	return int(p)
}

// parsePathID reads a positive numeric path parameter.
func parsePathID(raw string) (int64, error) {
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("tenant: invalid id")
	}
	return id, nil
}

// pageParams mirrors the file listing's paging: a default, a ceiling, and a 400
// for nonsense rather than a silent fallback.
func pageParams(c *gin.Context) (limit, offset int, err error) {
	limit = defaultUserPageSize
	if raw := c.Query("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil || limit <= 0 {
			return 0, 0, errors.New("tenant: invalid limit")
		}
		if limit > maxUserPageSize {
			limit = maxUserPageSize
		}
	}
	if raw := c.Query("offset"); raw != "" {
		offset, err = strconv.Atoi(raw)
		if err != nil || offset < 0 {
			return 0, 0, errors.New("tenant: invalid offset")
		}
	}
	return limit, offset, nil
}

const (
	defaultUserPageSize = 50
	maxUserPageSize     = 200
)

// mapAdminError folds the package's sentinels into client-facing errors.
func mapAdminError(err error) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return httpx.ErrNotFound
	case errors.Is(err, ErrRoleNotFound):
		return httpx.NewError(http.StatusNotFound, "role not found in this tenant")
	case errors.Is(err, ErrRoleCodeTaken):
		return httpx.NewError(http.StatusConflict, "this role code is already used in the tenant")
	case errors.Is(err, ErrUnknownPermission):
		// The message names the offending code: a client sending a typo should
		// learn which one, not just "invalid request".
		return httpx.NewError(http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrInvalidRole):
		return httpx.NewError(http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrQuotaExceeded):
		return httpx.NewError(http.StatusRequestEntityTooLarge, "storage quota exceeded")
	case errors.Is(err, ErrUsernameTaken):
		return httpx.NewError(http.StatusConflict, "this username is already used in the tenant")
	default:
		// The password-length failure is the only plain error the create path
		// returns; anything else is a server fault and stays a 500.
		if strings.Contains(err.Error(), "password shorter than") {
			return httpx.ErrInvalidRequest
		}
		return err
	}
}
