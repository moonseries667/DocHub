package chunk

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"godochub/internal/file"
	"godochub/internal/httpx"
	"godochub/internal/tenant"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

type initRequest struct {
	Dir         string `json:"dir"`
	Name        string `json:"name" binding:"required"`
	Size        int64  `json:"size" binding:"required"`
	ChunkSize   int64  `json:"chunk_size"`
	SHA256      string `json:"sha256"`
	ContentType string `json:"content_type"`
}

// Init opens an upload session or answers with the file an instant-upload hit
// found.
//
// ShouldBindBodyWithJSON rather than ShouldBindJSON: the ACL guard on this route
// has already read the body to learn the target directory, and the plain binder
// would see a drained reader. The body-aware variant reuses the copy the guard
// cached, so the directory check and this handler see the same bytes.
func (h *Handler) Init(c *gin.Context) {
	ident, ok := tenant.FromContext(c.Request.Context())
	if !ok {
		_ = c.Error(httpx.ErrUnauthorized)
		return
	}
	var req initRequest
	if err := c.ShouldBindBodyWithJSON(&req); err != nil {
		_ = c.Error(httpx.ErrInvalidRequest)
		return
	}

	result, err := h.service.Init(c.Request.Context(), ident.TenantID, ident.UserID,
		req.Dir, req.Name, req.ContentType, req.Size, req.SHA256, req.ChunkSize)
	if err != nil {
		_ = c.Error(mapError(err))
		return
	}
	httpx.OK(c, result)
}

// Put stores one chunk. The body is the raw bytes; the digest travels in a
// header so the payload stays a plain stream.
func (h *Handler) Put(c *gin.Context) {
	ident, ok := tenant.FromContext(c.Request.Context())
	if !ok {
		_ = c.Error(httpx.ErrUnauthorized)
		return
	}
	uploadID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || uploadID <= 0 {
		_ = c.Error(httpx.ErrInvalidRequest)
		return
	}
	idx, err := strconv.Atoi(c.Param("idx"))
	if err != nil || idx < 0 {
		_ = c.Error(httpx.ErrInvalidRequest)
		return
	}
	// ContentLength is authoritative here: the service compares it against the
	// expected chunk length, so a wrong header fails fast instead of being filled
	// in from however much the client happened to send.
	size := c.Request.ContentLength
	if size < 0 {
		_ = c.Error(httpx.ErrInvalidRequest)
		return
	}

	if err := h.service.PutChunk(c.Request.Context(), ident.TenantID, uploadID, idx,
		c.Request.Body, size, c.GetHeader("X-Chunk-SHA256")); err != nil {
		_ = c.Error(mapError(err))
		return
	}
	httpx.OK(c, gin.H{"upload_id": uploadID, "index": idx, "size": size})
}

// Status lists what is still missing so the client can resume.
func (h *Handler) Status(c *gin.Context) {
	ident, ok := tenant.FromContext(c.Request.Context())
	if !ok {
		_ = c.Error(httpx.ErrUnauthorized)
		return
	}
	uploadID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || uploadID <= 0 {
		_ = c.Error(httpx.ErrInvalidRequest)
		return
	}

	sess, missing, err := h.service.Status(c.Request.Context(), ident.TenantID, uploadID)
	if err != nil {
		_ = c.Error(mapError(err))
		return
	}
	httpx.OK(c, gin.H{
		"upload_id":   sess.ID,
		"name":        sess.Name,
		"size":        sess.Size,
		"chunk_size":  sess.ChunkSize,
		"chunk_count": sess.ChunkCount,
		"missing":     missing,
		"done":        len(missing) == 0,
	})
}

// Complete merges the chunks into the final object.
func (h *Handler) Complete(c *gin.Context) {
	ident, ok := tenant.FromContext(c.Request.Context())
	if !ok {
		_ = c.Error(httpx.ErrUnauthorized)
		return
	}
	uploadID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || uploadID <= 0 {
		_ = c.Error(httpx.ErrInvalidRequest)
		return
	}

	f, err := h.service.Merge(c.Request.Context(), ident.TenantID, uploadID)
	if err != nil {
		_ = c.Error(mapError(err))
		return
	}
	httpx.OK(c, f)
}

// Abort drops an upload and its temp files.
func (h *Handler) Abort(c *gin.Context) {
	ident, ok := tenant.FromContext(c.Request.Context())
	if !ok {
		_ = c.Error(httpx.ErrUnauthorized)
		return
	}
	uploadID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || uploadID <= 0 {
		_ = c.Error(httpx.ErrInvalidRequest)
		return
	}
	if err := h.service.Abort(c.Request.Context(), ident.TenantID, uploadID); err != nil {
		_ = c.Error(mapError(err))
		return
	}
	httpx.OK(c, gin.H{"aborted": uploadID})
}

func mapError(err error) error {
	switch {
	case errors.Is(err, ErrNotFound), errors.Is(err, file.ErrNotFound):
		return httpx.ErrNotFound
	case errors.Is(err, ErrChecksum):
		return httpx.NewError(http.StatusBadRequest, "chunk checksum mismatch")
	case errors.Is(err, ErrIncomplete):
		return httpx.NewError(http.StatusConflict, "not all chunks have been uploaded")
	case errors.Is(err, file.ErrNameTaken):
		return httpx.NewError(http.StatusConflict, "a file with this name already exists in this directory")
	case errors.Is(err, ErrInvalidChunk), errors.Is(err, file.ErrInvalidPath):
		return httpx.ErrInvalidRequest
	case errors.Is(err, ErrTooLarge), errors.Is(err, file.ErrTooLarge):
		return httpx.NewError(http.StatusRequestEntityTooLarge, "file too large")
	case errors.Is(err, tenant.ErrQuotaExceeded):
		return httpx.NewError(http.StatusRequestEntityTooLarge, "tenant storage quota exceeded")
	default:
		return err
	}
}
