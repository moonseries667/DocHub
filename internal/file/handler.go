package file

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"godochub/internal/httpx"
	"godochub/internal/tenant"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// Upload takes a small file as multipart form data. The tenant comes from the
// token, never from the request body: accepting it from the client would make
// the isolation unenforceable.
func (h *Handler) Upload(c *gin.Context) {
	ident, ok := tenant.FromContext(c.Request.Context())
	if !ok {
		_ = c.Error(httpx.ErrUnauthorized)
		return
	}

	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MaxSmallFileSize+1<<20)
	fileHeader, err := c.FormFile("file")
	if err != nil {
		// MaxBytesReader reports through FormFile, so an oversized body arrives
		// here rather than at the explicit size check below. Both paths must
		// answer 413, or clients see 413 or 400 depending on how big they went.
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			_ = c.Error(httpx.NewError(http.StatusRequestEntityTooLarge,
				"file exceeds the 8MB direct upload limit"))
			return
		}
		_ = c.Error(httpx.ErrInvalidRequest)
		return
	}
	if fileHeader.Size > MaxSmallFileSize {
		_ = c.Error(httpx.NewError(http.StatusRequestEntityTooLarge,
			"file exceeds the 8MB direct upload limit"))
		return
	}

	// Read the form fields before opening the file part. c.PostForm triggers the
	// multipart parse and may consume and rewind the request body; relying on a
	// part reader across that is a lifecycle dependency worth not having even
	// though it happens to work with net/http's temp-file buffering.
	dir := c.PostForm("dir")

	src, err := fileHeader.Open()
	if err != nil {
		_ = c.Error(err)
		return
	}
	defer src.Close()

	f, err := h.service.Upload(c.Request.Context(), ident.TenantID, ident.UserID,
		dir, fileHeader.Filename, fileHeader.Header.Get("Content-Type"),
		src, fileHeader.Size)
	if err != nil {
		_ = c.Error(mapError(err))
		return
	}
	httpx.OK(c, f)
}

// Download streams the bytes back with the recorded content type.
//
// It hands the reader to http.ServeContent rather than writing the body itself.
// ServeContent is what implements Range, If-Range and HEAD for us: a plain
// write answers "here is the whole file" to a client that asked for bytes=N-,
// which silently turns every resumed download into a full one. Sending
// Content-Disposition as an extra header keeps the attachment behaviour.
func (h *Handler) Download(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	ident, ok := tenant.FromContext(c.Request.Context())
	if !ok {
		_ = c.Error(httpx.ErrUnauthorized)
		return
	}

	f, rc, err := h.service.Open(c.Request.Context(), ident.TenantID, id)
	if err != nil {
		_ = c.Error(mapError(err))
		return
	}
	defer rc.Close()

	c.Header("Content-Disposition", "attachment; filename=\""+f.Name+"\"")
	// The last argument is the modification time ServeContent uses to answer
	// If-Modified-Since. The row does not record one, so the zero time tells it
	// not to advertise a validator it cannot honour.
	http.ServeContent(c.Writer, c.Request, f.Name, time.Time{}, rc)
}

// List returns the files directly under one directory of the caller's tenant.
// data.dir echoes the normalized directory, which is the one actually queried.
//
// Results are paged: a directory that has grown for a year must not be shipped
// in one response. limit is capped rather than trusted, and next_offset is
// present only when there is another page, so "absent" means "you have it all".
func (h *Handler) List(c *gin.Context) {
	ident, ok := tenant.FromContext(c.Request.Context())
	if !ok {
		_ = c.Error(httpx.ErrUnauthorized)
		return
	}

	dir, err := NormalizeDir(c.Query("dir"))
	if err != nil {
		_ = c.Error(mapError(err))
		return
	}
	limit, offset, err := pageParams(c)
	if err != nil {
		_ = c.Error(httpx.ErrInvalidRequest)
		return
	}

	// Ask for one extra row: its presence is what says "there is a next page"
	// without a second COUNT query over the same directory.
	files, err := h.service.List(c.Request.Context(), ident.TenantID, dir, limit+1, offset)
	if err != nil {
		_ = c.Error(mapError(err))
		return
	}
	next := 0
	if len(files) > limit {
		files = files[:limit]
		next = offset + limit
	}
	if files == nil {
		files = []File{} // an empty directory is [], never null
	}
	body := gin.H{"dir": dir, "files": files, "limit": limit}
	if next > 0 {
		body["next_offset"] = next
	}
	httpx.OK(c, body)
}

// pageParams reads limit/offset, applying a default and a ceiling. A client that
// asks for 100000 rows gets the ceiling, not an error and not 100000 rows.
func pageParams(c *gin.Context) (limit, offset int, err error) {
	limit = defaultPageSize
	if raw := c.Query("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil || limit <= 0 {
			return 0, 0, errors.New("invalid limit")
		}
		if limit > maxPageSize {
			limit = maxPageSize
		}
	}
	if raw := c.Query("offset"); raw != "" {
		offset, err = strconv.Atoi(raw)
		if err != nil || offset < 0 {
			return 0, 0, errors.New("invalid offset")
		}
	}
	return limit, offset, nil
}

// Delete removes one file of the caller's tenant.
func (h *Handler) Delete(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	ident, ok := tenant.FromContext(c.Request.Context())
	if !ok {
		_ = c.Error(httpx.ErrUnauthorized)
		return
	}

	if err := h.service.Delete(c.Request.Context(), ident.TenantID, id); err != nil {
		_ = c.Error(mapError(err))
		return
	}
	httpx.OK(c, gin.H{"deleted": id})
}

func parseID(c *gin.Context) (int64, bool) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		_ = c.Error(httpx.ErrInvalidRequest)
		return 0, false
	}
	return id, true
}

// mapError keeps storage and SQL details out of the response while still
// answering with the right status.
func mapError(err error) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return httpx.ErrNotFound
	case errors.Is(err, ErrNameTaken):
		return httpx.NewError(http.StatusConflict, "a file with this name already exists in this directory")
	case errors.Is(err, ErrInvalidPath):
		return httpx.ErrInvalidRequest
	case errors.Is(err, ErrTooLarge):
		return httpx.NewError(http.StatusRequestEntityTooLarge, "file too large")
	case errors.Is(err, tenant.ErrQuotaExceeded):
		return httpx.NewError(http.StatusRequestEntityTooLarge, "tenant storage quota exceeded")
	default:
		return err
	}
}
