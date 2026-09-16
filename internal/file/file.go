// Package file owns file metadata and the upload/download path.
//
// Every exported entry point takes the caller's tenant id first: a query without
// it is a cross-tenant leak, so the signature forces the caller to have one.
package file

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/jmoiron/sqlx"
)

var (
	ErrNotFound    = errors.New("file: not found")
	ErrNameTaken   = errors.New("file: name already used in this directory")
	ErrInvalidPath = errors.New("file: invalid directory or name")
	ErrTooLarge    = errors.New("file: too large for direct upload")
	// ErrNoDigestMatch means the tenant holds no object with this digest, which
	// is the normal "not an instant hit" answer rather than a failure.
	ErrNoDigestMatch = errors.New("file: no stored object with this digest")
)

const (
	MaxSmallFileSize = 8 << 20 // 8 MiB: above this the request goes to the chunk API

	// The storage column records which backend holds a row's bytes. Two values:
	// "s3" for the bucket (every deployment), "local" for the development
	// directory. Rows written by an older build that said "minio" are the only
	// reason this column is worth reading at all.
	StorageS3    = "s3"
	StorageLocal = "local"

	// Listing is paged: defaultPageSize matches what a person scrolls through
	// before filtering, and maxPageSize bounds one response so a caller cannot
	// ask the server to serialise an entire directory.
	defaultPageSize = 100
	maxPageSize     = 500
)

type File struct {
	ID          int64  `db:"id" json:"id"`
	TenantID    int64  `db:"tenant_id" json:"-"`
	OwnerID     int64  `db:"owner_id" json:"owner_id"`
	Dir         string `db:"dir" json:"dir"`
	Name        string `db:"name" json:"name"`
	Size        int64  `db:"size" json:"size"`
	SHA256      string `db:"sha256" json:"sha256"`
	ContentType string `db:"content_type" json:"content_type"`
	Storage     string `db:"storage" json:"storage"`
	StorageKey  string `db:"storage_key" json:"-"`
}

type Store struct {
	db *sqlx.DB
}

func NewStore(db *sqlx.DB) *Store {
	return &Store{db: db}
}

// Insert records metadata. The unique key on (tenant, dir, name) is the only
// arbiter of a name clash: checking first would race under concurrent uploads.
func (s *Store) Insert(ctx context.Context, f *File) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO file (tenant_id, owner_id, dir, name, size, sha256, content_type, storage, storage_key)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.TenantID, f.OwnerID, f.Dir, f.Name, f.Size, f.SHA256, f.ContentType, f.Storage, f.StorageKey)
	if err != nil {
		// 1062 is MySQL's duplicate-entry code; checking it here keeps the
		// driver's error type out of the service layer.
		if strings.Contains(err.Error(), "Error 1062") {
			return 0, fmt.Errorf("%w: %s/%s", ErrNameTaken, f.Dir, f.Name)
		}
		return 0, fmt.Errorf("insert file: %w", err)
	}
	return res.LastInsertId()
}

// GetByID scopes on tenant: an id from another tenant must look nonexistent.
func (s *Store) GetByID(ctx context.Context, tenantID, id int64) (*File, error) {
	var f File
	err := s.db.GetContext(ctx, &f, `
		SELECT id, tenant_id, owner_id, dir, name, size, sha256, content_type, storage, storage_key
		FROM file
		WHERE id = ? AND tenant_id = ?`, id, tenantID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query file %d: %w", id, err)
	}
	return &f, nil
}

// ListByDir returns one page of the files directly under dir.
//
// The order is (name, id) rather than name alone: LIMIT/OFFSET is only correct
// over a total order, and a tie-break on the primary key guarantees one row
// never shows up on two pages or falls between them.
func (s *Store) ListByDir(ctx context.Context, tenantID int64, dir string, limit, offset int) ([]File, error) {
	var files []File
	err := s.db.SelectContext(ctx, &files, `
		SELECT id, tenant_id, owner_id, dir, name, size, sha256, content_type, storage, storage_key
		FROM file
		WHERE tenant_id = ? AND dir = ?
		ORDER BY name, id
		LIMIT ? OFFSET ?`, tenantID, dir, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list files in %q: %w", dir, err)
	}
	return files, nil
}

// Delete removes the metadata row and reports what was deleted so the caller can
// drop the bytes too.
func (s *Store) Delete(ctx context.Context, tenantID, id int64) (*File, error) {
	f, err := s.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM file WHERE id = ? AND tenant_id = ?", id, tenantID); err != nil {
		return nil, fmt.Errorf("delete file %d: %w", id, err)
	}
	return f, nil
}

// FindByDigest returns one row whose object has this digest, or ErrNoDigestMatch.
// It is the instant-upload lookup, so it is scoped by tenant: matching across
// tenants would hand one tenant's bytes to another.
func (s *Store) FindByDigest(ctx context.Context, tenantID int64, sha256Hex string) (*File, error) {
	var f File
	err := s.db.GetContext(ctx, &f, `
		SELECT id, tenant_id, owner_id, dir, name, size, sha256, content_type, storage, storage_key
		FROM file
		WHERE tenant_id = ? AND sha256 = ?
		ORDER BY id
		LIMIT 1`, tenantID, sha256Hex)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoDigestMatch
	}
	if err != nil {
		return nil, fmt.Errorf("query file by digest: %w", err)
	}
	return &f, nil
}

// FindByPath returns the row at (tenant, dir, name), or ErrNotFound.
func (s *Store) FindByPath(ctx context.Context, tenantID int64, dir, name string) (*File, error) {
	var f File
	err := s.db.GetContext(ctx, &f, `
		SELECT id, tenant_id, owner_id, dir, name, size, sha256, content_type, storage, storage_key
		FROM file
		WHERE tenant_id = ? AND dir = ? AND name = ?`, tenantID, dir, name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query file at %s/%s: %w", dir, name, err)
	}
	return &f, nil
}

// CountByStorageKey counts the rows of this tenant still pointing at one object.
// Callers use it to decide whether removing the bytes is safe.
func (s *Store) CountByStorageKey(ctx context.Context, tenantID int64, storageKey string) (int, error) {
	var n int
	err := s.db.GetContext(ctx, &n,
		"SELECT COUNT(*) FROM file WHERE tenant_id = ? AND storage_key = ?", tenantID, storageKey)
	if err != nil {
		return 0, fmt.Errorf("count rows for %q: %w", storageKey, err)
	}
	return n, nil
}

// SetDigest fills in the digest once the bytes have been written. A row is
// inserted before its object exists (so a duplicate name fails early), and this
// is the closing half of that pair.
func (s *Store) SetDigest(ctx context.Context, tenantID, id int64, sha256Hex string) error {
	if _, err := s.db.ExecContext(ctx,
		"UPDATE file SET sha256 = ? WHERE id = ? AND tenant_id = ?", sha256Hex, id, tenantID); err != nil {
		return fmt.Errorf("update digest of file %d: %w", id, err)
	}
	return nil
}

// NormalizeDir accepts "/", "/a/b" and "a/b" and returns "/a/b".
//
// It rejects ".." outright (normalising it away would silently move a file
// somewhere the user did not ask for) and, like NormalizeName, rejects "\" and
// NUL. A backslash matters on the local backend: filepath.Clean treats it as a
// separator on Windows, so "/a\b" and "/a/b" would collapse onto one object while
// remaining two distinct rows in the database.
func NormalizeDir(dir string) (string, error) {
	if dir == "" {
		return "/", nil
	}
	if strings.ContainsAny(dir, "\\\x00") {
		return "", fmt.Errorf("%w: %q", ErrInvalidPath, dir)
	}
	if strings.Contains(dir, "..") {
		return "", fmt.Errorf("%w: %q", ErrInvalidPath, dir)
	}
	clean := path.Clean("/" + dir)
	if clean == "/." {
		return "/", nil
	}
	if strings.HasPrefix(clean, "/../") || clean == "/.." {
		return "", fmt.Errorf("%w: %q", ErrInvalidPath, dir)
	}
	if len(clean) > maxDirLen {
		return "", fmt.Errorf("%w: directory too long", ErrInvalidPath)
	}
	return clean, nil
}

// maxDirLen and maxNameLen match the column widths in migrations/0002_file.sql.
// maxStorageKeyLen matches storage_key VARCHAR(512).
const (
	maxDirLen        = 255
	maxNameLen       = 255
	maxStorageKeyLen = 512
)

// NormalizeName validates a single file name. Path separators are rejected: the
// directory comes from its own parameter, so a name must not smuggle one in.
func NormalizeName(name string) (string, error) {
	name = strings.TrimSpace(name)
	switch {
	case name == "", name == ".", name == "..":
		return "", fmt.Errorf("%w: empty name", ErrInvalidPath)
	case strings.ContainsAny(name, "/\\\x00"):
		return "", fmt.Errorf("%w: %q", ErrInvalidPath, name)
	case len(name) > maxNameLen:
		return "", fmt.Errorf("%w: name too long", ErrInvalidPath)
	}
	return name, nil
}
