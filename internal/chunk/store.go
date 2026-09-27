// Package chunk implements chunked, resumable uploads and the SHA256 shortcut
// that skips transfer entirely when the tenant already holds the bytes.
//
// The flow is deliberately three calls plus the merge: init → put chunks (in any
// order) → complete. State lives in MySQL, not in memory, so a client that
// disconnects can ask "what is still missing" and continue from another process.
package chunk

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"
)

var (
	ErrNotFound     = errors.New("chunk: upload not found")
	ErrInvalidChunk = errors.New("chunk: invalid chunk")
	ErrChecksum     = errors.New("chunk: checksum mismatch")
	ErrIncomplete   = errors.New("chunk: not all chunks uploaded")
	ErrTooLarge     = errors.New("chunk: file too large")
)

// Session is one resumable upload. ChunkSize is stored so a resume after a
// restart uses the same slicing the first attempt used.
type Session struct {
	ID          int64  `db:"id" json:"upload_id"`
	TenantID    int64  `db:"tenant_id" json:"-"`
	OwnerID     int64  `db:"owner_id" json:"owner_id"`
	Dir         string `db:"dir" json:"dir"`
	Name        string `db:"name" json:"name"`
	Size        int64  `db:"size" json:"size"`
	ChunkSize   int64  `db:"chunk_size" json:"chunk_size"`
	ChunkCount  int    `db:"chunk_count" json:"chunk_count"`
	ContentType string `db:"content_type" json:"content_type"`
}

type Store struct {
	db *sqlx.DB
}

func NewStore(db *sqlx.DB) *Store {
	return &Store{db: db}
}

func (s *Store) Create(ctx context.Context, sess *Session) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO upload_session (tenant_id, owner_id, dir, name, size, chunk_size, chunk_count, content_type)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.TenantID, sess.OwnerID, sess.Dir, sess.Name, sess.Size,
		sess.ChunkSize, sess.ChunkCount, sess.ContentType)
	if err != nil {
		return 0, fmt.Errorf("create upload session: %w", err)
	}
	return res.LastInsertId()
}

// Get loads a session, scoped by tenant: another tenant's id must look absent.
func (s *Store) Get(ctx context.Context, tenantID, id int64) (*Session, error) {
	var sess Session
	err := s.db.GetContext(ctx, &sess, `
		SELECT id, tenant_id, owner_id, dir, name, size, chunk_size, chunk_count, content_type
		FROM upload_session
		WHERE id = ? AND tenant_id = ?`, id, tenantID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query upload session %d: %w", id, err)
	}
	return &sess, nil
}

// PutChunk records one chunk. Re-uploading the same index overwrites it, which
// is what makes a retry after a dropped connection safe.
func (s *Store) PutChunk(ctx context.Context, uploadID int64, idx int, size int64, sha256 string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO upload_chunk (upload_id, idx, size, sha256)
		VALUES (?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE size = VALUES(size), sha256 = VALUES(sha256), created_at = CURRENT_TIMESTAMP`,
		uploadID, idx, size, sha256)
	if err != nil {
		return fmt.Errorf("record chunk %d: %w", idx, err)
	}
	// Bump the lease so the cleanup job measures idle time, not total time.
	if _, err := s.db.ExecContext(ctx,
		"UPDATE upload_session SET updated_at = CURRENT_TIMESTAMP WHERE id = ?", uploadID); err != nil {
		return fmt.Errorf("touch upload session %d: %w", uploadID, err)
	}
	return nil
}

// Received returns the indexes already stored, sorted ascending.
func (s *Store) Received(ctx context.Context, uploadID int64) ([]int, error) {
	got := []int{}
	if err := s.db.SelectContext(ctx, &got,
		"SELECT idx FROM upload_chunk WHERE upload_id = ? ORDER BY idx", uploadID); err != nil {
		return nil, fmt.Errorf("list received chunks: %w", err)
	}
	return got, nil
}

// ChunkDigest returns the recorded checksum of one chunk, used by the merge to
// re-verify before assembling.
func (s *Store) ChunkDigest(ctx context.Context, uploadID int64, idx int) (string, error) {
	var sum string
	err := s.db.GetContext(ctx, &sum,
		"SELECT sha256 FROM upload_chunk WHERE upload_id = ? AND idx = ?", uploadID, idx)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("%w: chunk %d", ErrNotFound, idx)
	}
	if err != nil {
		return "", fmt.Errorf("query chunk %d digest: %w", idx, err)
	}
	return sum, nil
}

// Delete drops a session and, by cascade, its chunk rows. The temp directory is
// the caller's to remove.
func (s *Store) Delete(ctx context.Context, uploadID int64) error {
	if _, err := s.db.ExecContext(ctx, "DELETE FROM upload_session WHERE id = ?", uploadID); err != nil {
		return fmt.Errorf("delete upload session %d: %w", uploadID, err)
	}
	return nil
}

// Expired lists sessions idle for longer than idleHours, so the cleanup job can
// reclaim their temp directories.
func (s *Store) Expired(ctx context.Context, idleHours int, limit int) ([]Session, error) {
	var out []Session
	err := s.db.SelectContext(ctx, &out, `
		SELECT id, tenant_id, owner_id, dir, name, size, chunk_size, chunk_count, content_type
		FROM upload_session
		WHERE updated_at < (NOW() - INTERVAL ? HOUR)
		ORDER BY updated_at
		LIMIT ?`, idleHours, limit)
	if err != nil {
		return nil, fmt.Errorf("list expired upload sessions: %w", err)
	}
	return out, nil
}
