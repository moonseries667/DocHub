package chunk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"godochub/internal/file"
)

const (
	// MinChunkSize stops a client from turning one file into a million rows.
	MinChunkSize = 256 << 10
	// MaxFileSize is the ceiling for the chunked path; the demo file is 100MB.
	MaxFileSize = 8 << 30
	// DefaultPoolSize is the merge concurrency from the task card.
	DefaultPoolSize = 4
	// DefaultChunkSize is only used when a client does not propose one.
	DefaultChunkSize = 4 << 20
)

type Service struct {
	store    *Store
	files    *file.Service
	tempRoot string
	poolSize int
}

func NewService(store *Store, files *file.Service, tempRoot string, poolSize int) (*Service, error) {
	if poolSize <= 0 {
		poolSize = DefaultPoolSize
	}
	abs, err := filepath.Abs(tempRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve chunk temp root %q: %w", tempRoot, err)
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, fmt.Errorf("create chunk temp root %q: %w", abs, err)
	}
	return &Service{store: store, files: files, tempRoot: abs, poolSize: poolSize}, nil
}

// InitResult tells the client either "here is your upload id" or "you already
// have this file, stop".
type InitResult struct {
	Instant   bool       `json:"instant"`
	UploadID  int64      `json:"upload_id,omitempty"`
	ChunkSize int64      `json:"chunk_size,omitempty"`
	ChunkNum  int        `json:"chunk_count,omitempty"`
	File      *file.File `json:"file,omitempty"`
}

// Init opens an upload session, or short-circuits it when the tenant already
// holds an object with this digest.
//
// The SHA256 check runs before any temp directory is created, so an instant hit
// performs no write at all — not even an empty one. The digest is only trusted
// as a lookup key here; a false claim would hand back someone else's bytes, so
// the digest is also what the client is matched by at merge time.
func (s *Service) Init(ctx context.Context, tenantID, ownerID int64, dir, name, contentType string, size int64, sha256Hex string, chunkSize int64) (*InitResult, error) {
	dir, err := file.NormalizeDir(dir)
	if err != nil {
		return nil, err
	}
	name, err = file.NormalizeName(name)
	if err != nil {
		return nil, err
	}
	if size <= 0 || size > MaxFileSize {
		return nil, fmt.Errorf("%w: size %d", ErrTooLarge, size)
	}
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	if chunkSize < MinChunkSize {
		return nil, fmt.Errorf("%w: chunk_size below %d", ErrInvalidChunk, MinChunkSize)
	}
	chunkCount := int((size + chunkSize - 1) / chunkSize)

	// The chunked path consumes the same quota as the direct one. Checking at init
	// rather than at merge means a client learns it is out of room before spending
	// bandwidth on gigabytes of chunks.
	if err := s.files.CheckQuota(ctx, tenantID, size); err != nil {
		return nil, err
	}

	if sha256Hex != "" {
		if len(sha256Hex) != 64 {
			return nil, fmt.Errorf("%w: sha256 must be 64 hex characters", ErrInvalidChunk)
		}
		existing, err := s.files.Reference(ctx, tenantID, ownerID, dir, name, contentType, strings.ToLower(sha256Hex), size)
		if err == nil {
			return &InitResult{Instant: true, File: existing}, nil
		}
		if !errors.Is(err, file.ErrNoDigestMatch) {
			return nil, err
		}
		// No object for this digest: fall through to a normal upload.
	}

	sess := &Session{
		TenantID:    tenantID,
		OwnerID:     ownerID,
		Dir:         dir,
		Name:        name,
		Size:        size,
		ChunkSize:   chunkSize,
		ChunkCount:  chunkCount,
		ContentType: contentType,
	}
	id, err := s.store.Create(ctx, sess)
	if err != nil {
		return nil, err
	}
	sess.ID = id
	return &InitResult{UploadID: id, ChunkSize: chunkSize, ChunkNum: chunkCount}, nil
}

// PutChunk stores one chunk after verifying its checksum.
//
// The bytes are hashed while being written to the temp file; if the digest does
// not match, the temp file is removed and the row is never recorded, so a
// tampered chunk can never be merged later.
func (s *Service) PutChunk(ctx context.Context, tenantID, uploadID int64, idx int, body io.Reader, declaredSize int64, checksum string) error {
	sess, err := s.store.Get(ctx, tenantID, uploadID)
	if err != nil {
		return err
	}
	if idx < 0 || idx >= sess.ChunkCount {
		return fmt.Errorf("%w: index %d out of range [0,%d)", ErrInvalidChunk, idx, sess.ChunkCount)
	}
	want := chunkLength(sess, idx)
	if declaredSize != want {
		return fmt.Errorf("%w: chunk %d should be %d bytes, got %d", ErrInvalidChunk, idx, want, declaredSize)
	}
	if len(checksum) != 64 {
		return fmt.Errorf("%w: checksum must be 64 hex characters", ErrInvalidChunk)
	}

	dir := s.sessionDir(tenantID, uploadID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create chunk dir: %w", err)
	}
	partPath := filepath.Join(dir, partName(idx))

	h := sha256.New()
	f, err := os.OpenFile(partPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open chunk file: %w", err)
	}
	n, copyErr := io.Copy(f, io.TeeReader(io.LimitReader(body, want), h))
	closeErr := f.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(partPath)
		return fmt.Errorf("write chunk %d: %w", idx, firstErr(copyErr, closeErr))
	}
	if n != want {
		_ = os.Remove(partPath)
		return fmt.Errorf("%w: chunk %d has %d of %d bytes", ErrInvalidChunk, idx, n, want)
	}

	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, checksum) {
		_ = os.Remove(partPath)
		return fmt.Errorf("%w: chunk %d digest %s, client said %s", ErrChecksum, idx, got, checksum)
	}

	return s.store.PutChunk(ctx, uploadID, idx, want, strings.ToLower(checksum))
}

// Status reports which chunk indexes are still missing, so a client resumes by
// sending only those.
func (s *Service) Status(ctx context.Context, tenantID, uploadID int64) (*Session, []int, error) {
	sess, err := s.store.Get(ctx, tenantID, uploadID)
	if err != nil {
		return nil, nil, err
	}
	received, err := s.store.Received(ctx, uploadID)
	if err != nil {
		return nil, nil, err
	}
	have := make(map[int]bool, len(received))
	for _, i := range received {
		have[i] = true
	}
	missing := make([]int, 0, sess.ChunkCount-len(received))
	for i := 0; i < sess.ChunkCount; i++ {
		if !have[i] {
			missing = append(missing, i)
		}
	}
	return sess, missing, nil
}

// Abort removes a session and its temp files.
func (s *Service) Abort(ctx context.Context, tenantID, uploadID int64) error {
	if _, err := s.store.Get(ctx, tenantID, uploadID); err != nil {
		return err
	}
	if err := s.store.Delete(ctx, uploadID); err != nil {
		return err
	}
	return os.RemoveAll(s.sessionDir(tenantID, uploadID))
}

// Reclaim removes sessions idle for longer than idleHours.
func (s *Service) Reclaim(ctx context.Context, idleHours int) (int, error) {
	expired, err := s.store.Expired(ctx, idleHours, 100)
	if err != nil {
		return 0, err
	}
	for _, sess := range expired {
		// Directory first: if the row were deleted first and this failed, the
		// session would be gone and no later sweep could find the orphan to
		// retry it. The row is the only handle on the directory.
		if err := os.RemoveAll(s.sessionDir(sess.TenantID, sess.ID)); err != nil {
			return 0, fmt.Errorf("remove temp dir for upload %d: %w", sess.ID, err)
		}
		if err := s.store.Delete(ctx, sess.ID); err != nil {
			return 0, err
		}
	}
	return len(expired), nil
}

// sessionDir keeps each tenant's in-flight bytes under its own directory, so a
// tenant's activity is never visible in another tenant's filesystem layout and
// reclaiming one tenant cannot touch another's chunks.
func (s *Service) sessionDir(tenantID, uploadID int64) string {
	return filepath.Join(s.tempRoot, fmt.Sprintf("%d", tenantID), fmt.Sprintf("%d", uploadID))
}

func partName(idx int) string {
	return fmt.Sprintf("part-%06d", idx)
}

// chunkLength is the size of chunk idx: full chunks everywhere but the last.
func chunkLength(sess *Session, idx int) int64 {
	if idx == sess.ChunkCount-1 {
		if rem := sess.Size - int64(idx)*sess.ChunkSize; rem > 0 {
			return rem
		}
	}
	return sess.ChunkSize
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
