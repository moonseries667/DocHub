package chunk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"godochub/internal/file"
)

// Merge verifies every chunk again and assembles the file through a goroutine
// pool, writing the result through the storage provider.
//
// Re-verification is not redundant with PutChunk: the temp files live on disk and
// could be replaced between the two calls, and the merge is the last moment a
// corrupted byte could still be caught.
func (s *Service) Merge(ctx context.Context, tenantID, uploadID int64) (*file.File, error) {
	sess, missing, err := s.Status(ctx, tenantID, uploadID)
	if err != nil {
		return nil, err
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%w: %d chunks missing", ErrIncomplete, len(missing))
	}

	tmpOut, err := os.CreateTemp(s.sessionDir(tenantID, uploadID), "merged-*")
	if err != nil {
		return nil, fmt.Errorf("create merged file: %w", err)
	}
	mergedPath := tmpOut.Name()
	defer os.Remove(mergedPath)

	// Preallocate so the ordered writer below can seek freely.
	if err := tmpOut.Truncate(sess.Size); err != nil {
		_ = tmpOut.Close()
		return nil, fmt.Errorf("preallocate merged file: %w", err)
	}
	if err := tmpOut.Close(); err != nil {
		return nil, fmt.Errorf("close merged file: %w", err)
	}

	if err := s.verifyAndAssemble(ctx, sess, mergedPath); err != nil {
		return nil, err
	}

	// Adopt hashes the bytes while copying them into storage, so the assembled
	// file is never read a second time just to learn its digest.
	f, err := s.files.Adopt(ctx, tenantID, sess.OwnerID, sess.Dir, sess.Name, sess.ContentType, mergedPath, sess.Size)
	if err != nil {
		return nil, err
	}

	if err := s.store.Delete(ctx, uploadID); err != nil {
		return nil, err
	}
	_ = os.RemoveAll(s.sessionDir(tenantID, uploadID))
	return f, nil
}

// verifyAndAssemble runs the pool: each worker verifies one chunk against its
// recorded digest and writes it straight into its offset, so the file is
// assembled in the same pass that proves it correct.
//
// Workers write with WriteAt, which is a positional write and safe to run
// concurrently on one file handle: no worker can disturb another's range, and no
// mutex is held across IO.
func (s *Service) verifyAndAssemble(ctx context.Context, sess *Session, mergedPath string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	out, err := os.OpenFile(mergedPath, os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open merged file for writing: %w", err)
	}
	defer out.Close()

	idxCh := make(chan int)
	errCh := make(chan error, 1)

	var wg sync.WaitGroup
	for i := 0; i < s.poolSize; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range idxCh {
				if err := s.verifyAndWriteChunk(ctx, out, sess, idx); err != nil {
					select {
					case errCh <- err:
					default:
					}
					cancel()
					return
				}
			}
		}()
	}

	go func() {
		defer close(idxCh)
		for idx := 0; idx < sess.ChunkCount; idx++ {
			select {
			case idxCh <- idx:
			case <-ctx.Done():
				return
			}
		}
	}()

	wg.Wait()
	select {
	case err := <-errCh:
		return err
	default:
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("merge cancelled: %w", err)
	}
	return out.Sync()
}

// verifyAndWriteChunk reads one chunk once, checks its digest against the row
// recorded at upload time, and writes it at its offset.
//
// Verifying and writing in one pass matters at 100MB: a separate verify pass and
// copy pass would read every chunk twice for no additional safety.
func (s *Service) verifyAndWriteChunk(ctx context.Context, out *os.File, sess *Session, idx int) error {
	path := filepath.Join(s.sessionDir(sess.TenantID, sess.ID), partName(idx))
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open chunk %d: %w", idx, err)
	}
	defer f.Close()

	want, err := s.store.ChunkDigest(ctx, sess.ID, idx)
	if err != nil {
		return err
	}

	// Hash while buffering into memory would defeat the point for large chunks,
	// so the chunk is streamed once: through the hasher and into the file at its
	// own offset. WriteAt is a positional write, so several workers can write to
	// the same handle without sharing a file cursor.
	h := sha256.New()
	offset := int64(idx) * sess.ChunkSize
	buf := make([]byte, 256<<10)
	var written int64
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			if _, wErr := out.WriteAt(buf[:n], offset+written); wErr != nil {
				return fmt.Errorf("write chunk %d at %d: %w", idx, offset+written, wErr)
			}
			_, _ = h.Write(buf[:n])
			written += int64(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read chunk %d: %w", idx, readErr)
		}
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("%w: chunk %d on disk no longer matches its digest", ErrChecksum, idx)
	}
	return nil
}
