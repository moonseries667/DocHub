package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Local keeps objects as files under one root directory.
//
// It exists for development and for the test suite: `make run` on a machine with
// no bucket, and a contract test that runs without credentials. It is not a
// deployment target — a single local directory has no redundancy, no lifecycle
// rules and no way to survive the host, which is what the S3 provider is for.
// config refuses to select it unless the operator opts in explicitly.
type Local struct {
	root string
}

var ErrInvalidKey = errors.New("storage: invalid key")

// NewLocal opens (and creates) the directory objects live in.
func NewLocal(root string) (*Local, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve storage root %q: %w", root, err)
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, fmt.Errorf("create storage root %q: %w", abs, err)
	}
	return &Local{root: abs}, nil
}

// path turns a caller key into an absolute path inside root.
//
// Containment is guaranteed by cleaning a rooted path, which collapses ".."
// segments. That alone would silently map "../a" and "a" to the same object, so
// ".." is refused outright: keys are generated internally and never need it.
func (l *Local) path(key string) (string, error) {
	if key == "" {
		return "", ErrInvalidKey
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == ".." {
			return "", fmt.Errorf("%w: %q", ErrInvalidKey, key)
		}
	}
	clean := filepath.Clean("/" + key)
	full := filepath.Join(l.root, clean)
	rel, err := filepath.Rel(l.root, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("%w: %q", ErrInvalidKey, key)
	}
	return full, nil
}

func (l *Local) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	full, err := l.path(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return fmt.Errorf("create dir for %q: %w", key, err)
	}

	f, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create %q: %w", key, err)
	}

	// A short read means the caller's size lied, and a half-written object must
	// never stay behind: it would be indistinguishable from a good one later.
	written, copyErr := io.Copy(f, io.LimitReader(r, size))
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(full)
		return fmt.Errorf("write %q: %w", key, copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(full)
		return fmt.Errorf("close %q: %w", key, closeErr)
	}
	if written != size {
		_ = os.Remove(full)
		return fmt.Errorf("write %q: wrote %d bytes, expected %d", key, written, size)
	}
	return nil
}

func (l *Local) Get(ctx context.Context, key string) (io.ReadSeekCloser, error) {
	full, err := l.path(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(full)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %q", ErrNotFound, key)
	}
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", key, err)
	}
	return f, nil
}

func (l *Local) Delete(ctx context.Context, key string) error {
	full, err := l.path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(full); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: %q", ErrNotFound, key)
		}
		return fmt.Errorf("remove %q: %w", key, err)
	}
	return nil
}

func (l *Local) Stat(ctx context.Context, key string) (Info, error) {
	full, err := l.path(key)
	if err != nil {
		return Info{}, err
	}
	st, err := os.Stat(full)
	if errors.Is(err, os.ErrNotExist) {
		return Info{}, fmt.Errorf("%w: %q", ErrNotFound, key)
	}
	if err != nil {
		return Info{}, fmt.Errorf("stat %q: %w", key, err)
	}
	return Info{Size: st.Size(), ModTime: st.ModTime()}, nil
}
