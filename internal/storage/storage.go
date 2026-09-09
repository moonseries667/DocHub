// Package storage abstracts where file bytes physically live.
//
// The interface is deliberately four methods. Everything the project needs —
// write, read, remove, and ask how big a stored object is — fits here; a MinIO
// implementation can satisfy it without either side knowing about the other.
package storage

import (
	"context"
	"errors"
	"io"
	"time"
)

// ErrNotFound is returned by Get, Stat and Delete when the key does not exist.
var ErrNotFound = errors.New("storage: object not found")

// Info is the part of an object's metadata the API needs. Size is what lets
// download set Content-Length without buffering the whole object.
type Info struct {
	Size    int64
	ModTime time.Time
}

// Provider stores opaque byte blobs under caller-chosen keys.
//
// Keys are slash-separated and relative; the provider decides whether they map
// to directories or object paths. Callers must not assume a key survives as a
// filesystem path.
type Provider interface {
	// Put writes exactly size bytes from r under key.
	Put(ctx context.Context, key string, r io.Reader, size int64) error
	// Get opens key for reading. The caller closes the reader.
	//
	// The reader can seek because download has to serve byte ranges: a client
	// that resumes an interrupted transfer asks for "bytes=N-", and answering
	// 200 with the whole object instead of 206 with the tail is the difference
	// between a download that resumes and one that starts over. Both backends
	// already give us this for free — *os.File and the S3 object reader — so
	// the interface asks for it rather than buffering a hidden copy.
	Get(ctx context.Context, key string) (io.ReadSeekCloser, error)
	// Delete removes key. Removing a missing key returns ErrNotFound.
	Delete(ctx context.Context, key string) error
	// Stat reports key's size and mtime.
	Stat(ctx context.Context, key string) (Info, error)
}
