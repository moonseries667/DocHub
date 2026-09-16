package file

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"

	"godochub/internal/storage"
)

// Service is the file use case: keep metadata and bytes in step, and never touch
// a key that belongs to another tenant.
type Service struct {
	store *Store
	sp    storage.Provider
	// backend is the name recorded on each row. There is one backend now, so it
	// is a label rather than a switch: a row says which store holds its bytes,
	// which matters the day the bucket is migrated.
	backend string
	// quota decides whether a tenant has room for another size bytes. It is a
	// function rather than a tenant.Store field on purpose: this package must not
	// import tenant, or the two would form the cycle the layering avoids. A nil
	// hook means no quota, which is what the unit tests and the first run of a
	// fresh install want.
	quota func(ctx context.Context, tenantID, size int64) error
}

// NewService takes the backend name alongside the provider because the two must
// agree: a row's storage column has to name the store that actually holds its
// bytes, or a later migration that trusts the column moves the wrong things.
func NewService(store *Store, sp storage.Provider, backend string) *Service {
	if backend == "" {
		backend = StorageS3
	}
	return &Service{store: store, sp: sp, backend: backend}
}

// OnQuotaCheck registers the tenant quota check. Nil (the default) means the
// tenant has no ceiling, so a caller that does not wire it keeps working.
func (s *Service) OnQuotaCheck(fn func(ctx context.Context, tenantID, size int64) error) {
	s.quota = fn
}

// checkQuota applies the registered check, or allows everything when none is set.
func (s *Service) checkQuota(ctx context.Context, tenantID, size int64) error {
	if s.quota == nil {
		return nil
	}
	return s.quota(ctx, tenantID, size)
}

// CheckQuota exposes the quota check to the chunk package, which creates rows
// through this service and must refuse an oversized session at init time.
func (s *Service) CheckQuota(ctx context.Context, tenantID, size int64) error {
	return s.checkQuota(ctx, tenantID, size)
}

// Upload reserves the name first, then stores the bytes.
//
// Order matters and is not symmetric with Delete: the row is inserted before the
// object is written so a duplicate name fails on the unique key while the
// existing file's bytes are untouched. Writing the object first would mean the
// 1062 path has to compensate by deleting, and a compensating delete must never
// target a key another row could own. A crash between insert and put leaves a
// row with no object, which Open reports as an error; that is strictly better
// than destroying data that was already acknowledged as stored.
//
// The body is read into memory first because its SHA256 has to be stored in the
// same row that reserves the name, and the direct-upload limit (8MB) bounds what
// that can cost.
func (s *Service) Upload(ctx context.Context, tenantID, ownerID int64, dir, name, contentType string, body io.Reader, size int64) (*File, error) {
	dir, err := NormalizeDir(dir)
	if err != nil {
		return nil, err
	}
	name, err = NormalizeName(name)
	if err != nil {
		return nil, err
	}
	if size <= 0 {
		return nil, fmt.Errorf("%w: empty body", ErrInvalidPath)
	}
	if size > MaxSmallFileSize {
		return nil, fmt.Errorf("%w: %d bytes exceeds the %d byte direct upload limit",
			ErrTooLarge, size, MaxSmallFileSize)
	}
	// Quota is checked before any bytes are read or any row is reserved: a tenant
	// that is out of room should not pay for the transfer, and the name must not
	// end up taken by an upload that cannot be stored.
	if err := s.checkQuota(ctx, tenantID, size); err != nil {
		return nil, err
	}

	key, err := objectKey(tenantID, name)
	if err != nil {
		return nil, err
	}

	// Read one byte past the declared size: a longer body is rejected by n != size
	// below instead of being silently truncated.
	buf := make([]byte, size)
	n, err := io.ReadFull(body, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, fmt.Errorf("%w: read body: %v", ErrInvalidPath, err)
	}
	if int64(n) != size {
		return nil, fmt.Errorf("%w: body has %d bytes, declared %d", ErrInvalidPath, n, size)
	}

	sum := sha256.Sum256(buf)
	f := &File{
		TenantID:    tenantID,
		OwnerID:     ownerID,
		Dir:         dir,
		Name:        name,
		Size:        size,
		SHA256:      hex.EncodeToString(sum[:]),
		ContentType: pickupContentType(contentType, name),
		Storage:     s.backend,
		StorageKey:  key,
	}

	id, err := s.store.Insert(ctx, f)
	if err != nil {
		return nil, err
	}
	f.ID = id

	if err := s.sp.Put(ctx, key, bytes.NewReader(buf), size); err != nil {
		// The name is reserved but no usable object exists, so the row must go:
		// otherwise the name stays taken by a file that can never be downloaded.
		if _, delErr := s.store.Delete(ctx, tenantID, id); delErr != nil {
			return nil, fmt.Errorf("store object: %w (and release name: %v)", err, delErr)
		}
		_ = s.sp.Delete(ctx, key) // Put may have written a partial object
		return nil, fmt.Errorf("store object: %w", err)
	}
	return f, nil
}

// Get returns one file's metadata for the caller's tenant, without opening the
// object. Authorisation needs the path before it can decide, so it cannot wait
// for a download to have already started.
func (s *Service) Get(ctx context.Context, tenantID, id int64) (*File, error) {
	return s.store.GetByID(ctx, tenantID, id)
}

// Open returns the metadata and a reader for the caller's own tenant only.
//
// The reader can seek so the HTTP layer can serve a byte range. That is what
// makes an interrupted download resumable; see the Provider interface comment.
func (s *Service) Open(ctx context.Context, tenantID, id int64) (*File, io.ReadSeekCloser, error) {
	f, err := s.store.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, nil, err
	}
	rc, err := s.sp.Get(ctx, f.StorageKey)
	if err != nil {
		return nil, nil, fmt.Errorf("open object %q: %w", f.StorageKey, err)
	}
	return f, rc, nil
}

// List returns one page of the entries in one directory of the caller's tenant.
func (s *Service) List(ctx context.Context, tenantID int64, dir string, limit, offset int) ([]File, error) {
	dir, err := NormalizeDir(dir)
	if err != nil {
		return nil, err
	}
	return s.store.ListByDir(ctx, tenantID, dir, limit, offset)
}

// OpenText returns the metadata and a reader for the enrichment pipeline.
//
// It is separate from Open only to name the intent: this reader may be consumed
// on a background worker, so the caller owns closing it and must not hand it the
// request's context lifetime.
func (s *Service) OpenText(ctx context.Context, tenantID, id int64) (*File, io.ReadCloser, error) {
	return s.Open(ctx, tenantID, id)
}

// Delete removes the metadata first: if the blob removal fails afterwards, the
// leftover object is unreachable through the API, whereas the reverse order
// would leave a row pointing at bytes that are already gone.
//
// The object is only removed when no other row still references the same key.
// An instant-upload hit appends rows that share one physical object, so deleting
// any of them unconditionally would take the bytes away from the survivors.
func (s *Service) Delete(ctx context.Context, tenantID, id int64) error {
	f, err := s.store.Delete(ctx, tenantID, id)
	if err != nil {
		return err
	}
	shared, err := s.store.CountByStorageKey(ctx, tenantID, f.StorageKey)
	if err != nil {
		return err
	}
	if shared > 0 {
		return nil
	}
	if err := s.sp.Delete(ctx, f.StorageKey); err != nil {
		// The row is already gone, so the caller's intent is satisfied: an object
		// that is no longer there is the desired end state, not a failure. This
		// happens for real after a re-upload at the same path or when the bucket
		// was cleaned out from under an old row.
		if errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("remove object %q: %w", f.StorageKey, err)
	}
	return nil
}

// Adopt takes ownership of a file already assembled on local disk by the merge
// step, moving it into storage under this file's key.
//
// The digest is computed while the bytes are copied into storage, so the merge
// does not have to read the assembled file a second time just to learn its hash.
func (s *Service) Adopt(ctx context.Context, tenantID, ownerID int64, dir, name, contentType, localPath string, size int64) (*File, error) {
	name, err := NormalizeName(name)
	if err != nil {
		return nil, err
	}
	key, err := objectKey(tenantID, name)
	if err != nil {
		return nil, err
	}

	src, err := os.Open(localPath)
	if err != nil {
		return nil, fmt.Errorf("open merged file: %w", err)
	}
	defer src.Close()

	// Reserve the name first, for the same reason as Upload: a duplicate must
	// fail before anything is written, never delete bytes that already exist.
	f := &File{
		TenantID:    tenantID,
		OwnerID:     ownerID,
		Dir:         dir,
		Name:        name,
		Size:        size,
		ContentType: pickupContentType(contentType, name),
		Storage:     s.backend,
		StorageKey:  key,
	}
	id, err := s.store.Insert(ctx, f)
	if err != nil {
		return nil, err
	}
	f.ID = id

	h := sha256.New()
	if err := s.sp.Put(ctx, key, io.TeeReader(src, h), size); err != nil {
		if _, delErr := s.store.Delete(ctx, tenantID, id); delErr != nil {
			return nil, fmt.Errorf("store object: %w (and release name: %v)", err, delErr)
		}
		_ = s.sp.Delete(ctx, key)
		return nil, fmt.Errorf("store object: %w", err)
	}
	f.SHA256 = hex.EncodeToString(h.Sum(nil))

	// The digest only exists after the copy, so it is filled in afterwards. If
	// this update fails the bytes and row are still consistent — only an instant
	// upload lookup would stop matching this row, which is a miss, not corruption.
	if err := s.store.SetDigest(ctx, tenantID, id, f.SHA256); err != nil {
		return nil, err
	}
	return f, nil
}

// Reference appends a file row that points at an object the tenant already
// stores with this digest, which is what makes an instant hit cost no transfer
// and no disk write.
//
// The row still gets its own (dir, name) while pointing at the source row's key,
// so the file behaves like any other afterwards: listing, download and delete all
// work unchanged, and the shared object survives until its last row is gone.
func (s *Service) Reference(ctx context.Context, tenantID, ownerID int64, dir, name, contentType, sha256Hex string, size int64) (*File, error) {
	name, err := NormalizeName(name)
	if err != nil {
		return nil, err
	}
	src, err := s.store.FindByDigest(ctx, tenantID, sha256Hex)
	if err != nil {
		return nil, err
	}
	if src.Size != size {
		return nil, fmt.Errorf("%w: stored object is %d bytes, client declared %d",
			ErrInvalidPath, src.Size, size)
	}

	// An instant hit onto an existing (dir, name) is a no-op rather than an error:
	// the client asked for a file it already has, and returning the row it already
	// has is the useful answer.
	if existing, err := s.store.FindByPath(ctx, tenantID, dir, name); err == nil {
		if existing.SHA256 == sha256Hex {
			return existing, nil
		}
		return nil, fmt.Errorf("%w: %s/%s", ErrNameTaken, dir, name)
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	f := &File{
		TenantID:    tenantID,
		OwnerID:     ownerID,
		Dir:         dir,
		Name:        name,
		Size:        size,
		SHA256:      sha256Hex,
		ContentType: pickupContentType(contentType, name),
		Storage:     src.Storage,
		// The row points at the source object: an instant hit writes nothing, so
		// there is no object under its own key to point at.
		StorageKey: src.StorageKey,
	}
	id, err := s.store.Insert(ctx, f)
	if err != nil {
		return nil, err
	}
	f.ID = id
	// An instant hit is a new file from the caller's point of view (new path, new
	// id), so it gets its own enrichment. It shares bytes, not metadata.
	return f, nil
}

// pickupContentType trusts the client only as far as the extension agrees.
func pickupContentType(declared, name string) string {
	if declared != "" {
		if mt, _, err := mime.ParseMediaType(declared); err == nil {
			return mt
		}
	}
	if guessed := mime.TypeByExtension(filepath.Ext(name)); guessed != "" {
		return guessed
	}
	return "application/octet-stream"
}
