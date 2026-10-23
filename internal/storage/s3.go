package storage

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// S3 stores objects in any S3-compatible bucket: Cloudflare R2, AWS S3, MinIO,
// a vendor object store. It is the only Provider the project ships.
//
// The minio-go client speaks plain S3, so nothing here is MinIO-specific — the
// import name is just the SDK that happens to implement the protocol.
type S3 struct {
	client *minio.Client
	bucket string
}

// S3Config is the subset of S3 settings the project needs.
//
// Region is empty for gateways that do not care and "auto" for Cloudflare R2;
// AWS rejects both an empty region and a wrong one.
type S3Config struct {
	Endpoint  string
	AccessKey string
	SecretKey string
	Bucket    string
	UseSSL    bool
	Region    string
}

// NewS3 connects and makes sure the bucket exists.
//
// Bucket creation is part of construction on purpose: a server that starts
// against a missing bucket would fail every upload with an opaque 404 from the
// S3 layer, and doing it once here keeps the service layer free of "ensure"
// logic. On a managed bucket the credentials may legitimately lack CreateBucket;
// in that case an existing bucket is fine and only a missing one is fatal. That
// distinction is why BucketExists is checked first.
func NewS3(ctx context.Context, cfg S3Config) (*S3, error) {
	if cfg.Endpoint == "" || cfg.Bucket == "" {
		return nil, errors.New("s3: endpoint and bucket are required")
	}
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("s3: create client for %q: %w", cfg.Endpoint, err)
	}

	exists, err := client.BucketExists(ctx, cfg.Bucket)
	if err != nil {
		return nil, fmt.Errorf("s3: check bucket %q: %w", cfg.Bucket, err)
	}
	if !exists {
		if err := client.MakeBucket(ctx, cfg.Bucket, minio.MakeBucketOptions{Region: cfg.Region}); err != nil {
			return nil, fmt.Errorf("s3: create bucket %q: %w", cfg.Bucket, err)
		}
	}
	return &S3{client: client, bucket: cfg.Bucket}, nil
}

// Put writes exactly size bytes. The size is what makes a truncated body an
// error instead of a silently short object.
func (s *S3) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	info, err := s.client.PutObject(ctx, s.bucket, key, io.LimitReader(r, size), size, minio.PutObjectOptions{
		ContentType: "application/octet-stream",
	})
	if err != nil {
		// A partial upload must not survive: S3 would keep the previous version
		// (if any) or an incomplete multipart state otherwise.
		_ = s.client.RemoveObject(context.WithoutCancel(ctx), s.bucket, key, minio.RemoveObjectOptions{})
		return fmt.Errorf("s3: put %q: %w", key, err)
	}
	if info.Size != size {
		_ = s.client.RemoveObject(context.WithoutCancel(ctx), s.bucket, key, minio.RemoveObjectOptions{})
		return fmt.Errorf("s3: put %q stored %d bytes, expected %d", key, info.Size, size)
	}
	return nil
}

func (s *S3) Get(ctx context.Context, key string) (io.ReadSeekCloser, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, s.mapError(key, err)
	}
	// GetObject is lazy: the first Stat is what actually asks the server, so a
	// missing key must be reported here rather than by the caller's first Read.
	if _, err := obj.Stat(); err != nil {
		_ = obj.Close()
		return nil, s.mapError(key, err)
	}
	return obj, nil
}

func (s *S3) Delete(ctx context.Context, key string) error {
	// RemoveObject is idempotent and reports success for a key that never
	// existed, while the Provider contract says a missing key is ErrNotFound.
	// Stat first, then delete: the extra round trip is what makes the contract
	// honest, and delete is not on the hot path.
	if _, err := s.Stat(ctx, key); err != nil {
		return err
	}
	if err := s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{}); err != nil {
		return s.mapError(key, err)
	}
	return nil
}

func (s *S3) Stat(ctx context.Context, key string) (Info, error) {
	st, err := s.client.StatObject(ctx, s.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		return Info{}, s.mapError(key, err)
	}
	return Info{Size: st.Size, ModTime: st.LastModified}, nil
}

// mapError folds the SDK's error shape into the one outcome callers act on:
// a missing object. Everything else keeps the SDK's detail for the log.
func (s *S3) mapError(key string, err error) error {
	switch minio.ToErrorResponse(err).Code {
	case "NoSuchKey", "NotFound", "NoSuchBucket":
		return fmt.Errorf("%w: %q", ErrNotFound, key)
	}
	return fmt.Errorf("s3: %q: %w", key, err)
}

// ensure the interface stays satisfied at compile time.
var _ Provider = (*S3)(nil)
