package storage

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"
)

// The contract every Provider must satisfy.
//
// Both implementations run it. local is always available, so the suite has a
// case that runs on any machine; the S3 case needs a bucket and skips without
// one. Running the same assertions against both is what keeps the dev backend
// from quietly drifting away from the one that ships.
func TestProviderContract(t *testing.T) {
	t.Run("local", func(t *testing.T) {
		runProviderContract(t, func(t *testing.T) Provider {
			p, err := NewLocal(t.TempDir())
			if err != nil {
				t.Fatalf("new local provider: %v", err)
			}
			return p
		})
	})

	t.Run("s3", func(t *testing.T) {
		cfg := s3TestConfig(t)
		runProviderContract(t, func(t *testing.T) Provider {
			p, err := NewS3(context.Background(), cfg())
			if err != nil {
				t.Fatalf("new s3 provider: %v", err)
			}
			return p
		})
	})
}

// s3TestConfig reads the S3 settings from the environment. Without an
// endpoint the test skips, so `go test ./...` works on a machine with no bucket.
//
// UseSSL matters as much as the endpoint: a TLS-only backend answers a plain-http
// request with 301 Moved Permanently, which reads as "every contract case fails"
// even though the provider is fine. It follows GODOC_TEST_S3_USE_SSL, and falls
// back to https for anything that is obviously not a loopback endpoint.
func s3TestConfig(t *testing.T) func() S3Config {
	t.Helper()
	endpoint := os.Getenv("GODOC_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("set GODOC_TEST_S3_ENDPOINT to run the S3 contract tests")
	}
	bucket := os.Getenv("GODOC_TEST_S3_BUCKET")
	if bucket == "" {
		bucket = "godochub-test"
	}
	useSSL := testS3UseSSL(endpoint)
	return func() S3Config {
		return S3Config{
			Endpoint:  endpoint,
			AccessKey: os.Getenv("GODOC_TEST_S3_ACCESS_KEY"),
			SecretKey: os.Getenv("GODOC_TEST_S3_SECRET_KEY"),
			Bucket:    bucket,
			UseSSL:    useSSL,
			Region:    os.Getenv("GODOC_TEST_S3_REGION"),
		}
	}
}

// testS3UseSSL decides whether to speak TLS to the test endpoint. An explicit
// GODOC_TEST_S3_USE_SSL wins; otherwise loopback endpoints are plain http (the
// local S3 gateways this project uses) and everything else is https, because a
// public object store is TLS-only in practice.
func testS3UseSSL(endpoint string) bool {
	switch os.Getenv("GODOC_TEST_S3_USE_SSL") {
	case "1", "true", "yes":
		return true
	case "0", "false", "no":
		return false
	}
	host := endpoint
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host != "127.0.0.1" && host != "localhost" && host != "::1"
}

func runProviderContract(t *testing.T, newProvider func(t *testing.T) Provider) {
	ctx := context.Background()

	t.Run("put then get returns the same bytes", func(t *testing.T) {
		p := newProvider(t)
		payload := []byte("hello docnub")

		if err := p.Put(ctx, "1/a/file.txt", bytes.NewReader(payload), int64(len(payload))); err != nil {
			t.Fatalf("put: %v", err)
		}
		rc, err := p.Get(ctx, "1/a/file.txt")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		defer rc.Close()

		got, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("bytes = %q, want %q", got, payload)
		}
	})

	t.Run("stat reports the written size", func(t *testing.T) {
		p := newProvider(t)
		payload := []byte("0123456789")
		if err := p.Put(ctx, "k", bytes.NewReader(payload), int64(len(payload))); err != nil {
			t.Fatalf("put: %v", err)
		}
		info, err := p.Stat(ctx, "k")
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if info.Size != int64(len(payload)) {
			t.Fatalf("size = %d, want %d", info.Size, len(payload))
		}
	})

	t.Run("get missing key is ErrNotFound", func(t *testing.T) {
		p := newProvider(t)
		if _, err := p.Get(ctx, "nope"); err == nil {
			t.Fatal("get of a missing key returned no error")
		}
	})

	t.Run("delete removes the object", func(t *testing.T) {
		p := newProvider(t)
		payload := []byte("x")
		if err := p.Put(ctx, "gone", bytes.NewReader(payload), 1); err != nil {
			t.Fatalf("put: %v", err)
		}
		if err := p.Delete(ctx, "gone"); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if _, err := p.Stat(ctx, "gone"); err == nil {
			t.Fatal("stat after delete returned no error")
		}
	})

	t.Run("delete missing key is ErrNotFound", func(t *testing.T) {
		p := newProvider(t)
		if err := p.Delete(ctx, "never-existed"); err == nil {
			t.Fatal("delete of a missing key returned no error")
		}
	})

	// Download serves byte ranges by seeking, so every provider's reader has to
	// seek. A provider without it would make every resumed download restart.
	t.Run("get returns a reader that can seek", func(t *testing.T) {
		p := newProvider(t)
		payload := []byte("0123456789")
		if err := p.Put(ctx, "seekable", bytes.NewReader(payload), int64(len(payload))); err != nil {
			t.Fatalf("put: %v", err)
		}
		rc, err := p.Get(ctx, "seekable")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		defer rc.Close()

		if _, err := rc.Seek(6, io.SeekStart); err != nil {
			t.Fatalf("seek: %v", err)
		}
		tail, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("read after seek: %v", err)
		}
		if string(tail) != "6789" {
			t.Fatalf("tail after seek = %q, want %q", tail, "6789")
		}
	})

	// A size that does not match the body must fail loudly instead of storing a
	// truncated object that later looks complete.
	t.Run("short body is rejected", func(t *testing.T) {
		p := newProvider(t)
		err := p.Put(ctx, "short", strings.NewReader("abc"), 10)
		if err == nil {
			t.Fatal("put accepted a body shorter than the declared size")
		}
		if _, statErr := p.Stat(ctx, "short"); statErr == nil {
			t.Fatal("a half-written object was left behind")
		}
	})
}
