package storage

import (
	"context"
	"errors"
	"testing"
)

// Keys come from the database, but a compromised or buggy caller must not be
// able to read or write outside the storage root.
func TestLocalRejectsEscapingKeys(t *testing.T) {
	p, err := NewLocal(t.TempDir())
	if err != nil {
		t.Fatalf("new local: %v", err)
	}
	ctx := context.Background()

	for _, key := range []string{"../outside.txt", "../../etc/passwd", "a/../../../b"} {
		if err := p.Put(ctx, key, nil, 0); err == nil {
			t.Fatalf("key %q was accepted", key)
		}
	}
	if _, err := p.Get(ctx, "../outside.txt"); err == nil {
		t.Fatal("get with an escaping key returned no error")
	}
}

func TestLocalAcceptsNestedKeys(t *testing.T) {
	p, err := NewLocal(t.TempDir())
	if err != nil {
		t.Fatalf("new local: %v", err)
	}
	ctx := context.Background()
	if err := p.Put(ctx, "1/reports/2026/q1.csv", nil, 0); err != nil {
		t.Fatalf("put nested key: %v", err)
	}
	if _, err := p.Stat(ctx, "1/reports/2026/q1.csv"); err != nil {
		t.Fatalf("stat nested key: %v", err)
	}
}

func TestLocalEmptyKeyRejected(t *testing.T) {
	p, err := NewLocal(t.TempDir())
	if err != nil {
		t.Fatalf("new local: %v", err)
	}
	if _, err := p.Get(context.Background(), ""); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("err = %v, want ErrInvalidKey", err)
	}
}
