package file

import (
	"strings"
	"testing"
)

func TestNormalizeDir(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "/", false},
		{"/", "/", false},
		{"a", "/a", false},
		{"/a/b/", "/a/b", false},
		{"a//b", "/a/b", false},
		{"../etc", "", true},
		{"a/../../b", "", true},
		// A backslash is a path separator to the local backend on Windows, so
		// "/a\b" must not be allowed to become a directory name at all.
		{`/a\b`, "", true},
		{`a\b`, "", true},
		{"/a\x00b", "", true},
	}
	for _, c := range cases {
		got, err := NormalizeDir(c.in)
		if c.wantErr {
			if err == nil {
				t.Fatalf("NormalizeDir(%q) = %q, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("NormalizeDir(%q) error: %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("NormalizeDir(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeName(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"report.pdf", false},
		{"  spaced.txt  ", false},
		{"", true},
		{".", true},
		{"..", true},
		{"a/b.txt", true},
		{"a\\b.txt", true},
	}
	for _, c := range cases {
		_, err := NormalizeName(c.in)
		if c.wantErr != (err != nil) {
			t.Fatalf("NormalizeName(%q) error = %v, wantErr = %v", c.in, err, c.wantErr)
		}
	}
}

func TestPickupContentType(t *testing.T) {
	if got := pickupContentType("text/csv; charset=utf-8", "a.bin"); got != "text/csv" {
		t.Fatalf("declared type = %q, want text/csv", got)
	}
	if got := pickupContentType("", "a.json"); got != "application/json" {
		t.Fatalf("guessed type = %q, want application/json", got)
	}
	if got := pickupContentType("", "a.unknownext"); got != "application/octet-stream" {
		t.Fatalf("fallback type = %q", got)
	}
}

// A key belongs to one row, not to a path: two uploads of the same name must
// never land on the same key, or the second would overwrite bytes the first row
// still points at. The key must also fit the column it is stored in.
func TestObjectKey(t *testing.T) {
	first, err := objectKey(1, "f.txt")
	if err != nil {
		t.Fatalf("objectKey: %v", err)
	}
	if !strings.HasPrefix(first, "1/") || !strings.HasSuffix(first, "/f.txt") {
		t.Fatalf("key = %q, want <tenant>/<random>/<name>", first)
	}

	second, err := objectKey(1, "f.txt")
	if err != nil {
		t.Fatalf("objectKey second: %v", err)
	}
	if first == second {
		t.Fatalf("two objects got the same key %q", first)
	}

	// A maximal name still fits storage_key VARCHAR(512).
	longName := strings.Repeat("n", maxNameLen)
	if _, err := objectKey(10, longName); err != nil {
		t.Fatalf("maximal name key should fit: %v", err)
	}
	// The width guard stays as a backstop even though NormalizeName caps the name
	// well below it.
	if _, err := objectKey(10, strings.Repeat("n", maxStorageKeyLen)); err == nil {
		t.Fatal("key that overflows storage_key was accepted")
	}
}
