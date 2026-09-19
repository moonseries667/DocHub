package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"godochub/internal/file"
)

// MaxSmallFileSize mirrors the file package's limit so the oversized-upload test
// cannot drift away from the code it exercises.
const MaxSmallFileSize = file.MaxSmallFileSize

// fileBody is the unified envelope around one file's metadata.
type fileBody struct {
	Code int `json:"code"`
	Data struct {
		ID     int64  `json:"id"`
		Dir    string `json:"dir"`
		Name   string `json:"name"`
		Size   int64  `json:"size"`
		SHA256 string `json:"sha256"`
	} `json:"data"`
}

type listBody struct {
	Code int `json:"code"`
	Data struct {
		Dir   string `json:"dir"`
		Files []struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
			Size int64  `json:"size"`
		} `json:"files"`
	} `json:"data"`
}

func mustUpload(t *testing.T, env *testEnv, token, dir, name string, content []byte) fileBody {
	t.Helper()
	rec := uploadFile(t, env.engine, token, dir, name, content)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var body fileBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode upload body: %v (raw=%s)", err, rec.Body.String())
	}
	return body
}

// The core promise of the stage: what goes up comes down byte for byte.
func TestUploadDownloadRoundTrip(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	content := make([]byte, 64*1024)
	if _, err := rand.Read(content); err != nil {
		t.Fatalf("random content: %v", err)
	}
	want := sha256.Sum256(content)

	uploaded := mustUpload(t, env, token, "/reports", "q1.bin", content)
	if uploaded.Data.Size != int64(len(content)) {
		t.Fatalf("reported size = %d, want %d", uploaded.Data.Size, len(content))
	}
	if uploaded.Data.SHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("reported sha256 = %s, want %s", uploaded.Data.SHA256, hex.EncodeToString(want[:]))
	}
	if uploaded.Data.Dir != "/reports" || uploaded.Data.Name != "q1.bin" {
		t.Fatalf("metadata = %+v", uploaded.Data)
	}

	rec := doJSON(t, env.engine, http.MethodGet,
		"/api/v1/files/"+itoa(uploaded.Data.ID)+"/download", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("download status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if !bytes.Equal(rec.Body.Bytes(), content) {
		t.Fatalf("downloaded %d bytes, want %d identical bytes", rec.Body.Len(), len(content))
	}
	if got := rec.Header().Get("Content-Length"); got != itoa(int64(len(content))) {
		t.Fatalf("content-length = %s, want %d", got, len(content))
	}
}

func TestListShowsOnlyThatDirectory(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	mustUpload(t, env, token, "/reports", "a.txt", []byte("a"))
	mustUpload(t, env, token, "/reports", "b.txt", []byte("b"))
	mustUpload(t, env, token, "/other", "c.txt", []byte("c"))

	rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/files?dir=/reports", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var body listBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(body.Data.Files) != 2 {
		t.Fatalf("listed %d files, want 2: %+v", len(body.Data.Files), body.Data.Files)
	}
	if body.Data.Files[0].Name != "a.txt" || body.Data.Files[1].Name != "b.txt" {
		t.Fatalf("names = %s, %s; want a.txt, b.txt (sorted)", body.Data.Files[0].Name, body.Data.Files[1].Name)
	}
}

// A download that can be resumed is the difference between "usable over a flaky
// link" and "start over every time". The server must answer a byte range with
// 206 and the requested slice, not 200 and the whole object.
func TestDownloadServesByteRange(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	content := []byte("0123456789abcdefghij")
	up := mustUpload(t, env, token, "/ranges", "ten.bin", content)
	path := "/api/v1/files/" + itoa(up.Data.ID) + "/download"

	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Range", "bytes=4-9")
	rec := doRequest(env.engine, req)

	if rec.Code != http.StatusPartialContent {
		t.Fatalf("range request = %d, want 206 (body=%s)", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "456789" {
		t.Fatalf("range body = %q, want %q", got, "456789")
	}
	if got := rec.Header().Get("Content-Range"); got != "bytes 4-9/20" {
		t.Fatalf("content-range = %q, want bytes 4-9/20", got)
	}
	if got := rec.Header().Get("Accept-Ranges"); got != "bytes" {
		t.Fatalf("accept-ranges = %q, want bytes", got)
	}
}

// An open-ended range is what a resuming client actually sends: "give me
// everything from where my partial file stopped".
func TestDownloadServesOpenEndedRange(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	up := mustUpload(t, env, token, "/ranges", "tail.bin", []byte("abcdefghij"))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/files/"+itoa(up.Data.ID)+"/download", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Range", "bytes=7-")
	rec := doRequest(env.engine, req)

	if rec.Code != http.StatusPartialContent {
		t.Fatalf("open-ended range = %d, want 206", rec.Code)
	}
	if got := rec.Body.String(); got != "hij" {
		t.Fatalf("resumed tail = %q, want %q", got, "hij")
	}
}

// A range past the end is a client error, not a 500 and not a full body.
func TestDownloadRejectsUnsatisfiableRange(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	up := mustUpload(t, env, token, "/ranges", "short.bin", []byte("abc"))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/files/"+itoa(up.Data.ID)+"/download", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Range", "bytes=100-200")
	rec := doRequest(env.engine, req)

	if rec.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("unsatisfiable range = %d, want 416", rec.Code)
	}
}

// HEAD answers "how big is this and can I resume" without shipping the bytes.
// A client probing before a download has no other standard way to ask.
func TestDownloadHeadReportsMetadataWithoutBody(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	content := []byte("head-me")
	up := mustUpload(t, env, token, "/heads", "probe.bin", content)

	req := httptest.NewRequest(http.MethodHead, "/api/v1/files/"+itoa(up.Data.ID)+"/download", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := doRequest(env.engine, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("HEAD = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Length"); got != itoa(int64(len(content))) {
		t.Fatalf("HEAD content-length = %q, want %d", got, len(content))
	}
	if got := rec.Header().Get("Accept-Ranges"); got != "bytes" {
		t.Fatalf("HEAD accept-ranges = %q, want bytes", got)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("HEAD returned %d body bytes, want 0", rec.Body.Len())
	}
}

// Listing must be paged. A directory that has been written to for a year cannot
// be serialised into one response, and a caller needs a way to walk it.
func TestListIsPaged(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	for _, name := range []string{"a.txt", "b.txt", "c.txt", "d.txt", "e.txt"} {
		mustUpload(t, env, token, "/paged", name, []byte(name))
	}

	// First page: two rows plus a pointer to the rest.
	rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/files?dir=/paged&limit=2", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("first page = %d (body=%s)", rec.Code, rec.Body.String())
	}
	var page struct {
		Data struct {
			Files []struct {
				Name string `json:"name"`
			} `json:"files"`
			Limit      int `json:"limit"`
			NextOffset int `json:"next_offset"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode page: %v", err)
	}
	if len(page.Data.Files) != 2 || page.Data.Files[0].Name != "a.txt" {
		t.Fatalf("first page = %+v, want a.txt and b.txt", page.Data.Files)
	}
	if page.Data.NextOffset != 2 {
		t.Fatalf("next_offset = %d, want 2", page.Data.NextOffset)
	}

	// Walk the rest and make sure the pages together are the whole directory,
	// with no row repeated and none skipped.
	var seen []string
	for _, f := range page.Data.Files {
		seen = append(seen, f.Name)
	}
	offset := page.Data.NextOffset
	for offset > 0 {
		rec := doJSON(t, env.engine, http.MethodGet,
			"/api/v1/files?dir=/paged&limit=2&offset="+itoa(int64(offset)), token, nil)
		page.Data.Files = nil
		page.Data.NextOffset = 0
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			t.Fatalf("decode page at %d: %v", offset, err)
		}
		for _, f := range page.Data.Files {
			seen = append(seen, f.Name)
		}
		offset = page.Data.NextOffset
	}
	want := []string{"a.txt", "b.txt", "c.txt", "d.txt", "e.txt"}
	if strings.Join(seen, ",") != strings.Join(want, ",") {
		t.Fatalf("paged walk = %v, want %v", seen, want)
	}
}

// The last page must not advertise a next one, or a client loops forever.
func TestListLastPageHasNoNextOffset(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token
	mustUpload(t, env, token, "/onepage", "only.txt", []byte("x"))

	rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/files?dir=/onepage&limit=10", token, nil)
	if strings.Contains(rec.Body.String(), "next_offset") {
		t.Fatalf("last page advertised a next page: %s", rec.Body.String())
	}
}

// limit is capped rather than trusted, so one request cannot ask for a whole
// directory; and a nonsense limit is a 400 rather than a silent default.
func TestListCapsLimitAndRejectsGarbage(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token
	mustUpload(t, env, token, "/capped", "a.txt", []byte("a"))

	rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/files?dir=/capped&limit=100000", token, nil)
	var body struct {
		Data struct {
			Limit int `json:"limit"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Data.Limit != 500 {
		t.Fatalf("limit = %d, want it capped at 500", body.Data.Limit)
	}

	for _, q := range []string{"limit=0", "limit=abc", "offset=-1"} {
		rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/files?dir=/capped&"+q, token, nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s = %d, want 400 (body=%s)", q, rec.Code, rec.Body.String())
		}
	}
}

// The multipart form carries the directory as a field next to the file part, and
// the handler reads the field before opening the part. A size-only assertion
// would pass even if the body were empty, because the row records the declared
// length; comparing bytes is what makes this meaningful.
func TestUploadStoresNonZeroBytesAlongsideFormFields(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	content := make([]byte, 64)
	for i := range content {
		content[i] = byte(i + 1)
	}
	up := mustUpload(t, env, token, "/both", "nonzero.bin", content)

	rec := doJSON(t, env.engine, http.MethodGet, "/api/v1/files/"+itoa(up.Data.ID)+"/download", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("download = %d (body=%s)", rec.Code, rec.Body.String())
	}
	if !bytes.Equal(rec.Body.Bytes(), content) {
		t.Fatalf("stored bytes differ from the upload: got %d bytes, want %d", rec.Body.Len(), len(content))
	}
	if up.Data.Dir != "/both" {
		t.Fatalf("dir = %q, want /both", up.Data.Dir)
	}
}

func TestDeleteRemovesMetadataAndBytes(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	uploaded := mustUpload(t, env, token, "/", "temp.txt", []byte("delete me"))
	id := uploaded.Data.ID

	rec := doJSON(t, env.engine, http.MethodDelete, "/api/v1/files/"+itoa(id), token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	gone := doJSON(t, env.engine, http.MethodGet, "/api/v1/files/"+itoa(id)+"/download", token, nil)
	if gone.Code != http.StatusNotFound {
		t.Fatalf("download after delete = %d, want 404", gone.Code)
	}

	listed := doJSON(t, env.engine, http.MethodGet, "/api/v1/files?dir=/", token, nil)
	var body listBody
	if err := json.Unmarshal(listed.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(body.Data.Files) != 0 {
		t.Fatalf("listing after delete has %d files, want 0", len(body.Data.Files))
	}
}

// Deleting a row whose object is already gone must succeed: the desired end state
// ("these bytes are not served any more") already holds. A 500 here punishes the
// caller for state they cannot influence — it showed up on a real S3 backend.
func TestDeleteSucceedsWhenObjectIsAlreadyGone(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	uploaded := mustUpload(t, env, token, "/gone-bytes", "orphan.txt", []byte("will lose its bytes"))
	// Remove the object behind the API's back, leaving the row pointing at nothing.
	row, err := env.files.Get(context.Background(), 1, uploaded.Data.ID)
	if err != nil {
		t.Fatalf("read row: %v", err)
	}
	if err := env.storage.Delete(context.Background(), row.StorageKey); err != nil {
		t.Fatalf("remove object behind the API: %v", err)
	}

	rec := doJSON(t, env.engine, http.MethodDelete, "/api/v1/files/"+itoa(uploaded.Data.ID), token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete of a row with missing bytes = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
}

// Tenant A must never see, download or delete tenant B's file — and must not be
// able to tell it exists.
func TestTenantCannotReachAnotherTenantsFile(t *testing.T) {
	env := newTestEnv(t)
	alice := env.login(t, "east", "alice", seedPassword).Data.Token
	bob := env.login(t, "south", "bob", seedPassword).Data.Token

	uploaded := mustUpload(t, env, alice, "/secret", "east-only.txt", []byte("east data"))
	id := itoa(uploaded.Data.ID)

	for _, tc := range []struct {
		name   string
		method string
		path   string
	}{
		{"download", http.MethodGet, "/api/v1/files/" + id + "/download"},
		{"delete", http.MethodDelete, "/api/v1/files/" + id},
	} {
		rec := doJSON(t, env.engine, tc.method, tc.path, bob, nil)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s across tenants = %d, want 404 (body=%s)", tc.name, rec.Code, rec.Body.String())
		}
		if bytes.Contains(rec.Body.Bytes(), []byte("east")) {
			t.Fatalf("%s leaked tenant data: %s", tc.name, rec.Body.String())
		}
	}

	// And the listing of the other tenant does not contain it either.
	listed := doJSON(t, env.engine, http.MethodGet, "/api/v1/files?dir=/secret", bob, nil)
	if listed.Code != http.StatusOK {
		t.Fatalf("bob list status = %d, want 200", listed.Code)
	}
	var body listBody
	if err := json.Unmarshal(listed.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(body.Data.Files) != 0 {
		t.Fatalf("bob sees %d of alice's files, want 0", len(body.Data.Files))
	}

	// Same name in the same directory is fine across tenants: the unique key
	// includes tenant_id.
	sameName := mustUpload(t, env, bob, "/secret", "east-only.txt", []byte("south data"))
	if sameName.Data.ID == uploaded.Data.ID {
		t.Fatal("two tenants ended up sharing one file row")
	}
}

func TestDuplicateNameInSameDirectoryConflicts(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	first := mustUpload(t, env, token, "/dup", "same.txt", []byte("first"))
	rec := uploadFile(t, env.engine, token, "/dup", "same.txt", []byte("second"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("second upload = %d, want 409 (body=%s)", rec.Code, rec.Body.String())
	}

	// The conflict must not touch what was already stored: a 1062 on the name
	// unique key must leave the existing row, and its bytes, exactly as they were.
	got := doJSON(t, env.engine, http.MethodGet,
		"/api/v1/files/"+itoa(first.Data.ID)+"/download", token, nil)
	if got.Code != http.StatusOK {
		t.Fatalf("original download after conflict = %d, want 200 (body=%s)", got.Code, got.Body.String())
	}
	if !bytes.Equal(got.Body.Bytes(), []byte("first")) {
		t.Fatalf("original bytes changed: %q", got.Body.String())
	}
	if int64(len(got.Body.Bytes())) != first.Data.Size {
		t.Fatalf("downloaded %d bytes, metadata says %d", got.Body.Len(), first.Data.Size)
	}
}

// A backslash in a directory name used to collapse onto the same storage object
// as a slash, because the local backend cleans paths with Windows separators.
func TestUploadRejectsBackslashDirectory(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	for _, dir := range []string{`/a\b`, "/a\x00b"} {
		rec := uploadFile(t, env.engine, token, dir, "bs.txt", []byte("payload"))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("dir %q = %d, want 400 (body=%s)", dir, rec.Code, rec.Body.String())
		}
	}

	// Nothing reached the storage root under a collapsed path.
	entries := walkFiles(t, env.root)
	if len(entries) != 0 {
		t.Fatalf("rejected uploads left objects behind: %v", entries)
	}
}

// Oversized uploads must answer 413 no matter which reader notices the limit:
// MaxBytesReader fires inside FormFile, the explicit size check fires afterwards.
func TestOversizedUploadIsAlways413(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	for _, size := range []int{MaxSmallFileSize + 512*1024, 2 * MaxSmallFileSize} {
		rec := uploadFile(t, env.engine, token, "/big", "big.bin", make([]byte, size))
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("%d bytes = %d, want 413 (body=%s)", size, rec.Code, rec.Body.String())
		}
	}
}

// The middleware, not the handler, must reject unauthenticated requests: this
// route parses its id before it looks at the identity, so a missing Abort would
// surface as 400 here.
func TestUnauthenticatedRequestNeverReachesHandler(t *testing.T) {
	env := newTestEnv(t)

	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/files/abc/download"},
		{http.MethodDelete, "/api/v1/files/abc"},
		{http.MethodGet, "/api/v1/files/1/download"},
	}
	for _, c := range cases {
		rec := doJSON(t, env.engine, c.method, c.path, "", nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s without a token = %d, want 401 (body=%s)",
				c.method, c.path, rec.Code, rec.Body.String())
		}
	}
}

func walkFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %q: %v", root, err)
	}
	return out
}

func TestUploadRejectsTraversalDirectory(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	rec := uploadFile(t, env.engine, token, "/../../etc", "x.txt", []byte("x"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("traversal dir upload = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
}

// A multipart filename containing a slash cannot escape: net/http's
// Part.FileName already applies filepath.Base, so the stored name is the last
// segment. This pins that behaviour rather than duplicating the parser.
func TestUploadStripsPathFromMultipartName(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	uploaded := mustUpload(t, env, token, "/", "sub/x.txt", []byte("x"))
	if uploaded.Data.Name != "x.txt" {
		t.Fatalf("stored name = %q, want x.txt", uploaded.Data.Name)
	}
	if uploaded.Data.Dir != "/" {
		t.Fatalf("stored dir = %q, want /", uploaded.Data.Dir)
	}
}

func TestUploadRequiresToken(t *testing.T) {
	env := newTestEnv(t)

	rec := uploadFile(t, env.engine, "", "/", "x.txt", []byte("x"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
