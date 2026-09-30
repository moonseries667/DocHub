package integration

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"

	"godochub/internal/chunk"
)

type initBody struct {
	Code int `json:"code"`
	Data struct {
		Instant   bool  `json:"instant"`
		UploadID  int64 `json:"upload_id"`
		ChunkSize int64 `json:"chunk_size"`
		ChunkNum  int   `json:"chunk_count"`
		File      *struct {
			ID     int64  `json:"id"`
			Name   string `json:"name"`
			Size   int64  `json:"size"`
			SHA256 string `json:"sha256"`
		} `json:"file"`
	} `json:"data"`
}

type statusBody struct {
	Code int `json:"code"`
	Data struct {
		UploadID  int64 `json:"upload_id"`
		ChunkSize int64 `json:"chunk_size"`
		ChunkNum  int   `json:"chunk_count"`
		Missing   []int `json:"missing"`
		Done      bool  `json:"done"`
	} `json:"data"`
}

// randomBytes returns n deterministic-but-uncompressible bytes for the test file.
func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("random bytes: %v", err)
	}
	return buf
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func initUpload(t *testing.T, env *testEnv, token, dir, name string, size int64, sha string, chunkSize int64) initBody {
	t.Helper()
	rec := doJSON(t, env.engine, http.MethodPost, "/api/v1/uploads", token, map[string]any{
		"dir": dir, "name": name, "size": size, "chunk_size": chunkSize, "sha256": sha,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("init = %d (body=%s)", rec.Code, rec.Body.String())
	}
	var body initBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode init: %v (raw=%s)", err, rec.Body.String())
	}
	return body
}

func putChunk(t *testing.T, engine *gin.Engine, token string, uploadID int64, idx int, payload []byte, checksum string) (int, string) {
	t.Helper()
	path := fmt.Sprintf("/api/v1/uploads/%d/chunks/%d", uploadID, idx)
	req := newRequest(http.MethodPut, path, bytes.NewReader(payload), token)
	if checksum != "" {
		req.Header.Set("X-Chunk-SHA256", checksum)
	}
	rec := doRequest(engine, req)
	return rec.Code, rec.Body.String()
}

func getStatus(t *testing.T, env *testEnv, token string, uploadID int64) statusBody {
	t.Helper()
	rec := doJSON(t, env.engine, http.MethodGet, fmt.Sprintf("/api/v1/uploads/%d", uploadID), token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s)", rec.Code, rec.Body.String())
	}
	var body statusBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	return body
}

func completeUpload(t *testing.T, env *testEnv, token string, uploadID int64) *httpRecorder {
	t.Helper()
	rec := doJSON(t, env.engine, http.MethodPost, fmt.Sprintf("/api/v1/uploads/%d/complete", uploadID), token, nil)
	return rec
}

// slice splits content into the exact chunk layout the server expects.
func slice(content []byte, chunkSize int64) [][]byte {
	var out [][]byte
	for off := 0; off < len(content); off += int(chunkSize) {
		end := off + int(chunkSize)
		if end > len(content) {
			end = len(content)
		}
		out = append(out, content[off:end])
	}
	return out
}

// The headline acceptance criterion: a 100MB file uploaded in chunks and merged
// must have the same SHA256 as the original, even arriving out of order.
func TestChunkedUpload100MBOutOfOrder(t *testing.T) {
	if testing.Short() {
		t.Skip("100MB round trip is skipped in -short mode")
	}
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	const chunkSize = 8 << 20 // 13 chunks for 100MB
	content := randomBytes(t, 100<<20)
	want := digestOf(content)

	init := initUpload(t, env, token, "/big", "hundred.bin", int64(len(content)), "", chunkSize)
	if init.Data.UploadID == 0 || init.Data.ChunkNum != 13 {
		t.Fatalf("init = %+v, want 13 chunks", init.Data)
	}

	// Reverse arrival order: the merge must not depend on the send sequence.
	parts := slice(content, chunkSize)
	for i := len(parts) - 1; i >= 0; i-- {
		if code, body := putChunk(t, env.engine, token, init.Data.UploadID, i, parts[i], digestOf(parts[i])); code != http.StatusOK {
			t.Fatalf("chunk %d = %d (body=%s)", i, code, body)
		}
	}

	rec := completeUpload(t, env, token, init.Data.UploadID)
	if rec.Code != http.StatusOK {
		t.Fatalf("complete = %d (body=%s)", rec.Code, rec.Body.String())
	}
	var merged fileBody
	if err := json.Unmarshal(rec.Body.Bytes(), &merged); err != nil {
		t.Fatalf("decode complete: %v", err)
	}
	if merged.Data.SHA256 != want {
		t.Fatalf("merged sha256 = %s, want %s", merged.Data.SHA256, want)
	}
	if merged.Data.Size != int64(len(content)) {
		t.Fatalf("merged size = %d, want %d", merged.Data.Size, len(content))
	}

	// And the bytes really are the original ones.
	down := doJSON(t, env.engine, http.MethodGet,
		fmt.Sprintf("/api/v1/files/%d/download", merged.Data.ID), token, nil)
	if down.Code != http.StatusOK {
		t.Fatalf("download = %d", down.Code)
	}
	if got := digestOf(down.Body.Bytes()); got != want {
		t.Fatalf("downloaded digest = %s, want %s", got, want)
	}
}

// Resume: after an interruption the client asks what is missing and sends only that.
func TestResumeSendsOnlyMissingChunks(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	const chunkSize = 512 << 10
	content := randomBytes(t, 5<<20) // 10 chunks
	want := digestOf(content)
	parts := slice(content, chunkSize)

	init := initUpload(t, env, token, "/resume", "resume.bin", int64(len(content)), "", chunkSize)
	id := init.Data.UploadID

	// Simulate an interruption after the first three chunks, out of order.
	for _, i := range []int{2, 0, 1} {
		if code, body := putChunk(t, env.engine, token, id, i, parts[i], digestOf(parts[i])); code != http.StatusOK {
			t.Fatalf("chunk %d = %d (%s)", i, code, body)
		}
	}

	st := getStatus(t, env, token, id)
	if st.Data.Done {
		t.Fatal("status reports done after three of ten chunks")
	}
	if len(st.Data.Missing) != 7 {
		t.Fatalf("missing = %v, want 7 entries", st.Data.Missing)
	}
	if st.Data.Missing[0] != 3 {
		t.Fatalf("missing[0] = %d, want 3 (0..2 already there)", st.Data.Missing[0])
	}

	// Completing before the rest arrives must fail rather than produce a short file.
	if rec := completeUpload(t, env, token, id); rec.Code != http.StatusConflict {
		t.Fatalf("early complete = %d, want 409 (body=%s)", rec.Code, rec.Body.String())
	}

	for _, i := range st.Data.Missing {
		if code, body := putChunk(t, env.engine, token, id, i, parts[i], digestOf(parts[i])); code != http.StatusOK {
			t.Fatalf("chunk %d = %d (%s)", i, code, body)
		}
	}
	if st := getStatus(t, env, token, id); !st.Data.Done || len(st.Data.Missing) != 0 {
		t.Fatalf("status after filling = %+v, want done", st.Data)
	}

	rec := completeUpload(t, env, token, id)
	if rec.Code != http.StatusOK {
		t.Fatalf("complete = %d (body=%s)", rec.Code, rec.Body.String())
	}
	var merged fileBody
	if err := json.Unmarshal(rec.Body.Bytes(), &merged); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if merged.Data.SHA256 != want {
		t.Fatalf("sha256 = %s, want %s", merged.Data.SHA256, want)
	}
}

// A tampered chunk must be refused at upload time and never reach the merge.
func TestTamperedChunkIsRejected(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	const chunkSize = 512 << 10
	content := randomBytes(t, 1<<20) // 2 chunks
	parts := slice(content, chunkSize)

	init := initUpload(t, env, token, "/tamper", "t.bin", int64(len(content)), "", chunkSize)
	id := init.Data.UploadID

	good := digestOf(parts[0])
	tampered := bytes.Clone(parts[0])
	tampered[0] ^= 0xff

	code, body := putChunk(t, env.engine, token, id, 0, tampered, good)
	if code != http.StatusBadRequest {
		t.Fatalf("tampered chunk = %d, want 400 (body=%s)", code, body)
	}
	// The rejected chunk must not be recorded as received.
	if st := getStatus(t, env, token, id); len(st.Data.Missing) != 2 {
		t.Fatalf("missing = %v, want both chunks still missing", st.Data.Missing)
	}

	// The good bytes for the same index still work afterwards.
	if code, body := putChunk(t, env.engine, token, id, 0, parts[0], good); code != http.StatusOK {
		t.Fatalf("retry chunk 0 = %d (%s)", code, body)
	}
}

// Instant upload: a second upload of known bytes must write nothing at all.
func TestInstantUploadWritesNothing(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	content := randomBytes(t, 1<<20)
	sum := digestOf(content)

	// First time: real upload through the chunked path.
	const chunkSize = 512 << 10
	init := initUpload(t, env, token, "/instant", "original.bin", int64(len(content)), sum, chunkSize)
	if init.Data.Instant {
		t.Fatal("first upload was reported as instant")
	}
	parts := slice(content, chunkSize)
	for i, p := range parts {
		if code, body := putChunk(t, env.engine, token, init.Data.UploadID, i, p, digestOf(p)); code != http.StatusOK {
			t.Fatalf("chunk %d = %d (%s)", i, code, body)
		}
	}
	if rec := completeUpload(t, env, token, init.Data.UploadID); rec.Code != http.StatusOK {
		t.Fatalf("complete = %d (%s)", rec.Code, rec.Body.String())
	}

	objectsBefore := walkFiles(t, env.root)

	// Second time, different directory and name: must hit the shortcut.
	instant := initUpload(t, env, token, "/instant/copy", "again.bin", int64(len(content)), sum, chunkSize)
	if !instant.Data.Instant {
		t.Fatalf("second upload was not instant: %+v", instant.Data)
	}
	if instant.Data.File == nil || instant.Data.File.SHA256 != sum {
		t.Fatalf("instant result = %+v, want the existing file", instant.Data)
	}

	objectsAfter := walkFiles(t, env.root)
	if len(objectsAfter) != len(objectsBefore) {
		t.Fatalf("instant upload wrote to storage: %d objects before, %d after: %v", len(objectsBefore), len(objectsAfter), objectsAfter)
	}

	// The reference still downloads the right bytes.
	down := doJSON(t, env.engine, http.MethodGet,
		fmt.Sprintf("/api/v1/files/%d/download", instant.Data.File.ID), token, nil)
	if down.Code != http.StatusOK {
		t.Fatalf("download of referenced file = %d (body=%s)", down.Code, down.Body.String())
	}
	if got := digestOf(down.Body.Bytes()); got != sum {
		t.Fatalf("referenced file digest = %s, want %s", got, sum)
	}
}

// Deleting one of several rows sharing an object must keep the bytes for the rest.
func TestDeletingOneReferenceKeepsSharedObject(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	content := randomBytes(t, 256<<10)
	sum := digestOf(content)

	first := mustUpload(t, env, token, "/shared", "a.bin", content)
	second := initUpload(t, env, token, "/shared2", "b.bin", int64(len(content)), sum, int64(chunk.MinChunkSize))
	if !second.Data.Instant {
		t.Fatalf("expected an instant hit, got %+v", second.Data)
	}

	// Drop the original row; the second row still points at the same object.
	rec := doJSON(t, env.engine, http.MethodDelete, fmt.Sprintf("/api/v1/files/%d", first.Data.ID), token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete = %d (%s)", rec.Code, rec.Body.String())
	}

	still := doJSON(t, env.engine, http.MethodGet,
		fmt.Sprintf("/api/v1/files/%d/download", second.Data.File.ID), token, nil)
	if still.Code != http.StatusOK {
		t.Fatalf("surviving reference = %d, want 200 (body=%s)", still.Code, still.Body.String())
	}
	if got := digestOf(still.Body.Bytes()); got != sum {
		t.Fatalf("surviving bytes digest = %s, want %s", got, sum)
	}

	// Removing the last reference does reclaim the object.
	del2 := doJSON(t, env.engine, http.MethodDelete, fmt.Sprintf("/api/v1/files/%d", second.Data.File.ID), token, nil)
	if del2.Code != http.StatusOK {
		t.Fatalf("second delete = %d (%s)", del2.Code, del2.Body.String())
	}
	if objs := walkFiles(t, filepath.Join(env.root, "1")); len(objs) != 0 {
		t.Fatalf("object survived its last reference: %v", objs)
	}
}

// Reclaim drops sessions that have been idle too long, temp files included.
func TestReclaimRemovesIdleUploads(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	const chunkSize = chunk.MinChunkSize
	content := randomBytes(t, 2*chunkSize)
	init := initUpload(t, env, token, "/abandoned", "x.bin", int64(len(content)), "", int64(chunkSize))

	parts := slice(content, chunkSize)
	if code, body := putChunk(t, env.engine, token, init.Data.UploadID, 0, parts[0], digestOf(parts[0])); code != http.StatusOK {
		t.Fatalf("chunk 0 = %d (%s)", code, body)
	}

	// Temp bytes live under <root>/_chunks/<tenant>/<upload>: one directory per
	// tenant so reclaiming one cannot reach another's chunks.
	tempDir := filepath.Join(env.root, "_chunks", "1", fmt.Sprint(init.Data.UploadID))
	if _, err := os.Stat(tempDir); err != nil {
		t.Fatalf("temp dir missing before reclaim: %v", err)
	}

	// Age the session instead of relying on a zero-hour window: the reclaimer
	// compares against NOW(), and a row written in the same second is not older.
	ageSession(t, init.Data.UploadID, 48)

	n, err := env.chunks.Reclaim(t.Context(), 24)
	if err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	if n != 1 {
		t.Fatalf("reclaimed %d sessions, want 1", n)
	}
	if _, err := os.Stat(tempDir); !os.IsNotExist(err) {
		t.Fatalf("temp dir survived reclaim: %v", err)
	}
	if rec := doJSON(t, env.engine, http.MethodGet,
		fmt.Sprintf("/api/v1/uploads/%d", init.Data.UploadID), token, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("status of reclaimed upload = %d, want 404", rec.Code)
	}
}

// Chunk endpoints are tenant-scoped like everything else.
func TestChunkUploadIsTenantScoped(t *testing.T) {
	env := newTestEnv(t)
	alice := env.login(t, "east", "alice", seedPassword).Data.Token
	bob := env.login(t, "south", "bob", seedPassword).Data.Token

	content := randomBytes(t, 2*chunk.MinChunkSize)
	init := initUpload(t, env, alice, "/private", "p.bin", int64(len(content)), "", int64(chunk.MinChunkSize))
	id := init.Data.UploadID

	if rec := doJSON(t, env.engine, http.MethodGet, fmt.Sprintf("/api/v1/uploads/%d", id), bob, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("bob status of alice's upload = %d, want 404", rec.Code)
	}
	if code, _ := putChunk(t, env.engine, bob, id, 0, content[:chunk.MinChunkSize], digestOf(content[:chunk.MinChunkSize])); code != http.StatusNotFound {
		t.Fatalf("bob writing to alice's upload = %d, want 404", code)
	}
	if rec := completeUpload(t, env, bob, id); rec.Code != http.StatusNotFound {
		t.Fatalf("bob completing alice's upload = %d, want 404", rec.Code)
	}
}

// An instant-upload row shares its owner's object. Deleting the owner and
// re-uploading different bytes at the same path must not reach that object: the
// surviving reference keeps serving — and advertising — the bytes it was
// created with.
func TestReuploadAfterOwnerDeleteLeavesSharedObjectAlone(t *testing.T) {
	env := newTestEnv(t)
	token := env.login(t, "east", "alice", seedPassword).Data.Token

	original := randomBytes(t, 256<<10)
	sum := digestOf(original)

	owner := mustUpload(t, env, token, "/bug", "orig.bin", original)
	ref := initUpload(t, env, token, "/bug2", "copy.bin", int64(len(original)), sum, chunk.MinChunkSize)
	if !ref.Data.Instant || ref.Data.File == nil {
		t.Fatalf("expected an instant hit, got %+v", ref.Data)
	}

	del := doJSON(t, env.engine, http.MethodDelete, "/api/v1/files/"+itoa(owner.Data.ID), token, nil)
	if del.Code != http.StatusOK {
		t.Fatalf("delete owner = %d (%s)", del.Code, del.Body.String())
	}

	// Same path, different content: this creates a new row and a new object.
	replacement := randomBytes(t, len(original))
	if digestOf(replacement) == sum {
		t.Fatal("test needs two distinct contents")
	}
	fresh := mustUpload(t, env, token, "/bug", "orig.bin", replacement)

	// The path serves the replacement...
	newBytes := doJSON(t, env.engine, http.MethodGet, "/api/v1/files/"+itoa(fresh.Data.ID)+"/download", token, nil)
	if newBytes.Code != http.StatusOK {
		t.Fatalf("download of the re-uploaded file = %d (%s)", newBytes.Code, newBytes.Body.String())
	}
	if got := digestOf(newBytes.Body.Bytes()); got != fresh.Data.SHA256 {
		t.Fatalf("re-uploaded file bytes = %s, its metadata says %s", got, fresh.Data.SHA256)
	}

	// ...and the survivor still serves its own bytes.
	survivor := doJSON(t, env.engine, http.MethodGet, "/api/v1/files/"+itoa(ref.Data.File.ID)+"/download", token, nil)
	if survivor.Code != http.StatusOK {
		t.Fatalf("surviving reference = %d (body=%s)", survivor.Code, survivor.Body.String())
	}
	if got := digestOf(survivor.Body.Bytes()); got != sum {
		t.Fatalf("surviving bytes digest = %s, want %s (the re-upload overwrote the shared object)", got, sum)
	}

	// Its metadata did not drift away from those bytes either.
	db := openTestDB(t)
	defer db.Close()
	var metaSHA string
	if err := db.Get(&metaSHA, "SELECT sha256 FROM file WHERE id = ?", ref.Data.File.ID); err != nil {
		t.Fatalf("read surviving metadata: %v", err)
	}
	if metaSHA != sum {
		t.Fatalf("surviving metadata sha256 = %s, want %s", metaSHA, sum)
	}
}

// The session routes carry the same ACL guard as the file routes. A user with no
// role at all must not be able to drive someone else's session to completion.
func TestRolelessUserCannotDriveAnotherUsersUpload(t *testing.T) {
	env := newTestEnv(t)
	alice := env.login(t, "east", "alice", seedPassword).Data.Token

	seedUserWithoutRole(t, "mallory", 1)
	mallory := env.login(t, "east", "mallory", seedPassword).Data.Token

	content := randomBytes(t, 2*chunk.MinChunkSize)
	init := initUpload(t, env, alice, "/hr", "salaries.bin", int64(len(content)), "", int64(chunk.MinChunkSize))
	id := init.Data.UploadID
	parts := slice(content, chunk.MinChunkSize)

	if code, body := putChunk(t, env.engine, mallory, id, 0, parts[0], digestOf(parts[0])); code != http.StatusForbidden {
		t.Fatalf("roleless PUT into another user's session = %d, want 403 (body=%s)", code, body)
	}
	if rec := doJSON(t, env.engine, http.MethodGet, fmt.Sprintf("/api/v1/uploads/%d", id), mallory, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("roleless status = %d, want 403", rec.Code)
	}
	if rec := completeUpload(t, env, mallory, id); rec.Code != http.StatusForbidden {
		t.Fatalf("roleless complete = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}

	// The rejected calls changed nothing: the owner still sees both chunks
	// missing and no file row exists in the target directory.
	if st := getStatus(t, env, alice, id); len(st.Data.Missing) != 2 {
		t.Fatalf("missing = %v, want both chunks untouched", st.Data.Missing)
	}
	listed := doJSON(t, env.engine, http.MethodGet, "/api/v1/files?dir=/hr", alice, nil)
	var body listBody
	if err := json.Unmarshal(listed.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(body.Data.Files) != 0 {
		t.Fatalf("roleless user landed %d file rows", len(body.Data.Files))
	}
}
