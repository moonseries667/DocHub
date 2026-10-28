// Package integration holds the tests that hit real MySQL and Redis.
//
// It is a separate package on purpose: `go test ./...` runs it, and the suite
// re-creates its own database each time so a stale schema cannot make a run
// pass for the wrong reason.
//
// Prerequisites: `make up` (MySQL on 127.0.0.1:3306, root/rootpass) and
// GODOC_MYSQL_DSN / GODOC_REDIS_ADDR if the ports differ.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"

	"godochub/internal/auth"
	"godochub/internal/chunk"
	"godochub/internal/file"
	"godochub/internal/httpx"
	"godochub/internal/migrate"
	"godochub/internal/perm"
	"godochub/internal/ratelimit"
	"godochub/internal/storage"
	"godochub/internal/tenant"
)

// seedPassword is what migrations/0001_init.sql hashes for alice and bob.
const seedPassword = "passw0rd"

const defaultDSN = "root:rootpass@tcp(127.0.0.1:3306)/docnub_test?parseTime=true&charset=utf8mb4&loc=Local"

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func testDSN() string {
	if v := os.Getenv("GODOC_TEST_MYSQL_DSN"); v != "" {
		return v
	}
	return defaultDSN
}

// adminDSN is the same server without a database, needed to drop/create it.
func adminDSN() string {
	dsn := testDSN()
	slash := strings.LastIndex(dsn, "/")
	query := strings.Index(dsn, "?")
	if slash < 0 || query < slash {
		return dsn
	}
	return dsn[:slash+1] + dsn[query:]
}

// setupDB recreates a dedicated database, then runs the project's real migration
// files against it. Recreating instead of cleaning tables keeps each run
// independent of what a previous run left behind.
func setupDB(t *testing.T) *sqlx.DB {
	t.Helper()

	admin, err := sqlx.Open("mysql", adminDSN())
	if err != nil {
		t.Fatalf("open admin connection: %v", err)
	}
	defer admin.Close()
	if _, err := admin.Exec("DROP DATABASE IF EXISTS docnub_test"); err != nil {
		t.Fatalf("drop test database: %v", err)
	}
	if _, err := admin.Exec("CREATE DATABASE docnub_test DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"); err != nil {
		t.Fatalf("create test database: %v", err)
	}

	db, err := sqlx.Open("mysql", testDSN())
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	applyMigrations(t, db)
	return db
}

func applyMigrations(t *testing.T, db *sqlx.DB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := migrate.Apply(ctx, db, filepath.Join("..", "..", "migrations")); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
}

type loginBody struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Token     string `json:"token"`
		ExpiresIn int64  `json:"expires_in"`
		User      struct {
			UserID   int64  `json:"user_id"`
			TenantID int64  `json:"tenant_id"`
			Username string `json:"username"`
		} `json:"user"`
	} `json:"data"`
}

type testEnv struct {
	engine  *gin.Engine
	auth    *auth.Service
	files   *file.Service
	chunks  *chunk.Service
	perm    *perm.Store
	storage storage.Provider
	root    string

	login func(t *testing.T, tenantCode, username, password string) loginBody
}

func newTestEnv(t *testing.T) *testEnv {
	return newTestEnvWithLimit(t, 0, 0)
}

// newTestEnvWithLimit builds the same engine, optionally with a token bucket.
// Zero burst disables the limiter, which is what most tests want.
func newTestEnvWithLimit(t *testing.T, burst int, window time.Duration) *testEnv {
	return newTestEnvFull(t, burst, window)
}

// newTestEnvFull is the assembly point: it mirrors main.go's route table, guards
// included, so a handler that only works without a guard cannot pass here.
func newTestEnvFull(t *testing.T, burst int, window time.Duration) *testEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db := setupDB(t)
	authService := auth.NewService(db, "test-secret-not-for-production", time.Hour)
	tenantStore := tenant.NewStore(db)

	// A directory per test keeps uploads from different tests from colliding and
	// lets a test inspect the bytes on disk if it needs to. The provider is the
	// project's own dev backend: the suite must not need a bucket and credentials
	// to run, and using the real implementation means the tests exercise the code
	// that ships rather than a test-only double.
	root := t.TempDir()
	provider, err := storage.NewLocal(root)
	if err != nil {
		t.Fatalf("new local storage: %v", err)
	}
	fileService := file.NewService(file.NewStore(db), provider, file.StorageLocal)
	fileService.OnQuotaCheck(tenantStore.ReserveBytes)
	chunkStore := chunk.NewStore(db)
	chunkService, err := chunk.NewService(chunkStore, fileService, filepath.Join(root, "_chunks"), 4)
	if err != nil {
		t.Fatalf("new chunk service: %v", err)
	}

	rdb := redis.NewClient(&redis.Options{Addr: redisAddr()})
	t.Cleanup(func() { rdb.Close() })
	permStore := perm.NewStore(db, rdb)

	// Permission decisions are cached in Redis and keyed by user and path, so a
	// previous run's keys must not answer for this one.
	clearPermCache(t, rdb)

	engine := httpx.NewEngine(testLogger())
	engine.POST("/api/v1/login", auth.NewHandler(authService).Login)
	protected := engine.Group("/api/v1", auth.Middleware(authService))
	if burst > 0 {
		limiter, err := ratelimit.NewLimiter(rdb, burst, window)
		if err != nil {
			t.Fatalf("new limiter: %v", err)
		}
		protected.Use(ratelimit.Middleware(limiter, testLogger()))
	}

	tenantHandler := tenant.NewHandler(tenantStore)
	fileHandler := file.NewHandler(fileService)
	chunkHandler := chunk.NewHandler(chunkService)
	permHandler := perm.NewHandler(permStore)
	// The route table mirrors main.go, guards included. Registering a route here
	// without the guard main puts on it is how the init/body bug survived a green
	// suite: the resolver never ran in any test.
	filePath := func(c *gin.Context) (string, error) {
		ident, ok := tenant.FromContext(c.Request.Context())
		if !ok {
			return "", errNoIdentity
		}
		id, err := pathID(c)
		if err != nil {
			return "", err
		}
		f, err := fileService.Get(c.Request.Context(), ident.TenantID, id)
		if err != nil {
			return "", err
		}
		return f.Dir, nil
	}
	uploadPath := func(c *gin.Context) (string, error) {
		ident, ok := tenant.FromContext(c.Request.Context())
		if !ok {
			return "", errNoIdentity
		}
		id, err := pathID(c)
		if err != nil {
			return "", err
		}
		sess, err := chunkStore.Get(c.Request.Context(), ident.TenantID, id)
		if errors.Is(err, chunk.ErrNotFound) {
			return "", httpx.ErrNotFound
		}
		if err != nil {
			return "", err
		}
		return sess.Dir, nil
	}
	protected.GET("/me", tenantHandler.ME)
	protected.GET("/users/:id/roles", tenantHandler.UserRoles)
	protected.GET("/users", tenantHandler.ListUsers)
	protected.POST("/users", perm.RequireManage(permStore), tenantHandler.CreateUser)
	protected.GET("/roles", tenantHandler.ListRoles)
	protected.POST("/roles", perm.RequireManage(permStore), tenantHandler.CreateRole)
	protected.PUT("/users/:id/roles/:role_id", perm.RequireManage(permStore), tenantHandler.AssignRole)
	protected.DELETE("/users/:id/roles/:role_id", perm.RequireManage(permStore), tenantHandler.RevokeRole)
	protected.GET("/usage", tenantHandler.Usage)
	protected.GET("/permissions", permHandler.MyPermissions)
	protected.GET("/permissions/check", permHandler.Check)
	protected.PUT("/permissions/acl", permHandler.SetACL)
	protected.DELETE("/permissions/acl", permHandler.DeleteACL)
	protected.POST("/files", perm.Guard(permStore, perm.ActionWrite, dirOfRequest), fileHandler.Upload)
	protected.GET("/files", perm.Guard(permStore, perm.ActionRead, dirOfRequest), fileHandler.List)
	protected.GET("/files/:id/download", perm.Guard(permStore, perm.ActionRead, filePath), fileHandler.Download)
	protected.HEAD("/files/:id/download", perm.Guard(permStore, perm.ActionRead, filePath), fileHandler.Download)
	protected.DELETE("/files/:id", perm.Guard(permStore, perm.ActionDelete, filePath), fileHandler.Delete)
	protected.POST("/uploads", perm.Guard(permStore, perm.ActionWrite, dirOfRequest), chunkHandler.Init)
	protected.GET("/uploads/:id", perm.Guard(permStore, perm.ActionRead, uploadPath), chunkHandler.Status)
	protected.PUT("/uploads/:id/chunks/:idx", perm.Guard(permStore, perm.ActionWrite, uploadPath), chunkHandler.Put)
	protected.POST("/uploads/:id/complete", perm.Guard(permStore, perm.ActionWrite, uploadPath), chunkHandler.Complete)
	protected.DELETE("/uploads/:id", perm.Guard(permStore, perm.ActionWrite, uploadPath), chunkHandler.Abort)

	env := &testEnv{
		engine:  engine,
		auth:    authService,
		files:   fileService,
		chunks:  chunkService,
		perm:    permStore,
		storage: provider,
		root:    root,
		login: func(t *testing.T, tenantCode, username, password string) loginBody {
			t.Helper()
			rec := doJSON(t, engine, http.MethodPost, "/api/v1/login", "", map[string]string{
				"tenant_code": tenantCode,
				"username":    username,
				"password":    password,
			})
			var body loginBody
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode login body: %v (raw=%s)", err, rec.Body.String())
			}
			return body
		},
	}

	return env
}

// pathID mirrors main's parseIDParam: a malformed id is a 400 before any lookup.
func pathID(c *gin.Context) (int64, error) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, httpx.ErrInvalidRequest
	}
	return id, nil
}

// dirOfRequest mirrors main's resolver for the routes that name a directory
// instead of a file. It reads the JSON body through gin's cached copy, which is
// what lets the handler bind the same bytes afterwards.
func dirOfRequest(c *gin.Context) (string, error) {
	if c.Request.Method == http.MethodPost {
		dir := c.PostForm("dir")
		if dir == "" {
			var payload struct {
				Dir string `json:"dir"`
			}
			if err := c.ShouldBindBodyWithJSON(&payload); err == nil {
				dir = payload.Dir
			}
		}
		return perm.NormalizePath(dir), nil
	}
	return perm.NormalizePath(c.Query("dir")), nil
}

// uploadFile posts a multipart upload through the real route, the same way the
// curl demo will.
func uploadFile(t *testing.T, engine *gin.Engine, token, dir, name string, content []byte) *httptest.ResponseRecorder {
	t.Helper()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if dir != "" {
		if err := mw.WriteField("dir", dir); err != nil {
			t.Fatalf("write dir field: %v", err)
		}
	}
	part, err := mw.CreateFormFile("file", name)
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatalf("write form file: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/files", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	return rec
}

func doJSON(t *testing.T, engine *gin.Engine, method, path, token string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	body := ""
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		body = string(raw)
	}

	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	return rec
}

// newRequest builds a request with a raw body, used by the chunk endpoints where
// the payload is the file bytes rather than JSON.
func newRequest(method, path string, body io.Reader, token string) *http.Request {
	req := httptest.NewRequest(method, path, body)
	req.Header.Set("Content-Type", "application/octet-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func doRequest(engine *gin.Engine, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	return rec
}

// httpRecorder aliases the recorder so tests can name the return type clearly.
type httpRecorder = httptest.ResponseRecorder

// clearPermCache drops every cached permission decision, so a test starts from
// an empty cache regardless of what a previous run left behind.
func clearPermCache(t *testing.T, rdb *redis.Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	keys, err := rdb.Keys(ctx, "perm*").Result()
	if err != nil || len(keys) == 0 {
		return
	}
	if err := rdb.Del(ctx, keys...).Err(); err != nil {
		t.Fatalf("clear permission cache: %v", err)
	}
}

func getenv(key string) string {
	return os.Getenv(key)
}

var errNoIdentity = errors.New("no identity in context")
