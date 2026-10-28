package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"

	"godochub/internal/auth"
	"godochub/internal/chunk"
	"godochub/internal/config"
	"godochub/internal/file"
	"godochub/internal/httpx"
	"godochub/internal/migrate"
	"godochub/internal/perm"
	"godochub/internal/ratelimit"
	"godochub/internal/storage"
	"godochub/internal/tenant"
)

func main() {
	configPath := flag.String("config", "configs/config.yaml", "path of the yaml config, env vars override it")
	migrations := flag.String("migrations", "migrations", "directory holding the numbered .sql files")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	if err := run(*configPath, *migrations, logger); err != nil {
		logger.Error("server exited", "err", err)
		os.Exit(1)
	}
}

func run(configPath, migrationsDir string, logger *slog.Logger) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	db, err := sqlx.Open("mysql", cfg.MySQL.DSN)
	if err != nil {
		return fmt.Errorf("open mysql: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(cfg.MySQL.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MySQL.MaxIdleConns)

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})
	defer rdb.Close()

	// Migrations run before the listener opens: a server that accepts traffic
	// against a half-created schema fails in a far more confusing way.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := migrate.Apply(ctx, db, migrationsDir); err != nil {
		return err
	}

	authService := auth.NewService(db, cfg.Auth.JWTSecret, cfg.Auth.TokenTTL)
	tenantStore := tenant.NewStore(db)

	provider, backend, err := newProvider(ctx, cfg, logger)
	if err != nil {
		return err
	}
	fileService := file.NewService(file.NewStore(db), provider, backend)
	// Quota is wired as a hook so the file package never imports tenant: the two
	// would form a cycle, and the ceiling is a policy the assembly owns rather
	// than something the storage path should know about.
	fileService.OnQuotaCheck(tenantStore.ReserveBytes)
	chunkStore := chunk.NewStore(db)
	chunkService, err := chunk.NewService(chunkStore, fileService, cfg.Chunk.TempRoot, cfg.Chunk.PoolSize)
	if err != nil {
		return err
	}

	engine := httpx.NewEngine(logger)
	engine.GET("/healthz", healthz(db, rdb))

	authHandler := auth.NewHandler(authService)
	tenantHandler := tenant.NewHandler(tenantStore)
	fileHandler := file.NewHandler(fileService)
	chunkHandler := chunk.NewHandler(chunkService)
	permStore := perm.NewStore(db, rdb)
	permHandler := perm.NewHandler(permStore)
	engine.POST("/api/v1/login", authHandler.Login)

	protected := engine.Group("/api/v1", auth.Middleware(authService))
	if cfg.RateLimit.Enabled {
		limiter, err := ratelimit.NewLimiter(rdb, cfg.RateLimit.Burst, cfg.RateLimit.Window)
		if err != nil {
			return err
		}
		protected.Use(ratelimit.Middleware(limiter, logger))
	}

	protected.GET("/me", tenantHandler.ME)
	protected.GET("/users/:id/roles", tenantHandler.UserRoles)
	// Tenant administration: accounts, their grants, and the tenant's footprint.
	// Creating a user and granting a role are privileged acts, so they carry the
	// same perm.manage the ACL write path requires — otherwise any authenticated
	// caller could mint accounts or hand themselves a role.
	protected.GET("/users", tenantHandler.ListUsers)
	protected.POST("/users", perm.RequireManage(permStore), tenantHandler.CreateUser)
	protected.GET("/roles", tenantHandler.ListRoles)
	protected.POST("/roles", perm.RequireManage(permStore), tenantHandler.CreateRole)
	protected.PUT("/users/:id/roles/:role_id", perm.RequireManage(permStore), tenantHandler.AssignRole)
	protected.DELETE("/users/:id/roles/:role_id", perm.RequireManage(permStore), tenantHandler.RevokeRole)
	// Usage answers "how much room is left", which is what makes a quota visible.
	protected.GET("/usage", tenantHandler.Usage)
	protected.GET("/permissions", permHandler.MyPermissions)
	protected.GET("/permissions/check", permHandler.Check)
	// Writing the ACL is what makes a revocation take effect: the handler writes
	// the row and drops the cached decisions in one step, so an operator does not
	// have to know that a Redis key stands between them and the change.
	protected.PUT("/permissions/acl", permHandler.SetACL)
	protected.DELETE("/permissions/acl", permHandler.DeleteACL)

	// File routes carry an ACL guard: RBAC alone would let any user with
	// file.read read every tenant file, which is the thing ACL exists to stop.
	protected.POST("/files", perm.Guard(permStore, perm.ActionWrite, dirOfRequest), fileHandler.Upload)
	protected.GET("/files", perm.Guard(permStore, perm.ActionRead, dirOfRequest), fileHandler.List)
	protected.GET("/files/:id/download", perm.Guard(permStore, perm.ActionRead, pathOfFile(fileService)), fileHandler.Download)
	// HEAD is registered explicitly: gin does not answer a HEAD from the GET
	// handler, and a client that probes a file before resuming (`curl -I`,
	// wget's size check, a player seeking) would otherwise get 404 and assume
	// the file is gone.
	protected.HEAD("/files/:id/download", perm.Guard(permStore, perm.ActionRead, pathOfFile(fileService)), fileHandler.Download)
	protected.DELETE("/files/:id", perm.Guard(permStore, perm.ActionDelete, pathOfFile(fileService)), fileHandler.Delete)

	protected.POST("/uploads", perm.Guard(permStore, perm.ActionWrite, dirOfRequest), chunkHandler.Init)
	// The session routes carry a guard too: an upload session's bytes and the row
	// it finally creates belong to the directory the session names, so the same
	// ACL that protects /files has to protect them. Without it any authenticated
	// user could drive someone else's session to completion.
	pathOfUpload := pathOfSession(chunkStore)
	protected.GET("/uploads/:id", perm.Guard(permStore, perm.ActionRead, pathOfUpload), chunkHandler.Status)
	protected.PUT("/uploads/:id/chunks/:idx", perm.Guard(permStore, perm.ActionWrite, pathOfUpload), chunkHandler.Put)
	protected.POST("/uploads/:id/complete", perm.Guard(permStore, perm.ActionWrite, pathOfUpload), chunkHandler.Complete)
	protected.DELETE("/uploads/:id", perm.Guard(permStore, perm.ActionWrite, pathOfUpload), chunkHandler.Abort)

	stopReclaimer := startReclaimer(chunkService, cfg.Chunk, logger)
	defer stopReclaimer()

	srv := &http.Server{
		Addr:              cfg.Server.Addr,
		Handler:           engine,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return serve(srv, logger)
}

// startReclaimer runs the abandoned-upload sweep until the returned func is
// called. A zero interval disables it, which is what tests want.
func startReclaimer(service *chunk.Service, cfg config.Chunk, logger *slog.Logger) func() {
	if cfg.ReclaimEvery <= 0 {
		return func() {}
	}
	stop := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)
		ticker := time.NewTicker(cfg.ReclaimEvery)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				n, err := service.Reclaim(ctx, cfg.IdleHours)
				cancel()
				if err != nil {
					logger.Error("reclaim abandoned uploads", "err", err)
					continue
				}
				if n > 0 {
					logger.Info("reclaimed abandoned uploads", "count", n)
				}
			}
		}
	}()

	return func() {
		close(stop)
		<-done
	}
}

// dirOfRequest resolves the ACL path for routes that act on a directory rather
// than a stored file: the upload and list endpoints.
func dirOfRequest(c *gin.Context) (string, error) {
	if c.Request.Method == http.MethodPost {
		// The upload endpoints carry dir in the body. Reading it here means the
		// body is parsed twice; the alternative is checking "/" for every upload,
		// which would make the ACL useless for exactly the write path it guards.
		dir := c.PostForm("dir")
		if dir == "" {
			var payload struct {
				Dir string `json:"dir"`
			}
			// A body that is not JSON simply means "root": the handler rejects the
			// request later if it really needed a body.
			if err := c.ShouldBindBodyWithJSON(&payload); err == nil {
				dir = payload.Dir
			}
		}
		return perm.NormalizePath(dir), nil
	}
	return perm.NormalizePath(c.Query("dir")), nil
}

// newProvider builds the storage backend and returns its name, which is what
// gets recorded on each file row.
//
// Two modes, not two backends: cloud is the deployment path, dev is a local
// directory so a checkout runs without a bucket. The distinction matters because
// only cloud is exercised against real infrastructure — dev exists to unblock
// development, and the warning below says so every time it is used.
func newProvider(ctx context.Context, cfg *config.Config, logger *slog.Logger) (storage.Provider, string, error) {
	if cfg.Storage.Mode == config.StorageModeDev {
		logger.Warn("storage.mode=dev: objects are written to a local directory; "+
			"this is for development only and has no redundancy or lifecycle rules",
			"root", cfg.Storage.LocalRoot)
		p, err := storage.NewLocal(cfg.Storage.LocalRoot)
		if err != nil {
			return nil, "", err
		}
		return p, file.StorageLocal, nil
	}
	p, err := storage.NewS3(ctx, storage.S3Config{
		Endpoint:  cfg.Storage.S3.Endpoint,
		AccessKey: os.Getenv("GODOC_S3_ACCESS_KEY"),
		SecretKey: os.Getenv("GODOC_S3_SECRET_KEY"),
		Bucket:    cfg.Storage.S3.Bucket,
		UseSSL:    cfg.Storage.S3.UseSSL,
		Region:    cfg.Storage.S3.Region,
	})
	if err != nil {
		return nil, "", err
	}
	return p, file.StorageS3, nil
}

// pathOfFile resolves the ACL path of an existing file row: its directory, which
// is what the ACL tree is keyed by.
func pathOfFile(files *file.Service) func(*gin.Context) (string, error) {
	return func(c *gin.Context) (string, error) {
		ident, ok := tenant.FromContext(c.Request.Context())
		if !ok {
			return "", errNoIdentity
		}
		id, err := parseIDParam(c)
		if err != nil {
			return "", err
		}
		f, err := files.Get(c.Request.Context(), ident.TenantID, id)
		if err != nil {
			return "", err
		}
		return f.Dir, nil
	}
}

// pathOfSession resolves the ACL path of an upload session: the directory its
// merged file will land in. The lookup is tenant-scoped, so another tenant's id
// is a 404 before the ACL is consulted.
func pathOfSession(sessions *chunk.Store) func(*gin.Context) (string, error) {
	return func(c *gin.Context) (string, error) {
		ident, ok := tenant.FromContext(c.Request.Context())
		if !ok {
			return "", errNoIdentity
		}
		id, err := parseIDParam(c)
		if err != nil {
			return "", err
		}
		sess, err := sessions.Get(c.Request.Context(), ident.TenantID, id)
		if errors.Is(err, chunk.ErrNotFound) {
			return "", httpx.ErrNotFound
		}
		if err != nil {
			return "", err
		}
		return sess.Dir, nil
	}
}

// parseIDParam reads the :id path parameter. A malformed id is a client error,
// and saying so here keeps it out of the 500 path (and out of the 5xx log).
func parseIDParam(c *gin.Context) (int64, error) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, httpx.ErrInvalidRequest
	}
	return id, nil
}

var errNoIdentity = errors.New("no identity in context")

// healthz reports every dependency separately: one broken backend should not hide
// the state of the other, which is the whole point of asking.
func healthz(db *sqlx.DB, rdb *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
		defer cancel()

		status := map[string]string{"mysql": "ok", "redis": "ok"}
		if err := db.PingContext(ctx); err != nil {
			slog.Error("healthz: mysql ping failed", "err", err)
			status["mysql"] = "down"
		}
		if err := rdb.Ping(ctx).Err(); err != nil {
			slog.Error("healthz: redis ping failed", "err", err)
			status["redis"] = "down"
		}

		if status["mysql"] != "ok" || status["redis"] != "ok" {
			c.JSON(http.StatusServiceUnavailable, httpx.Response{
				Code:    http.StatusServiceUnavailable,
				Message: "dependencies unavailable",
				Data:    status,
			})
			return
		}
		httpx.OK(c, status)
	}
}

// serve runs the http server until SIGINT/SIGTERM, then drains connections.
func serve(srv *http.Server, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("http server listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("listen: %w", err)
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
