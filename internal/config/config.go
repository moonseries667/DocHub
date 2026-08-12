package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server    Server    `yaml:"server"`
	MySQL     MySQL     `yaml:"mysql"`
	Redis     Redis     `yaml:"redis"`
	Auth      Auth      `yaml:"auth"`
	Storage   Storage   `yaml:"storage"`
	Chunk     Chunk     `yaml:"chunk"`
	RateLimit RateLimit `yaml:"rate_limit"`
}

type Server struct {
	Addr string `yaml:"addr"`
}

type MySQL struct {
	DSN          string `yaml:"dsn"`
	MaxOpenConns int    `yaml:"max_open_conns"`
	MaxIdleConns int    `yaml:"max_idle_conns"`
}

type Redis struct {
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

type Auth struct {
	JWTSecret string        `yaml:"jwt_secret"`
	TokenTTL  time.Duration `yaml:"token_ttl"`
}

// Storage selects where file bytes live.
//
// Mode is the only switch, and it has exactly two values on purpose:
//
//	cloud (default) — the S3-compatible bucket in S3. This is the deployment path.
//	dev             — a local directory. It exists so a checkout runs without a
//	                  bucket, and the server logs a warning when it is chosen.
//
// A "local" mode is not offered as a third peer of "cloud": two production
// backends means two sets of behaviour to keep honest, and the one nobody
// exercises is the one that breaks.
type Storage struct {
	Mode      string   `yaml:"mode"`
	LocalRoot string   `yaml:"local_root"`
	S3        S3Config `yaml:"s3"`
}

// Storage modes.
const (
	// StorageModeCloud is the S3-compatible bucket: the only deployment target.
	StorageModeCloud = "cloud"
	// StorageModeDev is a local directory, for a checkout with no bucket.
	StorageModeDev = "dev"
)

// S3Config points at the bucket. The credentials are not here on purpose: they
// come from GODOC_S3_ACCESS_KEY / GODOC_S3_SECRET_KEY so a copied yaml never
// carries a secret.
//
// Region is only needed by providers that reject an empty region; Cloudflare R2
// wants "auto", AWS wants a real one. Leave it empty for a self-hosted gateway.
type S3Config struct {
	Endpoint string `yaml:"endpoint"`
	Bucket   string `yaml:"bucket"`
	UseSSL   bool   `yaml:"use_ssl"`
	Region   string `yaml:"region"`
}

// Chunk holds the knobs the resumable upload path needs.
type Chunk struct {
	// TempRoot is where in-flight chunks are staged before the merge.
	TempRoot string `yaml:"temp_root"`
	// PoolSize is the merge verification concurrency.
	PoolSize int `yaml:"pool_size"`
	// IdleHours is how long an untouched upload survives before reclamation.
	IdleHours int `yaml:"idle_hours"`
	// ReclaimEvery is how often the reclaimer runs; 0 disables it.
	ReclaimEvery time.Duration `yaml:"reclaim_every"`
}

// RateLimit is the per-tenant token bucket.
type RateLimit struct {
	// Enabled turns the middleware off, which local work and tests want.
	Enabled bool `yaml:"enabled"`
	// Burst is the bucket capacity: how many requests may arrive back to back.
	Burst int `yaml:"burst"`
	// Window is how long a completely empty bucket takes to refill.
	Window time.Duration `yaml:"window"`
}

func defaults() Config {
	return Config{
		Server: Server{Addr: ":8080"},
		MySQL: MySQL{
			MaxOpenConns: 16,
			MaxIdleConns: 4,
		},
		Redis: Redis{Addr: "127.0.0.1:6379"},
		Auth:  Auth{TokenTTL: 2 * time.Hour},
		Storage: Storage{
			Mode:      StorageModeCloud,
			LocalRoot: "data/files",
			S3: S3Config{
				Endpoint: "127.0.0.1:9000",
				Bucket:   "godochub",
			},
		},
		Chunk: Chunk{
			TempRoot:     "data/chunks",
			PoolSize:     4,
			IdleHours:    24,
			ReclaimEvery: 10 * time.Minute,
		},
		RateLimit: RateLimit{
			Enabled: true,
			Burst:   100,
			Window:  time.Minute,
		},
	}
}

// Load reads the yaml file over the built-in defaults, then lets env vars win.
// Env is applied last on purpose: containers and CI configure by env only.
func Load(path string) (*Config, error) {
	cfg := defaults()

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}

	cfg.applyEnv()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyEnv() {
	if v := os.Getenv("GODOC_SERVER_ADDR"); v != "" {
		c.Server.Addr = v
	}
	if v := os.Getenv("GODOC_MYSQL_DSN"); v != "" {
		c.MySQL.DSN = v
	}
	if v := os.Getenv("GODOC_REDIS_ADDR"); v != "" {
		c.Redis.Addr = v
	}
	if v := os.Getenv("GODOC_REDIS_PASSWORD"); v != "" {
		c.Redis.Password = v
	}
	if v := os.Getenv("GODOC_JWT_SECRET"); v != "" {
		c.Auth.JWTSecret = v
	}
	if v := os.Getenv("GODOC_STORAGE_MODE"); v != "" {
		c.Storage.Mode = v
	}
	if v := os.Getenv("GODOC_STORAGE_LOCAL_ROOT"); v != "" {
		c.Storage.LocalRoot = v
	}
	if v := os.Getenv("GODOC_S3_ENDPOINT"); v != "" {
		c.Storage.S3.Endpoint = v
	}
	if v := os.Getenv("GODOC_S3_BUCKET"); v != "" {
		c.Storage.S3.Bucket = v
	}
	if v := os.Getenv("GODOC_S3_REGION"); v != "" {
		c.Storage.S3.Region = v
	}
	if v := os.Getenv("GODOC_S3_USE_SSL"); v != "" {
		c.Storage.S3.UseSSL = v == "1" || strings.EqualFold(v, "true")
	}
	if v := os.Getenv("GODOC_CHUNK_TEMP_ROOT"); v != "" {
		c.Chunk.TempRoot = v
	}
}

func (c *Config) validate() error {
	if c.Server.Addr == "" {
		return fmt.Errorf("config: server.addr is empty")
	}
	if c.MySQL.DSN == "" {
		return fmt.Errorf("config: mysql.dsn is empty")
	}
	if c.Redis.Addr == "" {
		return fmt.Errorf("config: redis.addr is empty")
	}
	if c.Auth.JWTSecret == "" {
		return fmt.Errorf("config: auth.jwt_secret is empty")
	}
	if c.Auth.TokenTTL <= 0 {
		return fmt.Errorf("config: auth.token_ttl must be positive")
	}
	switch c.Storage.Mode {
	case StorageModeDev:
		// The dev backend needs a directory and nothing else: no bucket, no
		// credentials. This is the whole point of having it.
		if c.Storage.LocalRoot == "" {
			return fmt.Errorf("config: storage.local_root is empty (required when storage.mode is dev)")
		}
	case StorageModeCloud:
		if c.Storage.S3.Endpoint == "" || c.Storage.S3.Bucket == "" {
			return fmt.Errorf("config: storage.s3.endpoint and storage.s3.bucket are required when storage.mode is cloud")
		}
		// The credentials are read from the environment at assembly time, so a
		// missing pair has to be caught there — but catching it here keeps the
		// error next to the settings that caused it.
		if os.Getenv("GODOC_S3_ACCESS_KEY") == "" || os.Getenv("GODOC_S3_SECRET_KEY") == "" {
			return fmt.Errorf("config: GODOC_S3_ACCESS_KEY and GODOC_S3_SECRET_KEY must be set when storage.mode is cloud")
		}
	default:
		return fmt.Errorf("config: storage.mode %q is not supported (cloud|dev)", c.Storage.Mode)
	}
	if c.Chunk.TempRoot == "" {
		return fmt.Errorf("config: chunk.temp_root is empty")
	}
	if c.Chunk.PoolSize <= 0 {
		return fmt.Errorf("config: chunk.pool_size must be positive")
	}
	if c.Chunk.IdleHours <= 0 {
		return fmt.Errorf("config: chunk.idle_hours must be positive")
	}
	if c.RateLimit.Enabled {
		if c.RateLimit.Burst <= 0 {
			return fmt.Errorf("config: rate_limit.burst must be positive")
		}
		if c.RateLimit.Window <= 0 {
			return fmt.Errorf("config: rate_limit.window must be positive")
		}
	}
	return nil
}
