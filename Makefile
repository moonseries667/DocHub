.PHONY: up down build test run tidy fmt

# Go caches live inside the project. `:=` deliberately overrides an inherited
# GOCACHE/GOMODCACHE: restricted shells hand down paths under D:\Code\Env that are
# not writable, and `?=` would treat those as "already set" and leave builds broken.
# Override on the command line when sharing the central cache is actually wanted:
#   make build GOCACHE=D:\Code\Env\Cache\go-build
export GOCACHE := $(CURDIR)/.gocache
export GOMODCACHE := $(CURDIR)/.gomodcache
export GOPATH := $(CURDIR)/.gopath
# goproxy.cn is the stable mirror here; proxy.golang.org truncates zip downloads.
export GOPROXY := https://goproxy.cn,direct

# Bring up MySQL 8 and Redis 7. Needs Docker; see README for the fallback.
up:
	docker compose -f deployments/docker-compose.yml up -d

down:
	docker compose -f deployments/docker-compose.yml down

# The binary carries a platform suffix so a Windows build and a Linux build in
# the same checkout do not overwrite each other, and so `bin/` says at a glance
# which one it holds. GOEXE is empty on Linux/macOS and ".exe" on Windows.
BIN := bin/godochub$(shell go env GOEXE)

build:
	go build -o $(BIN) ./cmd/server

# -p 1: every integration test drops and recreates the same test database, so
# packages must not run concurrently against it. The timeout covers the 100MB
# chunked round trip that the suite includes.
#
# -count=1 defeats Go's test cache. Without it a re-run reports "ok (cached)" and
# the duration on screen is the previous run's, which reads as a passing suite
# even after the environment changed underneath it.
test:
	go test -count=1 -p 1 -timeout 300s ./...

run:
	go run ./cmd/server -config configs/config.yaml -migrations migrations

# Reminder: nothing above exports the S3 credentials. Local runs need
# GODOC_S3_ACCESS_KEY / GODOC_S3_SECRET_KEY, always: S3 is the only backend.
tidy:
	go mod tidy

fmt:
	gofmt -w ./cmd ./internal
