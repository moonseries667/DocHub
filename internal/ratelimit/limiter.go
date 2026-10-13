// Package ratelimit implements a per-tenant token bucket on top of Redis.
//
// One Lua script does the whole read-modify-write so the check is atomic across
// API instances: doing GET then SET from Go would let two concurrent requests
// both observe a full bucket and both pass.
package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/go-redis/redis/v8"
)

// ErrInvalidConfig guards against a bucket that can never refill or never drain.
var ErrInvalidConfig = errors.New("ratelimit: invalid bucket config")

// bucketScript keeps the bucket as two fields in a hash: tokens and the unix
// timestamp (milliseconds) of the last refill.
//
// KEYS[1] bucket key
// ARGV[1] capacity        ARGV[2] refill tokens per second
// ARGV[3] now (ms)        ARGV[4] cost
// Returns {allowed, remaining, retry_after_ms}.
const bucketScript = `
local capacity = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])

local state = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(state[1])
local ts = tonumber(state[2])
if tokens == nil then
  tokens = capacity
  ts = now
end

-- Refill for the elapsed time, capped at capacity.
if now > ts then
  tokens = math.min(capacity, tokens + (now - ts) / 1000.0 * rate)
  ts = now
end

local allowed = 0
local retry = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
else
  -- How long until enough tokens accumulate for this request.
  retry = math.ceil((cost - tokens) / rate * 1000)
end

redis.call('HMSET', KEYS[1], 'tokens', tokens, 'ts', ts)
-- Expire an idle bucket so tenants that stop calling do not leak keys forever.
redis.call('PEXPIRE', KEYS[1], math.ceil(capacity / rate * 1000) + 60000)

return {allowed, math.floor(tokens), retry}
`

// Limiter is one bucket per tenant, sized by capacity and refill rate.
type Limiter struct {
	rdb      *redis.Client
	capacity float64
	rate     float64 // tokens per second
	script   *redis.Script
}

// NewLimiter builds a limiter allowing bursts up to capacity and a sustained
// rate of capacity per window.
func NewLimiter(rdb *redis.Client, capacity int, window time.Duration) (*Limiter, error) {
	if capacity <= 0 || window <= 0 {
		return nil, fmt.Errorf("%w: capacity=%d window=%s", ErrInvalidConfig, capacity, window)
	}
	return &Limiter{
		rdb:      rdb,
		capacity: float64(capacity),
		rate:     float64(capacity) / window.Seconds(),
		script:   redis.NewScript(bucketScript),
	}, nil
}

// Result is the outcome of one check.
type Result struct {
	Allowed    bool
	Remaining  int
	RetryAfter time.Duration
}

// Allow takes one token from the tenant's bucket, or reports how long to wait.
func (l *Limiter) Allow(ctx context.Context, tenantID int64) (Result, error) {
	key := fmt.Sprintf("ratelimit:tenant:%d", tenantID)
	now := time.Now().UnixMilli()

	raw, err := l.script.Run(ctx, l.rdb, []string{key},
		l.capacity, l.rate, now, 1).Result()
	if err != nil {
		return Result{}, fmt.Errorf("run token bucket: %w", err)
	}
	values, ok := raw.([]interface{})
	if !ok || len(values) != 3 {
		return Result{}, fmt.Errorf("token bucket returned %T", raw)
	}

	allowed, err := toInt(values[0])
	if err != nil {
		return Result{}, fmt.Errorf("parse allowed: %w", err)
	}
	remaining, err := toInt(values[1])
	if err != nil {
		return Result{}, fmt.Errorf("parse remaining: %w", err)
	}
	retryMs, err := toInt(values[2])
	if err != nil {
		return Result{}, fmt.Errorf("parse retry: %w", err)
	}

	return Result{
		Allowed:    allowed == 1,
		Remaining:  remaining,
		RetryAfter: time.Duration(retryMs) * time.Millisecond,
	}, nil
}

// Reset drops a tenant's bucket, which tests use to get a clean slate.
func (l *Limiter) Reset(ctx context.Context, tenantID int64) error {
	return l.rdb.Del(ctx, fmt.Sprintf("ratelimit:tenant:%d", tenantID)).Err()
}

func toInt(v interface{}) (int, error) {
	switch n := v.(type) {
	case int64:
		return int(n), nil
	case string:
		parsed, err := strconv.Atoi(n)
		return parsed, err
	case []byte:
		parsed, err := strconv.Atoi(string(n))
		return parsed, err
	default:
		f, ok := v.(float64)
		if !ok {
			return 0, fmt.Errorf("unexpected type %T", v)
		}
		return int(math.Round(f)), nil
	}
}
