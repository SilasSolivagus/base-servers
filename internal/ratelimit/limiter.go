package ratelimit

import (
	"hash/fnv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const numShards = 256

// Limiter decides whether a keyed request is allowed. Fail-open: Allow never errors.
type Limiter interface {
	// Allow reports whether key may proceed now. retryAfter is a suggested wait until
	// the next token (on denial; it does NOT consume a token). transitioned is true only
	// when this call crosses from "not throttled" into "throttled" AND the per-key cooldown
	// has elapsed (so callers emit at most one audit event per cooldown window).
	Allow(key string) (allowed bool, retryAfter time.Duration, transitioned bool)
	Close()
}

// AllowAll is a Limiter that never limits (used when a gate is disabled).
type AllowAll struct{}

func (AllowAll) Allow(string) (bool, time.Duration, bool) { return true, 0, false }
func (AllowAll) Close()                                   {}

type entry struct {
	lim        *rate.Limiter
	wasLimited bool
	lastEmit   time.Time
}

type shard struct {
	mu    sync.Mutex
	cache *lru
}

// MemoryLimiter is a per-replica, sharded, LRU-bounded token-bucket limiter.
type MemoryLimiter struct {
	rps      rate.Limit
	burst    int
	cooldown time.Duration
	now      func() time.Time
	shards   [numShards]shard
}

func NewMemory(rps float64, burst, maxKeysPerShard int, cooldown time.Duration) *MemoryLimiter {
	return NewMemoryClock(rps, burst, maxKeysPerShard, cooldown, time.Now)
}

func NewMemoryClock(rps float64, burst, maxKeysPerShard int, cooldown time.Duration, now func() time.Time) *MemoryLimiter {
	if burst < 1 {
		burst = 1
	}
	m := &MemoryLimiter{rps: rate.Limit(rps), burst: burst, cooldown: cooldown, now: now}
	for i := range m.shards {
		m.shards[i].cache = newLRU(maxKeysPerShard)
	}
	return m
}

func (m *MemoryLimiter) shardFor(key string) *shard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return &m.shards[h.Sum32()%numShards]
}

func (m *MemoryLimiter) Allow(key string) (bool, time.Duration, bool) {
	now := m.now()
	s := m.shardFor(key)
	s.mu.Lock()
	defer s.mu.Unlock()

	var e *entry
	if v, ok := s.cache.get(key); ok {
		e = v.(*entry)
	} else {
		e = &entry{lim: rate.NewLimiter(m.rps, m.burst)}
		s.cache.put(key, e)
	}

	ok := e.lim.AllowN(now, 1)
	var retryAfter time.Duration
	transitioned := false
	if !ok {
		// Peek the delay without consuming a token (Reserve consumes; Cancel gives it back).
		res := e.lim.ReserveN(now, 1)
		retryAfter = res.DelayFrom(now)
		res.CancelAt(now)
		if !e.wasLimited && now.Sub(e.lastEmit) > m.cooldown {
			transitioned = true
			e.lastEmit = now
		}
		e.wasLimited = true
	} else {
		e.wasLimited = false
	}
	return ok, retryAfter, transitioned
}

// Close is a no-op: the LRU cap bounds memory, so there is no background evictor to stop.
func (m *MemoryLimiter) Close() {}
