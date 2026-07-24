package ratelimit

import (
	"sync"
	"testing"
	"time"
)

// fixedClock lets tests advance time deterministically.
type fixedClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fixedClock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fixedClock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func TestBurstThenThrottleThenRefill(t *testing.T) {
	clk := &fixedClock{t: time.Unix(1000, 0)}
	// 10 rps, burst 5.
	l := NewMemoryClock(10, 5, 128, time.Minute, clk.now)
	defer l.Close()

	// burst of 5 allowed, 6th denied.
	for i := 0; i < 5; i++ {
		if ok, _, _ := l.Allow("k"); !ok {
			t.Fatalf("burst token %d should be allowed", i)
		}
	}
	ok, retry, _ := l.Allow("k")
	if ok {
		t.Fatal("6th call in same instant must be denied")
	}
	if retry <= 0 {
		t.Fatalf("denied call must report a positive retryAfter, got %v", retry)
	}

	// denials must NOT consume future tokens: after refilling exactly 1 token (100ms at 10rps),
	// exactly one more call should pass regardless of how many denials happened.
	for i := 0; i < 3; i++ {
		l.Allow("k") // 3 more denials
	}
	clk.add(100 * time.Millisecond) // +1 token
	if ok, _, _ := l.Allow("k"); !ok {
		t.Fatal("after 100ms one token should be available (denials must not have consumed it)")
	}
	if ok, _, _ := l.Allow("k"); ok {
		t.Fatal("only one token should have refilled")
	}
}

func TestTransitionedEdgeWithCooldown(t *testing.T) {
	clk := &fixedClock{t: time.Unix(1000, 0)}
	l := NewMemoryClock(1, 1, 128, 60*time.Second, clk.now)
	defer l.Close()
	l.Allow("k") // consume the one token
	_, _, tr1 := l.Allow("k")
	if !tr1 {
		t.Fatal("first denial after allow must transition=true")
	}
	_, _, tr2 := l.Allow("k")
	if tr2 {
		t.Fatal("second denial within cooldown must transition=false")
	}
	clk.add(61 * time.Second) // past cooldown AND refills a token
	l.Allow("k")              // consume refilled token (back under limit)
	_, _, tr3 := l.Allow("k")
	if !tr3 {
		t.Fatal("denial after cooldown elapsed must transition=true again")
	}
}

func TestKeysAreIndependentAndBounded(t *testing.T) {
	l := NewMemory(1, 1, 4, time.Minute) // 4 keys per shard cap
	defer l.Close()
	// distinct keys each get their own bucket
	if ok, _, _ := l.Allow("a"); !ok {
		t.Fatal("key a first call allowed")
	}
	if ok, _, _ := l.Allow("b"); !ok {
		t.Fatal("key b independent, first call allowed")
	}
	// flood distinct keys well past capacity; must not panic/grow unbounded (LRU evicts).
	for i := 0; i < 100000; i++ {
		l.Allow(string(rune(i)))
	}
}

func TestAllowAll(t *testing.T) {
	var l Limiter = AllowAll{}
	for i := 0; i < 1000; i++ {
		if ok, _, tr := l.Allow("x"); !ok || tr {
			t.Fatal("AllowAll must always allow, never transition")
		}
	}
	l.Close()
}

func TestConcurrentRace(t *testing.T) {
	l := NewMemory(1000, 1000, 256, time.Minute)
	defer l.Close()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				l.Allow("shared")
				l.Allow(string(rune(n*1000 + j)))
			}
		}(i)
	}
	wg.Wait()
}
