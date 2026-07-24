package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SilasSolivagus/base-servers/internal/authn"
	"github.com/SilasSolivagus/base-servers/internal/ratelimit"
)

func okHandler(hits *int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(hits, 1)
		w.WriteHeader(200)
	})
}

func TestGateAPerIPLimits(t *testing.T) {
	var hits int64
	cfg := RateLimitConfig{
		IPLim:     ratelimit.NewMemory(1, 2, 128, time.Minute), // 2 burst
		GlobalLim: ratelimit.AllowAll{},
	}
	h := RateLimitMiddleware(okHandler(&hits), cfg)

	call := func(ip string) int {
		r := httptest.NewRequest("POST", "/baseservers.v1.OrgService/CreateOrganization", nil)
		r.RemoteAddr = ip + ":12345"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if call("1.2.3.4") != 200 || call("1.2.3.4") != 200 {
		t.Fatal("first 2 from an IP should pass (burst)")
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/baseservers.v1.OrgService/CreateOrganization", nil)
	r.RemoteAddr = "1.2.3.4:1"
	h.ServeHTTP(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("3rd from same IP should be 429, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("429 must carry a Retry-After header")
	}
	if call("9.9.9.9") != 200 {
		t.Fatal("a different IP has its own bucket")
	}
}

func TestGateAHealthzExemptReadyzLimited(t *testing.T) {
	var hits int64
	cfg := RateLimitConfig{IPLim: ratelimit.AllowAll{}, GlobalLim: ratelimit.NewMemory(1, 1, 8, time.Minute)}
	h := RateLimitMiddleware(okHandler(&hits), cfg)
	get := func(path string) int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w.Code
	}
	// /healthz always exempt (static)
	for i := 0; i < 5; i++ {
		if get("/healthz") != 200 {
			t.Fatal("/healthz must never be limited")
		}
	}
	// /readyz still passes the global bucket: 1st ok, 2nd 429 (it pings DB+Keycloak; must not be a free amplifier)
	if get("/readyz") != 200 {
		t.Fatal("first /readyz allowed")
	}
	if get("/readyz") != http.StatusTooManyRequests {
		t.Fatal("/readyz must be subject to the global bucket (flood protection)")
	}
}

func TestGateARootBypassAndUnsetTokenNoBypass(t *testing.T) {
	var hits int64
	// tiny buckets so any non-bypassed call trips immediately
	cfg := RateLimitConfig{
		IPLim: ratelimit.NewMemory(0.0001, 1, 8, time.Minute), GlobalLim: ratelimit.AllowAll{},
		RootToken: []byte("rootsecret"),
	}
	h := RateLimitMiddleware(okHandler(&hits), cfg)
	do := func(tok string) int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/x", nil)
		r.RemoteAddr = "5.5.5.5:1"
		if tok != "" {
			r.Header.Set("X-BS-Root-Token", tok)
		}
		h.ServeHTTP(w, r)
		return w.Code
	}
	do("rootsecret") // consume nothing (bypass)
	if do("rootsecret") != 200 {
		t.Fatal("valid root token bypasses Gate A regardless of rate")
	}
	// without token, same IP is limited (burst 1 already used by... none, so 1 ok then 429)
	do("") // first non-root ok (burst 1)
	if do("") != http.StatusTooManyRequests {
		t.Fatal("non-root traffic is limited")
	}

	// CRITICAL: unset RootToken must NOT let an empty header bypass.
	cfg2 := RateLimitConfig{IPLim: ratelimit.NewMemory(0.0001, 1, 8, time.Minute), GlobalLim: ratelimit.AllowAll{}, RootToken: nil}
	h2 := RateLimitMiddleware(okHandler(&hits), cfg2)
	do2 := func() int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/x", nil)
		r.RemoteAddr = "6.6.6.6:1"
		h2.ServeHTTP(w, r)
		return w.Code
	}
	do2()
	if do2() != http.StatusTooManyRequests {
		t.Fatal("unset root token must NOT bypass Gate A (empty header trap)")
	}
}

func TestGateARootAuthTelemetryOnceOnInvalid(t *testing.T) {
	var events int64
	cfg := RateLimitConfig{
		IPLim: ratelimit.AllowAll{}, GlobalLim: ratelimit.AllowAll{},
		RootToken: []byte("rootsecret"),
		OnThrottle: func(_ context.Context, ev authn.ThrottleEvent) {
			if ev.Gate == "root.auth" {
				atomic.AddInt64(&events, 1)
			}
		},
	}
	h := RateLimitMiddleware(okHandler(new(int64)), cfg)
	send := func(tok string) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/x", nil)
		r.RemoteAddr = "7.7.7.7:1"
		if tok != "" {
			r.Header.Set("X-BS-Root-Token", tok)
		}
		h.ServeHTTP(w, r)
	}
	send("")           // absent → no root.auth event
	send("nope")       // present+invalid → 1 root.auth event
	send("rootsecret") // valid → no event
	if got := atomic.LoadInt64(&events); got != 1 {
		t.Fatalf("expected exactly 1 root.auth event (present+invalid only), got %d", got)
	}
}

func TestGateARootAuthTelemetryDebouncedUnderFlood(t *testing.T) {
	var events int64
	cfg := RateLimitConfig{
		IPLim: ratelimit.AllowAll{}, GlobalLim: ratelimit.AllowAll{},
		RootToken: []byte("rootsecret"),
		OnThrottle: func(_ context.Context, ev authn.ThrottleEvent) {
			if ev.Gate == "root.auth" {
				atomic.AddInt64(&events, 1)
			}
		},
	}
	h := RateLimitMiddleware(okHandler(new(int64)), cfg)
	const n = 50
	for i := 0; i < n; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/x", nil)
		r.RemoteAddr = "8.8.8.8:1"
		r.Header.Set("X-BS-Root-Token", "nope")
		h.ServeHTTP(w, r)
	}
	if got := atomic.LoadInt64(&events); got != 1 {
		t.Fatalf("expected exactly 1 root.auth event across a %d-request flood (debounced), got %d", n, got)
	}
}
