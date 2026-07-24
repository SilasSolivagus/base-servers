package server

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/SilasSolivagus/base-servers/internal/authn"
	"github.com/SilasSolivagus/base-servers/internal/ratelimit"
)

type RateLimitConfig struct {
	IPLim, GlobalLim ratelimit.Limiter
	TrustedProxies   []*net.IPNet
	RootToken        []byte
	OnThrottle       authn.ThrottleHook
}

// rootAuthCooldown bounds how often a present-but-invalid root token can emit a root.auth
// telemetry event. Without this, a flood of requests carrying a bogus X-BS-Root-Token would
// emit one event per request — before Gate A's buckets even run — filling the async audit
// buffer and starving real security events (spec R12/§7).
const rootAuthCooldown = 60 * time.Second

// rootAuthDebounce tracks the last root.auth emit so it can be rate-limited independently of
// Gate A's IP/global buckets.
type rootAuthDebounce struct {
	mu       sync.Mutex
	lastEmit time.Time
}

func (d *rootAuthDebounce) allow(now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if now.Sub(d.lastEmit) <= rootAuthCooldown {
		return false
	}
	d.lastEmit = now
	return true
}

// RateLimitMiddleware is Gate A: pre-auth per-IP + global token buckets in front of the
// Connect mux. /healthz is exempt; /readyz is NOT (it pings backends). Valid root token
// bypasses; a present-but-invalid root token emits a debounced root.auth event (at most once
// per rootAuthCooldown), since this check runs before the IP/global buckets and is not
// otherwise capped by them.
func RateLimitMiddleware(next http.Handler, cfg RateLimitConfig) http.Handler {
	debounce := &rootAuthDebounce{}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" { // static, no backend — always exempt
			next.ServeHTTP(w, r)
			return
		}
		present, valid := authn.CheckRoot(r.Header, cfg.RootToken)
		if present && !valid && cfg.OnThrottle != nil && debounce.allow(time.Now()) {
			cfg.OnThrottle(r.Context(), authn.ThrottleEvent{Gate: "root.auth", Reason: "invalid_root_token"})
		}
		if present && valid {
			next.ServeHTTP(w, r) // break-glass bypass
			return
		}
		ip := clientIP(r, cfg.TrustedProxies)
		if reject(w, r, cfg.GlobalLim, "global", "global", "", cfg.OnThrottle) {
			return
		}
		if reject(w, r, cfg.IPLim, "ip:"+ipKey(ip), "ip", ipKey(ip), cfg.OnThrottle) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

func reject(w http.ResponseWriter, r *http.Request, lim ratelimit.Limiter, key, gate, ipPrefix string, hook authn.ThrottleHook) bool {
	if lim == nil {
		return false
	}
	ok, retry, transitioned := lim.Allow(key)
	if ok {
		return false
	}
	if retry > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int((retry+time.Second-1)/time.Second)))
	}
	w.WriteHeader(http.StatusTooManyRequests)
	if transitioned && hook != nil {
		hook(r.Context(), authn.ThrottleEvent{Gate: gate, IPPrefix: ipPrefix, Reason: "rate_limited"})
	}
	return true
}

// clientIP returns the client IP host. If RemoteAddr is a trusted proxy, it honors the
// left-most X-Forwarded-For entry; otherwise it uses RemoteAddr. Never panics.
func clientIP(r *http.Request, trusted []*net.IPNet) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(strings.TrimSpace(host))
	if peer != nil && ipTrusted(peer, trusted) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if ip := net.ParseIP(first); ip != nil {
				return ip
			}
		}
	}
	if peer != nil {
		return peer
	}
	return net.IPv4zero
}

func ipTrusted(ip net.IP, trusted []*net.IPNet) bool {
	for _, n := range trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ipKey buckets IPv4 by /24 and IPv6 by /64 so a single large allocation can't spawn
// unbounded distinct buckets. The IPv4 /24 (vs. a /32-per-address bucket) is deliberate:
// it confines an attacker who owns a whole /24 to one shared bucket (evasion-resistance),
// and this same prefix is reused as the audit IP prefix.
func ipKey(ip net.IP) string {
	if ip == nil {
		return "nil"
	}
	if v4 := ip.To4(); v4 != nil {
		return net.IP(append(v4[:3:3], 0)).String() + "/24"
	}
	masked := ip.Mask(net.CIDRMask(64, 128))
	return masked.String() + "/64"
}
