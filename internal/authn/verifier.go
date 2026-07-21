package authn

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Verifier 验 Keycloak 签的 access token:钉 iss/azp/typ/alg,内网拉 JWKS 并缓存。
type Verifier struct {
	jwksURL    string
	issuer     string
	allowedAzp map[string]bool
	http       *http.Client

	mu                 sync.RWMutex
	keys               map[string]*rsa.PublicKey // kid → key
	fetched            time.Time
	cacheTTL           time.Duration
	minRefreshInterval time.Duration
	lastRefreshAttempt time.Time
}

func NewVerifier(jwksURL, issuer string, allowedAzp []string) *Verifier {
	m := map[string]bool{}
	for _, a := range allowedAzp {
		m[a] = true
	}
	return &Verifier{
		jwksURL: jwksURL, issuer: issuer, allowedAzp: m,
		http:               &http.Client{Timeout: 5 * time.Second},
		keys:               map[string]*rsa.PublicKey{},
		cacheTTL:           5 * time.Minute,
		minRefreshInterval: 15 * time.Second,
	}
}

// tokenClaims:仅取校验所需字段。
type kcClaims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Azp string `json:"azp"`
	Typ string `json:"typ"`
	Exp int64  `json:"exp"`
}

func (v *Verifier) Verify(ctx context.Context, bearer string) (Caller, error) {
	// alg 钉 RS256(拒 none/HS)。
	parsed, err := jwt.ParseSigned(bearer, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return Caller{}, fmt.Errorf("parse token: %w", err)
	}
	if len(parsed.Headers) == 0 {
		return Caller{}, fmt.Errorf("token missing header")
	}
	kid := parsed.Headers[0].KeyID
	pub, err := v.keyFor(ctx, kid)
	if err != nil {
		return Caller{}, err
	}
	var c kcClaims
	if err := parsed.Claims(pub, &c); err != nil {
		return Caller{}, fmt.Errorf("verify signature: %w", err)
	}
	if c.Iss != v.issuer {
		return Caller{}, fmt.Errorf("unexpected issuer %q", c.Iss)
	}
	if c.Typ == "ID" || c.Typ == "id" { // 拒 ID token
		return Caller{}, fmt.Errorf("id token not accepted")
	}
	if !v.allowedAzp[c.Azp] {
		return Caller{}, fmt.Errorf("unexpected azp %q", c.Azp)
	}
	if time.Now().Unix() >= c.Exp {
		return Caller{}, fmt.Errorf("token expired")
	}
	if c.Sub == "" {
		return Caller{}, fmt.Errorf("token missing sub")
	}
	return Caller{PrincipalID: c.Sub}, nil
}

func (v *Verifier) keyFor(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	k := v.keys[kid]
	fresh := k != nil && time.Since(v.fetched) <= v.cacheTTL
	v.mu.RUnlock()
	if fresh {
		return k, nil
	}

	// Throttle outbound JWKS fetches: the kid is read from the JWT header
	// before signature verification, so an anonymous caller sending garbage
	// kids could otherwise force one Keycloak fetch per request. Set
	// lastRefreshAttempt before the fetch so a failing fetch also throttles.
	v.mu.Lock()
	throttled := time.Since(v.lastRefreshAttempt) < v.minRefreshInterval
	if !throttled {
		v.lastRefreshAttempt = time.Now()
	}
	v.mu.Unlock()

	if throttled {
		// A refresh was already attempted recently; don't fire another one.
		// A stale-but-present key can keep being used until the throttle
		// allows a refresh (cacheTTL >> minRefreshInterval, so this only
		// matters right at the staleness boundary). A genuinely unknown kid
		// is unverifiable regardless of a refresh, so fail immediately.
		if k == nil {
			return nil, fmt.Errorf("no JWKS key for kid %q", kid)
		}
		return k, nil
	}

	if err := v.refresh(ctx); err != nil {
		return nil, err
	}
	v.mu.RLock()
	k = v.keys[kid]
	v.mu.RUnlock()
	if k == nil {
		return nil, fmt.Errorf("no JWKS key for kid %q", kid)
	}
	return k, nil
}

func (v *Verifier) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.http.Do(req)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return fmt.Errorf("decode JWKS: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, jwk := range set.Keys {
		if pub, ok := jwk.Key.(*rsa.PublicKey); ok {
			keys[jwk.KeyID] = pub
		}
	}
	v.mu.Lock()
	v.keys = keys
	v.fetched = time.Now()
	v.mu.Unlock()
	return nil
}
