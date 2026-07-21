package authn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/SilasSolivagus/base-servers/internal/engine/keycloak"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

// 起真 Keycloak、供给 realm+clients、用服务 client 换令牌,验证器应通过并给出 sub。
func TestVerifierAcceptsValidServiceToken(t *testing.T) {
	baseURL, _, user, pass := testsupport.StartKeycloak(t)
	a, _ := keycloak.New(keycloak.Config{
		BaseURL: baseURL, Realm: "base-servers", AdminUser: user, AdminPass: pass,
		LoginClientID: "base-servers-login", LoginRedirectURIs: []string{"https://app/cb"},
		ServiceClientID: "base-servers-service", ServiceClientSecret: "svc-secret-123",
	})
	ctx := context.Background()
	if err := a.EnsureProvisioned(ctx); err != nil {
		t.Fatal(err)
	}
	tok, err := gocloak.NewClient(baseURL).LoginClient(ctx, "base-servers-service", "svc-secret-123", "base-servers")
	if err != nil {
		t.Fatal(err)
	}
	// issuer = Keycloak 自身发出的(测试里无网关/KC_HOSTNAME):用 realm 的实际 issuer。
	issuer := baseURL + "/realms/base-servers"
	jwksURL := baseURL + "/realms/base-servers/protocol/openid-connect/certs"
	v := NewVerifier(jwksURL, issuer, []string{"base-servers-service", "base-servers-login"})

	c, err := v.Verify(ctx, tok.AccessToken)
	if err != nil {
		t.Fatalf("verify valid token: %v", err)
	}
	if c.PrincipalID == "" {
		t.Fatal("expected non-empty sub as PrincipalID")
	}
}

func TestVerifierRejectsGarbageAndWrongIssuer(t *testing.T) {
	v := NewVerifier("http://127.0.0.1:1/certs", "https://issuer.example", []string{"base-servers-service"})
	if _, err := v.Verify(context.Background(), "not.a.jwt"); err == nil {
		t.Fatal("expected garbage token to be rejected")
	}
}

// --- Deterministic unit suite: local JWKS + self-signed tokens, no container needed. ---

const (
	testIssuer = "https://test-issuer"
	testAzp    = "good-azp"
	testKid    = "test-kid-1"
)

// newTestJWKSVerifier generates an RSA keypair, serves its public JWKS from an
// httptest server, and returns a Verifier pointed at it plus a signer for
// minting RS256 tokens with the matching kid.
func newTestJWKSVerifier(t *testing.T) (*Verifier, jose.Signer, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: &priv.PublicKey, KeyID: testKid, Algorithm: "RS256", Use: "sig"},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(srv.Close)

	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", testKid),
	)
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}

	v := NewVerifier(srv.URL, testIssuer, []string{testAzp})
	return v, sig, priv
}

func mustSign(t *testing.T, sig jose.Signer, c kcClaims) string {
	t.Helper()
	tok, err := jwt.Signed(sig).Claims(c).Serialize()
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return tok
}

func validClaims() kcClaims {
	return kcClaims{
		Iss: testIssuer,
		Sub: "user-1",
		Azp: testAzp,
		Typ: "Bearer",
		Exp: time.Now().Add(time.Hour).Unix(),
	}
}

// Guards the happy path itself: a well-formed token from a controlled key
// must verify and yield the correct PrincipalID.
func TestVerifierAcceptsValidLocalToken(t *testing.T) {
	v, sig, _ := newTestJWKSVerifier(t)
	tok := mustSign(t, sig, validClaims())

	c, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("expected valid token to verify, got: %v", err)
	}
	if c.PrincipalID != "user-1" {
		t.Fatalf("expected PrincipalID %q, got %q", "user-1", c.PrincipalID)
	}
}

// Guards the `c.Iss != v.issuer` pin.
func TestVerifierRejectsWrongIssuer(t *testing.T) {
	v, sig, _ := newTestJWKSVerifier(t)
	claims := validClaims()
	claims.Iss = "https://evil"
	tok := mustSign(t, sig, claims)

	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected wrong-issuer token to be rejected")
	}
}

// Guards the `!v.allowedAzp[c.Azp]` pin.
func TestVerifierRejectsWrongAzp(t *testing.T) {
	v, sig, _ := newTestJWKSVerifier(t)
	claims := validClaims()
	claims.Azp = "unknown-client"
	tok := mustSign(t, sig, claims)

	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected wrong-azp token to be rejected")
	}
}

// Guards the `c.Typ == "ID"` pin.
func TestVerifierRejectsIDToken(t *testing.T) {
	v, sig, _ := newTestJWKSVerifier(t)
	claims := validClaims()
	claims.Typ = "ID"
	tok := mustSign(t, sig, claims)

	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected ID token to be rejected")
	}
}

// Guards the `time.Now().Unix() >= c.Exp` pin.
func TestVerifierRejectsExpiredToken(t *testing.T) {
	v, sig, _ := newTestJWKSVerifier(t)
	claims := validClaims()
	claims.Exp = time.Now().Add(-time.Hour).Unix()
	tok := mustSign(t, sig, claims)

	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}

// Guards the `c.Sub == ""` pin.
func TestVerifierRejectsEmptySub(t *testing.T) {
	v, sig, _ := newTestJWKSVerifier(t)
	claims := validClaims()
	claims.Sub = ""
	tok := mustSign(t, sig, claims)

	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected empty-sub token to be rejected")
	}
}

// Guards the parse-time algorithm allow-list (jwt.ParseSigned restricted to
// RS256): an HS256-signed token must never reach signature/claim checks.
func TestVerifierRejectsHS256SignedToken(t *testing.T) {
	v, _, _ := newTestJWKSVerifier(t)
	hsSig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: []byte("0123456789abcdef0123456789abcdef")},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", testKid),
	)
	if err != nil {
		t.Fatalf("build HS256 signer: %v", err)
	}
	tok := mustSign(t, hsSig, validClaims())

	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected HS256-signed token to be rejected")
	}
}

// Guards the JWKS cache TTL: a resident kid must be re-synced against the
// live JWKS at least every cacheTTL, so a revoked/rotated key drops out
// within that bound instead of being trusted forever.
func TestVerifierJWKSCacheExpiresAndRefreshes(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	var mu sync.Mutex
	served := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: &priv.PublicKey, KeyID: testKid, Algorithm: "RS256", Use: "sig"},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cur := served
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cur)
	}))
	t.Cleanup(srv.Close)

	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", testKid),
	)
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}

	v := NewVerifier(srv.URL, testIssuer, []string{testAzp})
	v.cacheTTL = 20 * time.Millisecond          // same-package test: set field directly
	v.minRefreshInterval = 1 * time.Millisecond // don't let the throttle mask the TTL-expiry refetch

	tok := mustSign(t, sig, validClaims())
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("expected initial verify to succeed: %v", err)
	}

	// Simulate revocation: the JWKS endpoint no longer serves this kid.
	mu.Lock()
	served = jose.JSONWebKeySet{}
	mu.Unlock()

	// Immediately after the first fetch the key is still cached (within TTL).
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("expected cached key to still verify within TTL: %v", err)
	}

	time.Sleep(30 * time.Millisecond) // exceed cacheTTL and the refresh throttle

	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected revoked key to be rejected once cache TTL has elapsed")
	}
}

// Guards the pre-auth amplification fix: the kid is read from the JWT header
// before signature verification, so an anonymous caller sending garbage/unknown
// kids must not be able to force a JWKS fetch per request. Two consecutive
// Verify calls with unknown kids should trigger at most one outbound fetch.
func TestVerifierThrottlesJWKSRefreshOnUnknownKid(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		jwks := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{Key: &priv.PublicKey, KeyID: testKid, Algorithm: "RS256", Use: "sig"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(srv.Close)

	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "unknown-kid-does-not-exist"),
	)
	if err != nil {
		t.Fatalf("build signer: %v", err)
	}

	v := NewVerifier(srv.URL, testIssuer, []string{testAzp})
	// Keep the default (production) minRefreshInterval to prove the throttle
	// actually suppresses the second fetch.

	claims := validClaims()
	tok1 := mustSign(t, sig, claims)
	tok2 := mustSign(t, sig, claims)

	if _, err := v.Verify(context.Background(), tok1); err == nil {
		t.Fatal("expected unknown-kid token to be rejected")
	}
	if _, err := v.Verify(context.Background(), tok2); err == nil {
		t.Fatal("expected unknown-kid token to be rejected")
	}

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected exactly 1 JWKS fetch across 2 unknown-kid requests, got %d", got)
	}
}
