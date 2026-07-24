package authn

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/SilasSolivagus/base-servers/internal/ratelimit"
)

func TestGateBPerPrincipal(t *testing.T) {
	// prLimiter: 1 rps, burst 1. Build an interceptor with a fake apikey verifier that
	// authenticates any bsk_ token to a fixed principal, so we exercise Gate B post-auth.
	pr := ratelimit.NewMemory(0.0001, 1, 64, time.Minute)
	ic := Interceptor(nil, fakeAK{pid: "p1", ro: false}, "", pr, nil).(*interceptor)
	next := connect.UnaryFunc(func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		return connect.NewResponse(&struct{}{}), nil
	})
	call := func() error {
		req := connect.NewRequest(&struct{}{})
		req.Header().Set("Authorization", "Bearer bsk_x")
		_, err := ic.WrapUnary(next)(context.Background(), req)
		return err
	}
	if err := call(); err != nil {
		t.Fatalf("first call (burst) should pass: %v", err)
	}
	if err := call(); connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("second call should be ResourceExhausted, got %v", err)
	}
}

// TestGateBSharesBucketAcrossAuthMethods proves Gate B keys on
// "pr:"+PrincipalID only (no AuthMethod): the same principal reached via
// apikey on one request and oidc on the next must share a single bucket, not
// get 2x the tokens by alternating auth methods.
//
// Two distinct auth methods are driven end-to-end: the first request
// authenticates via the fake API-key verifier (fakeAK, AuthMethod="apikey");
// the second authenticates via a real *Verifier (see verifier_test.go's
// newTestJWKSVerifier/mustSign/validClaims helpers, same package) presented
// with a self-signed RS256 JWT whose sub is the same principal "p1"
// (AuthMethod="oidc"). Both go through the same interceptor's WrapUnary.
func TestGateBSharesBucketAcrossAuthMethods(t *testing.T) {
	pr := ratelimit.NewMemory(0.0001, 1, 64, time.Minute) // burst 1: exactly one token total
	v, sig, _ := newTestJWKSVerifier(t)
	ic := Interceptor(v, fakeAK{pid: "p1", ro: false}, "", pr, nil).(*interceptor)
	next := connect.UnaryFunc(func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		return connect.NewResponse(&struct{}{}), nil
	})

	// First request: apikey path, principal "p1", consumes the single token.
	req1 := connect.NewRequest(&struct{}{})
	req1.Header().Set("Authorization", "Bearer bsk_x")
	if _, err := ic.WrapUnary(next)(context.Background(), req1); err != nil {
		t.Fatalf("first call (apikey, burst) should pass: %v", err)
	}

	// Second request: oidc path, SAME principal "p1" via a different
	// AuthMethod. If Gate B keyed on AuthMethod too, this would get its own
	// fresh bucket and pass; since it keys on PrincipalID only, it must share
	// the now-exhausted bucket and be denied.
	claims := validClaims()
	claims.Sub = "p1"
	tok := mustSign(t, sig, claims)
	req2 := connect.NewRequest(&struct{}{})
	req2.Header().Set("Authorization", "Bearer "+tok)
	_, err := ic.WrapUnary(next)(context.Background(), req2)
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("second call (oidc, same principal) should be ResourceExhausted (shared bucket), got %v", err)
	}
}

func TestGateBRootBypass(t *testing.T) {
	pr := ratelimit.NewMemory(0.0001, 1, 64, time.Minute)
	ic := Interceptor(nil, nil, "roottok", pr, nil).(*interceptor)
	next := connect.UnaryFunc(func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		return connect.NewResponse(&struct{}{}), nil
	})
	call := func() error {
		req := connect.NewRequest(&struct{}{})
		req.Header().Set("X-BS-Root-Token", "roottok")
		_, err := ic.WrapUnary(next)(context.Background(), req)
		return err
	}
	for i := 0; i < 5; i++ {
		if err := call(); err != nil {
			t.Fatalf("valid root must bypass Gate B (call %d): %v", i, err)
		}
	}
}
