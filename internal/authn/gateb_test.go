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
