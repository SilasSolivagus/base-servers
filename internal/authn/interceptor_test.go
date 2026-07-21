package authn

import (
	"context"
	"crypto/subtle"
	"testing"

	"connectrpc.com/connect"
)

// 无令牌无 root → Unauthenticated。
func TestInterceptorRejectsAnonymous(t *testing.T) {
	ic := Interceptor(nil, "root-secret")
	next := connect.UnaryFunc(func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		t.Fatal("next should not be called for anonymous")
		return nil, nil
	})
	req := connect.NewRequest(&struct{}{})
	_, err := ic(next)(context.Background(), req)
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("want Unauthenticated, got %v", err)
	}
}

// root token 命中 → Caller{SystemAdmin} 入 ctx,next 被调用。
func TestInterceptorRootToken(t *testing.T) {
	ic := Interceptor(nil, "root-secret")
	var got Caller
	next := connect.UnaryFunc(func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		got, _ = CallerFromContext(ctx)
		return connect.NewResponse(&struct{}{}), nil
	})
	req := connect.NewRequest(&struct{}{})
	req.Header().Set("X-BS-Root-Token", "root-secret")
	if _, err := ic(next)(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if !got.SystemAdmin {
		t.Fatal("expected SystemAdmin caller from root token")
	}
}

// root token 未配置 → 该路径禁用(带 root 头也不放行)。
func TestInterceptorRootDisabledWhenUnset(t *testing.T) {
	ic := Interceptor(nil, "")
	next := connect.UnaryFunc(func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		t.Fatal("next should not be called")
		return nil, nil
	})
	req := connect.NewRequest(&struct{}{})
	req.Header().Set("X-BS-Root-Token", "")
	if _, err := ic(next)(context.Background(), req); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("want Unauthenticated when root unset, got %v", err)
	}
}

var _ = subtle.ConstantTimeCompare
