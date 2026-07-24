package authn

import (
	"context"
	"crypto/subtle"
	"net/http"
	"testing"

	"connectrpc.com/connect"
)

// fakeStreamingHandlerConn is a minimal connect.StreamingHandlerConn stand-in
// used only to prove WrapStreamingHandler fails closed without needing a real
// stream transport.
type fakeStreamingHandlerConn struct{}

func (fakeStreamingHandlerConn) Spec() connect.Spec           { return connect.Spec{} }
func (fakeStreamingHandlerConn) Peer() connect.Peer           { return connect.Peer{} }
func (fakeStreamingHandlerConn) Receive(any) error            { return nil }
func (fakeStreamingHandlerConn) RequestHeader() http.Header   { return http.Header{} }
func (fakeStreamingHandlerConn) Send(any) error               { return nil }
func (fakeStreamingHandlerConn) ResponseHeader() http.Header  { return http.Header{} }
func (fakeStreamingHandlerConn) ResponseTrailer() http.Header { return http.Header{} }

// 无令牌无 root → Unauthenticated。
func TestInterceptorRejectsAnonymous(t *testing.T) {
	ic := Interceptor(nil, nil, "root-secret")
	next := connect.UnaryFunc(func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		t.Fatal("next should not be called for anonymous")
		return nil, nil
	})
	req := connect.NewRequest(&struct{}{})
	_, err := ic.WrapUnary(next)(context.Background(), req)
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("want Unauthenticated, got %v", err)
	}
}

// root token 命中 → Caller{SystemAdmin} 入 ctx,next 被调用。
func TestInterceptorRootToken(t *testing.T) {
	ic := Interceptor(nil, nil, "root-secret")
	var got Caller
	next := connect.UnaryFunc(func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		got, _ = CallerFromContext(ctx)
		return connect.NewResponse(&struct{}{}), nil
	})
	req := connect.NewRequest(&struct{}{})
	req.Header().Set("X-BS-Root-Token", "root-secret")
	if _, err := ic.WrapUnary(next)(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if !got.SystemAdmin {
		t.Fatal("expected SystemAdmin caller from root token")
	}
}

// root token 未配置 → 该路径禁用(带 root 头也不放行)。
func TestInterceptorRootDisabledWhenUnset(t *testing.T) {
	ic := Interceptor(nil, nil, "")
	next := connect.UnaryFunc(func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		t.Fatal("next should not be called")
		return nil, nil
	})
	req := connect.NewRequest(&struct{}{})
	req.Header().Set("X-BS-Root-Token", "")
	if _, err := ic.WrapUnary(next)(context.Background(), req); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("want Unauthenticated when root unset, got %v", err)
	}
}

// 未来若挂了 streaming RPC(现有 13 个都是 unary),必须 fail-closed:
// interceptor 没有实现 streaming authn,不能悄悄放行未认证的 stream。
func TestInterceptorRejectsStreaming(t *testing.T) {
	ic := Interceptor(nil, nil, "root-secret")
	next := connect.StreamingHandlerFunc(func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		t.Fatal("next should not be called for a streaming RPC")
		return nil
	})
	err := ic.WrapStreamingHandler(next)(context.Background(), fakeStreamingHandlerConn{})
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("want Unauthenticated for streaming RPC, got %v", err)
	}
}

var _ = subtle.ConstantTimeCompare
