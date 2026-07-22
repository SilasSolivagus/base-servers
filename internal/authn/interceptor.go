package authn

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"

	"connectrpc.com/connect"
)

// errAnonymous is returned when a request carries neither a valid root token
// nor a valid bearer token.
var errAnonymous = fmt.Errorf("unauthenticated: no credentials")

// errInvalidToken is the generic error returned to callers for any bearer
// token verification failure. The verifier's detailed reason (e.g. issuer
// mismatch, expired token) is intentionally not surfaced to the client to
// avoid leaking which validation pin failed.
var errInvalidToken = fmt.Errorf("unauthenticated: invalid or expired token")

// errStreamingUnsupported is returned for any streaming RPC. Interceptor only
// implements unary authn; mounting a streaming RPC without a real streaming
// authn design would otherwise be silently unauthenticated, so streaming
// calls fail closed instead.
var errStreamingUnsupported = fmt.Errorf("unauthenticated: streaming RPCs are not supported by this authn interceptor")

// interceptor 认证每个 Connect RPC:Authorization: Bearer <keycloak token> 或
// X-BS-Root-Token <root> 命中即 SystemAdmin;都无 → Unauthenticated。
// 只做 authn;能力/成员/委托授权由各 handler 做。
type interceptor struct {
	v         *Verifier
	rootBytes []byte
}

// Interceptor returns a connect.Interceptor enforcing authn on unary RPCs
// (see interceptor doc above) and fails closed on any streaming RPC, since
// none of the 13 current RPCs stream and a future one must not mount
// silently unauthenticated.
func Interceptor(v *Verifier, rootToken string) connect.Interceptor {
	return &interceptor{v: v, rootBytes: []byte(rootToken)}
}

func (ic *interceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		// 1) root-token(仅当已配置)
		if len(ic.rootBytes) > 0 {
			if rt := req.Header().Get("X-BS-Root-Token"); rt != "" &&
				subtle.ConstantTimeCompare([]byte(rt), ic.rootBytes) == 1 {
				return next(WithCaller(ctx, Caller{SystemAdmin: true}), req)
			}
		}
		// 2) bearer token
		auth := req.Header().Get("Authorization")
		if ic.v != nil && strings.HasPrefix(auth, "Bearer ") {
			c, err := ic.v.Verify(ctx, strings.TrimPrefix(auth, "Bearer "))
			if err == nil {
				return next(WithCaller(ctx, c), req)
			}
			return nil, connect.NewError(connect.CodeUnauthenticated, errInvalidToken)
		}
		return nil, connect.NewError(connect.CodeUnauthenticated, errAnonymous)
	}
}

// WrapStreamingHandler fails closed: no streaming RPC is reachable
// unauthenticated. A real streaming authn design is future work.
func (ic *interceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		return connect.NewError(connect.CodeUnauthenticated, errStreamingUnsupported)
	}
}

// WrapStreamingClient passes through unchanged; client-side streaming is not
// this interceptor's concern.
func (ic *interceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}
