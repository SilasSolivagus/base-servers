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

// Interceptor 认证每个 Connect RPC:Authorization: Bearer <keycloak token> 或
// X-BS-Root-Token <root> 命中即 SystemAdmin;都无 → Unauthenticated。
// 只做 authn;能力/成员/委托授权由各 handler 做。
func Interceptor(v *Verifier, rootToken string) connect.UnaryInterceptorFunc {
	rootBytes := []byte(rootToken)
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			// 1) root-token(仅当已配置)
			if len(rootBytes) > 0 {
				if rt := req.Header().Get("X-BS-Root-Token"); rt != "" &&
					subtle.ConstantTimeCompare([]byte(rt), rootBytes) == 1 {
					return next(WithCaller(ctx, Caller{SystemAdmin: true}), req)
				}
			}
			// 2) bearer token
			auth := req.Header().Get("Authorization")
			if v != nil && strings.HasPrefix(auth, "Bearer ") {
				c, err := v.Verify(ctx, strings.TrimPrefix(auth, "Bearer "))
				if err == nil {
					return next(WithCaller(ctx, c), req)
				}
				return nil, connect.NewError(connect.CodeUnauthenticated, err)
			}
			return nil, connect.NewError(connect.CodeUnauthenticated, errAnonymous)
		}
	}
}
