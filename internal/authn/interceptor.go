package authn

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"connectrpc.com/connect"
)

// apikeyPrefix identifies a base-servers API key token (as opposed to an
// OIDC/Keycloak bearer JWT). Routing on this prefix is exclusive: a token
// carrying it is verified ONLY via the API-key path, with no fallback to
// Keycloak on failure (fail-closed).
const apikeyPrefix = "bsk_"

// APIKeyVerifier is the local interface the interceptor depends on for
// API-key verification. Defined here (rather than importing internal/apikey
// directly) to avoid an import cycle: internal/audit already imports
// internal/authn, and internal/apikey depends on internal/audit-adjacent
// packages, so authn must not import apikey. apikey.Verifier satisfies this
// interface structurally.
type APIKeyVerifier interface {
	Verify(ctx context.Context, token string) (principalID string, readOnly bool, err error)
}

// errAnonymous is returned when a request carries neither a valid root token
// nor a valid bearer token.
var errAnonymous = fmt.Errorf("unauthenticated: no credentials")

// errInvalidToken is the generic error returned to callers for any bearer
// token verification failure. The verifier's detailed reason (e.g. issuer
// mismatch, expired token, unknown key, revoked key) is intentionally not
// surfaced to the client to avoid leaking which validation pin failed.
var errInvalidToken = fmt.Errorf("unauthenticated: invalid or expired token")

// errReadOnly is returned when a read-only credential (a read-only API key)
// attempts to invoke a procedure that is not on the explicit read-safe
// allowlist.
var errReadOnly = errors.New("read-only credential may not perform this operation")

// errStreamingUnsupported is returned for any streaming RPC. Interceptor only
// implements unary authn; mounting a streaming RPC without a real streaming
// authn design would otherwise be silently unauthenticated, so streaming
// calls fail closed instead.
var errStreamingUnsupported = fmt.Errorf("unauthenticated: streaming RPCs are not supported by this authn interceptor")

// interceptor 认证每个 Connect RPC:X-BS-Root-Token(→ SystemAdmin)、
// Authorization: Bearer bsk_...(→ API key,exclusive/fail-closed,见 authenticate)、
// 或 Authorization: Bearer <keycloak token>。都无/都验证失败 → Unauthenticated。
// 只做 authn;能力/成员/委托授权由各 handler 做,只读密钥的过程白名单门在此拦截。
type interceptor struct {
	v         *Verifier
	ak        APIKeyVerifier
	rootBytes []byte
}

// Interceptor returns a connect.Interceptor enforcing authn on unary RPCs
// (see interceptor doc above) and fails closed on any streaming RPC, since
// none of the current RPCs stream and a future one must not mount silently
// unauthenticated. ak may be nil, in which case the bsk_ API-key branch is
// disabled and such tokens fall through to errAnonymous/errInvalidToken like
// any other malformed bearer credential.
func Interceptor(v *Verifier, ak APIKeyVerifier, rootToken string) connect.Interceptor {
	return &interceptor{v: v, ak: ak, rootBytes: []byte(rootToken)}
}

// authenticate resolves a Caller from request headers, or returns a connect
// error. Routing is exclusive: a bsk_-prefixed bearer token is handled ONLY
// by the API-key verifier — on failure it returns Unauthenticated directly
// and never falls through to the Keycloak verifier.
func (ic *interceptor) authenticate(ctx context.Context, h http.Header) (Caller, error) {
	// 1) root-token(仅当已配置)
	if _, valid := CheckRoot(h, ic.rootBytes); valid {
		return Caller{SystemAdmin: true, AuthMethod: "root"}, nil
	}
	// 2) bearer token
	auth := h.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		tok := strings.TrimPrefix(auth, "Bearer ")
		// API key: exclusive prefix routing, fail-closed, NO fallback to Keycloak.
		if ic.ak != nil && strings.HasPrefix(tok, apikeyPrefix) {
			pid, ro, err := ic.ak.Verify(ctx, tok)
			if err != nil {
				return Caller{}, connect.NewError(connect.CodeUnauthenticated, errInvalidToken)
			}
			return Caller{PrincipalID: pid, AuthMethod: "apikey", ReadOnly: ro}, nil
		}
		if ic.v != nil {
			c, err := ic.v.Verify(ctx, tok)
			if err != nil {
				return Caller{}, connect.NewError(connect.CodeUnauthenticated, errInvalidToken)
			}
			c.AuthMethod = "oidc"
			return c, nil
		}
	}
	return Caller{}, connect.NewError(connect.CodeUnauthenticated, errAnonymous)
}

func (ic *interceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		c, err := ic.authenticate(ctx, req.Header())
		if err != nil {
			return nil, err
		}
		if c.ReadOnly && !IsReadSafe(req.Spec().Procedure) {
			return nil, connect.NewError(connect.CodePermissionDenied, errReadOnly)
		}
		return next(WithCaller(ctx, c), req)
	}
}

// WrapStreamingHandler fails closed unconditionally: no streaming RPC is
// reachable at all, authenticated or not. None of the currently registered
// RPCs stream, and this interceptor has no streaming authn design, so a
// future streaming RPC must not mount silently (or, worse, silently
// half-authenticated) rather than being rejected outright.
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
