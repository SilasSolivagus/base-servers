package testsupport

import (
	"context"

	"connectrpc.com/connect"
)

// RootToken is the fixed root token wire/e2e tests use to authenticate
// through the authn interceptor without a real Keycloak token. Wire tests
// pass connect.WithInterceptors(authn.Interceptor(nil, testsupport.RootToken))
// as the server's connect.HandlerOption (kept out of this package to avoid an
// import cycle with internal/authn's own tests, which use testsupport).
const RootToken = "test-root"

// ClientOpts returns the connect.ClientOption(s) wire tests pass to each
// NewXServiceClient so every outgoing request carries the root token header.
func ClientOpts() []connect.ClientOption {
	return []connect.ClientOption{connect.WithInterceptors(rootHeaderInterceptor{})}
}

// rootHeaderInterceptor stamps X-BS-Root-Token onto outgoing client requests
// so wire/e2e tests authenticate as the break-glass root caller.
type rootHeaderInterceptor struct{}

func (rootHeaderInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		req.Header().Set("X-BS-Root-Token", RootToken)
		return next(ctx, req)
	}
}

func (rootHeaderInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (rootHeaderInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}
