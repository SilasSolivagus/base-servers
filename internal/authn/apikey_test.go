package authn

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/emptypb"
)

type fakeAK struct {
	pid string
	ro  bool
	err error
}

func (f fakeAK) Verify(_ context.Context, _ string) (string, bool, error) {
	return f.pid, f.ro, f.err
}

// TestInterceptorApiKeyBranchSetsCaller exercises authenticate() directly
// (rather than routing a bare connect.NewRequest through WrapUnary, whose
// Spec().Procedure can't be set outside the connect package) to prove a
// bsk_-prefixed bearer token is routed to the API-key verifier and produces
// the expected Caller: PrincipalID + AuthMethod="apikey" + ReadOnly from the
// verifier, and SystemAdmin always false for API-key auth.
func TestInterceptorApiKeyBranchSetsCaller(t *testing.T) {
	ic := &interceptor{ak: fakeAK{pid: "p1", ro: true}}
	h := http.Header{}
	h.Set("Authorization", "Bearer bsk_abc")
	c, err := ic.authenticate(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	if c.PrincipalID != "p1" || c.AuthMethod != "apikey" || !c.ReadOnly || c.SystemAdmin {
		t.Fatalf("apikey caller wrong: %+v", c)
	}
}

// TestInterceptorApiKeyInvalidFailsClosedNoFallback proves that a bsk_-prefixed
// token which fails API-key verification is rejected as Unauthenticated and
// NEVER falls back to the Keycloak verifier. v is left nil: if the
// implementation wrongly fell through to the OIDC path, calling v.Verify on a
// nil *Verifier would panic, so a clean Unauthenticated (no panic) is itself
// part of the proof.
func TestInterceptorApiKeyInvalidFailsClosedNoFallback(t *testing.T) {
	ic := Interceptor(nil, fakeAK{err: errors.New("bad")}, "", nil, nil)
	next := connect.UnaryFunc(func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		t.Fatal("next should not be called for an invalid api key")
		return connect.NewResponse(&emptypb.Empty{}), nil
	})
	req := connect.NewRequest(&emptypb.Empty{})
	req.Header().Set("Authorization", "Bearer bsk_bad")
	_, err := ic.WrapUnary(next)(context.Background(), req)
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}

// TestInterceptorApiKeyUnknownPrefixFallsBackToOIDC proves the routing is on
// the bsk_ prefix specifically: a non-bsk_ bearer token with no ak configured
// falls through to anonymous rejection (no ak branch taken), not a panic or
// unrelated error.
func TestInterceptorApiKeyUnknownPrefixFallsBackToOIDC(t *testing.T) {
	ic := &interceptor{ak: fakeAK{err: errors.New("should not be called")}}
	h := http.Header{}
	h.Set("Authorization", "Bearer not-an-api-key")
	_, err := ic.authenticate(context.Background(), h)
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}

// newTestHandlerServer mounts a single unary procedure, wrapped by ic, on an
// httptest server, and returns a connect client bound to it plus a closer.
// Using a real connect.NewUnaryHandler + connect.NewClient round trip (rather
// than a bare connect.NewRequest) is necessary to exercise a real,
// non-empty req.Spec().Procedure through WrapUnary: connect.Request's spec
// field is unexported and unset by connect.NewRequest, so the read-only gate
// can only be verified end-to-end via an actual RPC.
func newTestHandlerServer(t *testing.T, procedure string, ic connect.Interceptor) (*connect.Client[emptypb.Empty, emptypb.Empty], func()) {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(procedure, connect.NewUnaryHandler(procedure,
		func(ctx context.Context, req *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
			return connect.NewResponse(&emptypb.Empty{}), nil
		},
		connect.WithInterceptors(ic),
	))
	srv := httptest.NewServer(mux)
	client := connect.NewClient[emptypb.Empty, emptypb.Empty](srv.Client(), srv.URL+procedure)
	return client, srv.Close
}

// TestInterceptorReadOnlyGateAllowsReadSafeProcedure proves the ReadOnly gate
// is actually wired into WrapUnary (not just IsReadSafe in isolation): a
// read-only API key can call a real read-safe procedure end-to-end.
func TestInterceptorReadOnlyGateAllowsReadSafeProcedure(t *testing.T) {
	procedure := "/baseservers.v1.AuthzService/Check"
	ic := Interceptor(nil, fakeAK{pid: "p1", ro: true}, "", nil, nil)
	client, closeSrv := newTestHandlerServer(t, procedure, ic)
	defer closeSrv()

	req := connect.NewRequest(&emptypb.Empty{})
	req.Header().Set("Authorization", "Bearer bsk_ok")
	if _, err := client.CallUnary(context.Background(), req); err != nil {
		t.Fatalf("expected read-safe procedure to be allowed for read-only key, got %v", err)
	}
}

// TestInterceptorReadOnlyGateDeniesMutation proves a read-only API key is
// denied PermissionDenied on a real, non-allowlisted (mutation) procedure,
// end-to-end through WrapUnary.
func TestInterceptorReadOnlyGateDeniesMutation(t *testing.T) {
	procedure := "/baseservers.v1.PrincipalService/CreatePrincipal"
	ic := Interceptor(nil, fakeAK{pid: "p1", ro: true}, "", nil, nil)
	client, closeSrv := newTestHandlerServer(t, procedure, ic)
	defer closeSrv()

	req := connect.NewRequest(&emptypb.Empty{})
	req.Header().Set("Authorization", "Bearer bsk_ok")
	_, err := client.CallUnary(context.Background(), req)
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("expected PermissionDenied for mutation via read-only key, got %v", err)
	}
}

// TestInterceptorReadOnlyGateDoesNotBlockWritableKey proves a non-read-only
// (writable) API key is NOT subject to the read-safe allowlist at all: it can
// call the same mutation procedure a read-only key was denied above.
func TestInterceptorReadOnlyGateDoesNotBlockWritableKey(t *testing.T) {
	procedure := "/baseservers.v1.PrincipalService/CreatePrincipal"
	ic := Interceptor(nil, fakeAK{pid: "p1", ro: false}, "", nil, nil)
	client, closeSrv := newTestHandlerServer(t, procedure, ic)
	defer closeSrv()

	req := connect.NewRequest(&emptypb.Empty{})
	req.Header().Set("Authorization", "Bearer bsk_ok")
	if _, err := client.CallUnary(context.Background(), req); err != nil {
		t.Fatalf("expected mutation to be allowed for writable key, got %v", err)
	}
}
