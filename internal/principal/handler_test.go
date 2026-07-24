package principal_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"

	v1 "github.com/SilasSolivagus/base-servers/gen/baseservers/v1"
	"github.com/SilasSolivagus/base-servers/gen/baseservers/v1/baseserversv1connect"
	"github.com/SilasSolivagus/base-servers/internal/audit"
	"github.com/SilasSolivagus/base-servers/internal/authn"
	"github.com/SilasSolivagus/base-servers/internal/engine/fake"
	"github.com/SilasSolivagus/base-servers/internal/principal"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

func TestHandlerCreateAndGet(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	svc := principal.NewService(fake.New(), principal.NewStore(pool))
	mux := http.NewServeMux()
	principal.NewHandler(svc, audit.NewRecorder(nil, 1)).Register(mux, connect.WithInterceptors(authn.Interceptor(nil, nil, testsupport.RootToken, nil, nil)))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client := baseserversv1connect.NewPrincipalServiceClient(http.DefaultClient, srv.URL, testsupport.ClientOpts()...)
	created, err := client.CreatePrincipal(context.Background(), connect.NewRequest(&v1.CreatePrincipalRequest{
		Type: v1.PrincipalType_PRINCIPAL_TYPE_AGENT, DisplayName: "planner", OwnerPrincipalId: "u1", Purpose: "triage",
	}))
	if err != nil {
		t.Fatalf("create rpc: %v", err)
	}
	got, err := client.GetPrincipal(context.Background(), connect.NewRequest(&v1.GetPrincipalRequest{
		Id: created.Msg.Principal.Id,
	}))
	if err != nil {
		t.Fatalf("get rpc: %v", err)
	}
	if got.Msg.Principal.OwnerPrincipalId != "u1" {
		t.Fatalf("owner mismatch: %+v", got.Msg.Principal)
	}
	if got.Msg.Principal.Type != v1.PrincipalType_PRINCIPAL_TYPE_AGENT {
		t.Fatalf("type mismatch: %+v", got.Msg.Principal)
	}
	if got.Msg.Principal.DisplayName != "planner" {
		t.Fatalf("display_name mismatch: %+v", got.Msg.Principal)
	}
	if got.Msg.Principal.Purpose != "triage" {
		t.Fatalf("purpose mismatch: %+v", got.Msg.Principal)
	}
}

func TestHandlerCreatePrincipalInvalidInput(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	svc := principal.NewService(fake.New(), principal.NewStore(pool))
	mux := http.NewServeMux()
	principal.NewHandler(svc, audit.NewRecorder(nil, 1)).Register(mux, connect.WithInterceptors(authn.Interceptor(nil, nil, testsupport.RootToken, nil, nil)))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client := baseserversv1connect.NewPrincipalServiceClient(http.DefaultClient, srv.URL, testsupport.ClientOpts()...)
	_, err := client.CreatePrincipal(context.Background(), connect.NewRequest(&v1.CreatePrincipalRequest{
		Type: v1.PrincipalType_PRINCIPAL_TYPE_AGENT, DisplayName: "planner",
	}))
	if err == nil {
		t.Fatal("expected error for agent without owner_principal_id")
	}
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("expected CodeInvalidArgument, got %v: %v", connect.CodeOf(err), err)
	}
}

// CreatePrincipal is a system-capability RPC: only SystemAdmin may call it.
// Call the handler directly (bypassing the wire/interceptor) so we can inject
// a non-admin Caller, which the root-token-only test wire cannot produce.
func TestHandlerCreatePrincipalRequiresSystemAdmin(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	svc := principal.NewService(fake.New(), principal.NewStore(pool))
	h := principal.NewHandler(svc, audit.NewRecorder(nil, 1))

	ctx := authn.WithCaller(context.Background(), authn.Caller{PrincipalID: "not-root", SystemAdmin: false})
	_, err := h.CreatePrincipal(ctx, connect.NewRequest(&v1.CreatePrincipalRequest{
		Type: v1.PrincipalType_PRINCIPAL_TYPE_AGENT, DisplayName: "planner", OwnerPrincipalId: "u1", Purpose: "triage",
	}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v (%v)", connect.CodeOf(err), err)
	}
}

func TestHandlerGetPrincipalNotFound(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	svc := principal.NewService(fake.New(), principal.NewStore(pool))
	mux := http.NewServeMux()
	principal.NewHandler(svc, audit.NewRecorder(nil, 1)).Register(mux, connect.WithInterceptors(authn.Interceptor(nil, nil, testsupport.RootToken, nil, nil)))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client := baseserversv1connect.NewPrincipalServiceClient(http.DefaultClient, srv.URL, testsupport.ClientOpts()...)
	_, err := client.GetPrincipal(context.Background(), connect.NewRequest(&v1.GetPrincipalRequest{
		Id: "does-not-exist",
	}))
	if err == nil {
		t.Fatal("expected error for missing principal")
	}
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("expected CodeNotFound, got %v: %v", connect.CodeOf(err), err)
	}
}
