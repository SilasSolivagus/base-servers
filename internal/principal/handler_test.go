package principal_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"

	v1 "github.com/SilasSolivagus/base-servers/gen/baseservers/v1"
	"github.com/SilasSolivagus/base-servers/gen/baseservers/v1/baseserversv1connect"
	"github.com/SilasSolivagus/base-servers/internal/engine/fake"
	"github.com/SilasSolivagus/base-servers/internal/principal"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

func TestHandlerCreateAndGet(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	svc := principal.NewService(fake.New(), principal.NewStore(pool))
	mux := http.NewServeMux()
	principal.NewHandler(svc).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client := baseserversv1connect.NewPrincipalServiceClient(http.DefaultClient, srv.URL)
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
}
