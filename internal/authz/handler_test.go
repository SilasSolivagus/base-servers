package authz_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"

	v1 "github.com/SilasSolivagus/base-servers/gen/baseservers/v1"
	"github.com/SilasSolivagus/base-servers/gen/baseservers/v1/baseserversv1connect"
	"github.com/SilasSolivagus/base-servers/internal/authz"
	"github.com/SilasSolivagus/base-servers/internal/org"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

func TestAuthzHandlerRegisterThenCheck(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	ctx := context.Background()
	o, _ := org.NewStore(pool).CreateOrg(ctx, "Acme")
	st := authz.NewStore(pool)
	mux := http.NewServeMux()
	authz.NewHandler(authz.NewService(st), st).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := baseserversv1connect.NewAuthzServiceClient(http.DefaultClient, srv.URL)
	_, err := c.RegisterOwnership(ctx, connect.NewRequest(&v1.RegisterOwnershipRequest{
		ResourceType: "doc", ResourceId: "d1", OwnerPrincipalId: "user-1", OrgId: o.ID,
	}))
	if err != nil {
		t.Fatalf("register ownership: %v", err)
	}
	resp, err := c.Check(ctx, connect.NewRequest(&v1.CheckRequest{
		Subject: "user-1", Action: "doc.delete", ResourceType: "doc", ResourceId: "d1", OrgId: o.ID,
	}))
	if err != nil || !resp.Msg.Allowed {
		t.Fatalf("expected allowed, got %v err=%v", resp.Msg.Allowed, err)
	}
	deny, _ := c.Check(ctx, connect.NewRequest(&v1.CheckRequest{
		Subject: "user-2", Action: "doc.delete", ResourceType: "doc", ResourceId: "d1", OrgId: o.ID,
	}))
	if deny.Msg.Allowed {
		t.Fatal("expected deny for non-owner without role")
	}
}
