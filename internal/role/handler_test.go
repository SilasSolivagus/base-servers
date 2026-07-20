package role_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"

	v1 "github.com/SilasSolivagus/base-servers/gen/baseservers/v1"
	"github.com/SilasSolivagus/base-servers/gen/baseservers/v1/baseserversv1connect"
	"github.com/SilasSolivagus/base-servers/internal/org"
	"github.com/SilasSolivagus/base-servers/internal/role"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

func TestRoleHandlerCreateAndAssign(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	o, err := org.NewStore(pool).CreateOrg(context.Background(), "Acme")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	role.NewHandler(role.NewService(role.NewStore(pool))).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := baseserversv1connect.NewRoleServiceClient(http.DefaultClient, srv.URL)
	r, err := c.CreateRole(context.Background(), connect.NewRequest(&v1.CreateRoleRequest{
		OrgId: o.ID, Name: "editor", Permissions: []string{"doc.edit"},
	}))
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	_, err = c.AssignRole(context.Background(), connect.NewRequest(&v1.AssignRoleRequest{
		PrincipalId: "user-1", RoleId: r.Msg.Role.Id, ScopeType: "org", ScopeId: o.ID,
	}))
	if err != nil {
		t.Fatalf("assign role: %v", err)
	}
}

func TestRoleHandlerRejectsBadScope(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	mux := http.NewServeMux()
	role.NewHandler(role.NewService(role.NewStore(pool))).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := baseserversv1connect.NewRoleServiceClient(http.DefaultClient, srv.URL)
	_, err := c.AssignRole(context.Background(), connect.NewRequest(&v1.AssignRoleRequest{
		PrincipalId: "u", RoleId: "00000000-0000-0000-0000-000000000000", ScopeType: "planet", ScopeId: "x",
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", connect.CodeOf(err))
	}
}
