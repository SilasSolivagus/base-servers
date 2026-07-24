package role_test

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
	role.NewHandler(role.NewService(role.NewStore(pool)), org.NewStore(pool), audit.NewRecorder(nil, 1)).Register(mux, connect.WithInterceptors(authn.Interceptor(nil, nil, testsupport.RootToken)))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := baseserversv1connect.NewRoleServiceClient(http.DefaultClient, srv.URL, testsupport.ClientOpts()...)
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
	role.NewHandler(role.NewService(role.NewStore(pool)), org.NewStore(pool), audit.NewRecorder(nil, 1)).Register(mux, connect.WithInterceptors(authn.Interceptor(nil, nil, testsupport.RootToken)))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := baseserversv1connect.NewRoleServiceClient(http.DefaultClient, srv.URL, testsupport.ClientOpts()...)
	_, err := c.AssignRole(context.Background(), connect.NewRequest(&v1.AssignRoleRequest{
		PrincipalId: "u", RoleId: "00000000-0000-0000-0000-000000000000", ScopeType: "planet", ScopeId: "x",
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", connect.CodeOf(err))
	}
}

// CreateRole is org-scoped: a caller must be a member of req.OrgId.
func TestRoleHandlerCreateRoleRequiresMembership(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	orgStore := org.NewStore(pool)
	h := role.NewHandler(role.NewService(role.NewStore(pool)), orgStore, audit.NewRecorder(nil, 1))
	ctx := context.Background()

	orgA, err := orgStore.CreateOrg(ctx, "Tenant A")
	if err != nil {
		t.Fatal(err)
	}
	orgB, err := orgStore.CreateOrg(ctx, "Tenant B")
	if err != nil {
		t.Fatal(err)
	}
	if err := orgStore.AddMember(ctx, "member-a", orgA.ID); err != nil {
		t.Fatal(err)
	}

	crossCtx := authn.WithCaller(ctx, authn.Caller{PrincipalID: "member-a", SystemAdmin: false})
	if _, err := h.CreateRole(crossCtx, connect.NewRequest(&v1.CreateRoleRequest{OrgId: orgB.ID, Name: "editor"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("cross-tenant CreateRole: expected PermissionDenied, got %v (%v)", connect.CodeOf(err), err)
	}

	memberCtx := authn.WithCaller(ctx, authn.Caller{PrincipalID: "member-a", SystemAdmin: false})
	if _, err := h.CreateRole(memberCtx, connect.NewRequest(&v1.CreateRoleRequest{OrgId: orgA.ID, Name: "editor"})); err != nil {
		t.Fatalf("member CreateRole: expected success, got %v", err)
	}

	adminCtx := authn.WithCaller(ctx, authn.Caller{PrincipalID: "root", SystemAdmin: true})
	if _, err := h.CreateRole(adminCtx, connect.NewRequest(&v1.CreateRoleRequest{OrgId: orgB.ID, Name: "viewer"})); err != nil {
		t.Fatalf("SystemAdmin CreateRole: expected success, got %v", err)
	}
}

// AssignRole carries no org_id directly; the handler resolves the role's
// owning org via RoleId and gates on membership in that org.
func TestRoleHandlerAssignRoleRequiresMembership(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	orgStore := org.NewStore(pool)
	roleStore := role.NewStore(pool)
	h := role.NewHandler(role.NewService(roleStore), orgStore, audit.NewRecorder(nil, 1))
	ctx := context.Background()

	orgA, err := orgStore.CreateOrg(ctx, "Tenant A")
	if err != nil {
		t.Fatal(err)
	}
	orgB, err := orgStore.CreateOrg(ctx, "Tenant B")
	if err != nil {
		t.Fatal(err)
	}
	roleB, err := roleStore.CreateRole(ctx, orgB.ID, "editor", []string{"doc.edit"})
	if err != nil {
		t.Fatal(err)
	}
	if err := orgStore.AddMember(ctx, "member-a", orgA.ID); err != nil {
		t.Fatal(err)
	}
	if err := orgStore.AddMember(ctx, "member-b", orgB.ID); err != nil {
		t.Fatal(err)
	}

	// member-a is a member of orgA, but roleB belongs to orgB: denied.
	crossCtx := authn.WithCaller(ctx, authn.Caller{PrincipalID: "member-a", SystemAdmin: false})
	if _, err := h.AssignRole(crossCtx, connect.NewRequest(&v1.AssignRoleRequest{
		PrincipalId: "user-1", RoleId: roleB.ID, ScopeType: "org", ScopeId: orgB.ID,
	})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("cross-tenant AssignRole: expected PermissionDenied, got %v (%v)", connect.CodeOf(err), err)
	}

	memberCtx := authn.WithCaller(ctx, authn.Caller{PrincipalID: "member-b", SystemAdmin: false})
	if _, err := h.AssignRole(memberCtx, connect.NewRequest(&v1.AssignRoleRequest{
		PrincipalId: "user-1", RoleId: roleB.ID, ScopeType: "org", ScopeId: orgB.ID,
	})); err != nil {
		t.Fatalf("member AssignRole: expected success, got %v", err)
	}
}
