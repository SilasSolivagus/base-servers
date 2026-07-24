package authz_test

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
	authz.NewHandler(authz.NewService(st), st, org.NewStore(pool), audit.NewRecorder(nil, 1)).Register(mux, connect.WithInterceptors(authn.Interceptor(nil, nil, testsupport.RootToken, nil, nil)))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := baseserversv1connect.NewAuthzServiceClient(http.DefaultClient, srv.URL, testsupport.ClientOpts()...)
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

func TestAuthzHandlerCheckBadOrgIDIsInvalidArgument(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	ctx := context.Background()
	st := authz.NewStore(pool)
	mux := http.NewServeMux()
	authz.NewHandler(authz.NewService(st), st, org.NewStore(pool), audit.NewRecorder(nil, 1)).Register(mux, connect.WithInterceptors(authn.Interceptor(nil, nil, testsupport.RootToken, nil, nil)))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := baseserversv1connect.NewAuthzServiceClient(http.DefaultClient, srv.URL, testsupport.ClientOpts()...)
	_, err := c.Check(ctx, connect.NewRequest(&v1.CheckRequest{
		Subject: "user-1", Action: "doc.delete", ResourceType: "doc", ResourceId: "d1", OrgId: "not-a-uuid",
	}))
	if err == nil {
		t.Fatal("expected error for malformed org_id")
	}
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("expected CodeInvalidArgument, got %v", connect.CodeOf(err))
	}
}

// Check and RegisterOwnership are org-scoped: a caller must be a member of
// req.OrgId to run permission checks or register ownership within that org.
func TestAuthzHandlerCheckRequiresMembership(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	ctx := context.Background()
	orgStore := org.NewStore(pool)
	st := authz.NewStore(pool)
	h := authz.NewHandler(authz.NewService(st), st, orgStore, audit.NewRecorder(nil, 1))

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
	if _, err := h.Check(crossCtx, connect.NewRequest(&v1.CheckRequest{
		Subject: "member-a", Action: "doc.delete", ResourceType: "doc", ResourceId: "d1", OrgId: orgB.ID,
	})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("cross-tenant Check: expected PermissionDenied, got %v (%v)", connect.CodeOf(err), err)
	}

	memberCtx := authn.WithCaller(ctx, authn.Caller{PrincipalID: "member-a", SystemAdmin: false})
	if _, err := h.Check(memberCtx, connect.NewRequest(&v1.CheckRequest{
		Subject: "member-a", Action: "doc.delete", ResourceType: "doc", ResourceId: "d1", OrgId: orgA.ID,
	})); err != nil {
		t.Fatalf("member Check: expected success, got %v", err)
	}

	adminCtx := authn.WithCaller(ctx, authn.Caller{PrincipalID: "root", SystemAdmin: true})
	if _, err := h.Check(adminCtx, connect.NewRequest(&v1.CheckRequest{
		Subject: "member-a", Action: "doc.delete", ResourceType: "doc", ResourceId: "d1", OrgId: orgB.ID,
	})); err != nil {
		t.Fatalf("SystemAdmin Check: expected success, got %v", err)
	}
}

func TestAuthzHandlerRegisterOwnershipRequiresMembership(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	ctx := context.Background()
	orgStore := org.NewStore(pool)
	st := authz.NewStore(pool)
	h := authz.NewHandler(authz.NewService(st), st, orgStore, audit.NewRecorder(nil, 1))

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
	if _, err := h.RegisterOwnership(crossCtx, connect.NewRequest(&v1.RegisterOwnershipRequest{
		ResourceType: "doc", ResourceId: "d1", OwnerPrincipalId: "member-a", OrgId: orgB.ID,
	})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("cross-tenant RegisterOwnership: expected PermissionDenied, got %v (%v)", connect.CodeOf(err), err)
	}

	memberCtx := authn.WithCaller(ctx, authn.Caller{PrincipalID: "member-a", SystemAdmin: false})
	if _, err := h.RegisterOwnership(memberCtx, connect.NewRequest(&v1.RegisterOwnershipRequest{
		ResourceType: "doc", ResourceId: "d1", OwnerPrincipalId: "member-a", OrgId: orgA.ID,
	})); err != nil {
		t.Fatalf("member RegisterOwnership: expected success, got %v", err)
	}
}
