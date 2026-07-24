package org_test

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

func TestOrgHandlerCreateAndTeam(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	orgStore := org.NewStore(pool)
	svc := org.NewService(orgStore, role.NewStore(pool))
	mux := http.NewServeMux()
	org.NewHandler(svc, orgStore, audit.NewRecorder(nil, 1)).Register(mux, connect.WithInterceptors(authn.Interceptor(nil, nil, testsupport.RootToken)))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := baseserversv1connect.NewOrgServiceClient(http.DefaultClient, srv.URL, testsupport.ClientOpts()...)
	o, err := c.CreateOrganization(context.Background(), connect.NewRequest(&v1.CreateOrganizationRequest{Name: "Acme"}))
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	if o.Msg.Organization.Id == "" || o.Msg.Organization.Name != "Acme" {
		t.Fatalf("bad org: %+v", o.Msg.Organization)
	}
	tm, err := c.CreateTeam(context.Background(), connect.NewRequest(&v1.CreateTeamRequest{OrgId: o.Msg.Organization.Id, Name: "Eng"}))
	if err != nil {
		t.Fatalf("create team: %v", err)
	}
	if tm.Msg.Team.OrgId != o.Msg.Organization.Id {
		t.Fatalf("team org mismatch: %+v", tm.Msg.Team)
	}
}

func TestOrgHandlerRejectsEmpty(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	orgStore := org.NewStore(pool)
	svc := org.NewService(orgStore, role.NewStore(pool))
	mux := http.NewServeMux()
	org.NewHandler(svc, orgStore, audit.NewRecorder(nil, 1)).Register(mux, connect.WithInterceptors(authn.Interceptor(nil, nil, testsupport.RootToken)))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := baseserversv1connect.NewOrgServiceClient(http.DefaultClient, srv.URL, testsupport.ClientOpts()...)
	_, err := c.CreateOrganization(context.Background(), connect.NewRequest(&v1.CreateOrganizationRequest{Name: ""}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v (%v)", connect.CodeOf(err), err)
	}
}

// CreateOrganization is a system-capability RPC: only SystemAdmin may call it.
func TestOrgHandlerCreateOrganizationRequiresSystemAdmin(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	orgStore := org.NewStore(pool)
	svc := org.NewService(orgStore, role.NewStore(pool))
	h := org.NewHandler(svc, orgStore, audit.NewRecorder(nil, 1))

	ctx := authn.WithCaller(context.Background(), authn.Caller{PrincipalID: "not-root", SystemAdmin: false})
	_, err := h.CreateOrganization(ctx, connect.NewRequest(&v1.CreateOrganizationRequest{Name: "Acme"}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v (%v)", connect.CodeOf(err), err)
	}
}

// CreateTeam, AddMember and AddTeamMember are org-scoped: a caller must be a
// member of the target org. Cross-tenant callers get PermissionDenied; a
// member of the org (or SystemAdmin) is allowed through.
func TestOrgHandlerCreateTeamRequiresMembership(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	orgStore := org.NewStore(pool)
	svc := org.NewService(orgStore, role.NewStore(pool))
	h := org.NewHandler(svc, orgStore, audit.NewRecorder(nil, 1))
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
	if _, err := h.CreateTeam(crossCtx, connect.NewRequest(&v1.CreateTeamRequest{OrgId: orgB.ID, Name: "Eng"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("cross-tenant CreateTeam: expected PermissionDenied, got %v (%v)", connect.CodeOf(err), err)
	}

	memberCtx := authn.WithCaller(ctx, authn.Caller{PrincipalID: "member-a", SystemAdmin: false})
	if _, err := h.CreateTeam(memberCtx, connect.NewRequest(&v1.CreateTeamRequest{OrgId: orgA.ID, Name: "Eng"})); err != nil {
		t.Fatalf("member CreateTeam: expected success, got %v", err)
	}

	adminCtx := authn.WithCaller(ctx, authn.Caller{PrincipalID: "root", SystemAdmin: true})
	if _, err := h.CreateTeam(adminCtx, connect.NewRequest(&v1.CreateTeamRequest{OrgId: orgB.ID, Name: "Sales"})); err != nil {
		t.Fatalf("SystemAdmin CreateTeam: expected success, got %v", err)
	}
}

func TestOrgHandlerAddMemberRequiresMembership(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	orgStore := org.NewStore(pool)
	svc := org.NewService(orgStore, role.NewStore(pool))
	h := org.NewHandler(svc, orgStore, audit.NewRecorder(nil, 1))
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
	if _, err := h.AddMember(crossCtx, connect.NewRequest(&v1.AddMemberRequest{PrincipalId: "newbie", OrgId: orgB.ID})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("cross-tenant AddMember: expected PermissionDenied, got %v (%v)", connect.CodeOf(err), err)
	}

	memberCtx := authn.WithCaller(ctx, authn.Caller{PrincipalID: "member-a", SystemAdmin: false})
	if _, err := h.AddMember(memberCtx, connect.NewRequest(&v1.AddMemberRequest{PrincipalId: "newbie", OrgId: orgA.ID})); err != nil {
		t.Fatalf("member AddMember: expected success, got %v", err)
	}
}

func TestOrgHandlerAddTeamMemberRequiresMembership(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	orgStore := org.NewStore(pool)
	svc := org.NewService(orgStore, role.NewStore(pool))
	h := org.NewHandler(svc, orgStore, audit.NewRecorder(nil, 1))
	ctx := context.Background()

	orgA, err := orgStore.CreateOrg(ctx, "Tenant A")
	if err != nil {
		t.Fatal(err)
	}
	orgB, err := orgStore.CreateOrg(ctx, "Tenant B")
	if err != nil {
		t.Fatal(err)
	}
	teamB, err := orgStore.CreateTeam(ctx, orgB.ID, "Eng")
	if err != nil {
		t.Fatal(err)
	}
	if err := orgStore.AddMember(ctx, "member-a", orgA.ID); err != nil {
		t.Fatal(err)
	}
	if err := orgStore.AddMember(ctx, "member-b", orgB.ID); err != nil {
		t.Fatal(err)
	}

	// member-a belongs to orgA, not orgB (which owns teamB): resolved to
	// orgB via team_id -> org_id, so must be denied cross-tenant.
	crossCtx := authn.WithCaller(ctx, authn.Caller{PrincipalID: "member-a", SystemAdmin: false})
	if _, err := h.AddTeamMember(crossCtx, connect.NewRequest(&v1.AddTeamMemberRequest{PrincipalId: "newbie", TeamId: teamB.ID})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("cross-tenant AddTeamMember: expected PermissionDenied, got %v (%v)", connect.CodeOf(err), err)
	}

	memberCtx := authn.WithCaller(ctx, authn.Caller{PrincipalID: "member-b", SystemAdmin: false})
	if _, err := h.AddTeamMember(memberCtx, connect.NewRequest(&v1.AddTeamMemberRequest{PrincipalId: "newbie", TeamId: teamB.ID})); err != nil {
		t.Fatalf("member AddTeamMember: expected success, got %v", err)
	}
}

// CreateOrganization must emit an org.create audit event on success, with the
// new org's id as both TargetID and OrgID (system-admin-created orgs still
// chain per-org, not into the system chain).
func TestOrgHandlerCreateOrganizationEmitsAuditEvent(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	orgStore := org.NewStore(pool)
	svc := org.NewService(orgStore, role.NewStore(pool))
	rec := &audit.FakeRecorder{}
	h := org.NewHandler(svc, orgStore, rec)

	ctx := authn.WithCaller(context.Background(), authn.Caller{PrincipalID: "root", SystemAdmin: true})
	resp, err := h.CreateOrganization(ctx, connect.NewRequest(&v1.CreateOrganizationRequest{Name: "Acme"}))
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	orgID := resp.Msg.Organization.Id

	var found *audit.Event
	for i := range rec.Events {
		if rec.Events[i].Action == "org.create" {
			found = &rec.Events[i]
		}
	}
	if found == nil {
		t.Fatalf("expected an org.create audit event, got %+v", rec.Events)
	}
	if found.TargetID != orgID || found.OrgID != orgID {
		t.Fatalf("audit event target/org mismatch: %+v (want org id %s)", found, orgID)
	}
	if found.Outcome != audit.OutcomeSuccess {
		t.Fatalf("expected success outcome, got %q", found.Outcome)
	}
}
