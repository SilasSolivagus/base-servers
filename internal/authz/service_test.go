package authz

import (
	"context"
	"testing"

	"github.com/SilasSolivagus/base-servers/internal/org"
	"github.com/SilasSolivagus/base-servers/internal/role"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

func TestCheckAllowViaRole(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	ctx := context.Background()
	o, _ := org.NewStore(pool).CreateOrg(ctx, "Acme")
	rs := role.NewStore(pool)
	r, _ := rs.CreateRole(ctx, o.ID, "editor", []string{"doc.edit"})
	_ = rs.AssignRole(ctx, "user-1", r.ID, "org", o.ID)

	svc := NewService(NewStore(pool))
	ok, err := svc.Check(ctx, "user-1", "doc.edit", Resource{Type: "doc", ID: "d1", OrgID: o.ID})
	if err != nil || !ok {
		t.Fatalf("expected allow via role, got ok=%v err=%v", ok, err)
	}
	// 未授予的 action 应拒
	ok, _ = svc.Check(ctx, "user-1", "doc.delete", Resource{Type: "doc", ID: "d1", OrgID: o.ID})
	if ok {
		t.Fatal("expected deny for ungranted action")
	}
}

func TestCheckAllowViaOwnership(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	ctx := context.Background()
	o, _ := org.NewStore(pool).CreateOrg(ctx, "Acme")
	st := NewStore(pool)
	if err := st.RegisterOwnership(ctx, "doc", "d9", "user-2", o.ID); err != nil {
		t.Fatal(err)
	}
	svc := NewService(st)
	ok, err := svc.Check(ctx, "user-2", "doc.delete", Resource{Type: "doc", ID: "d9", OrgID: o.ID})
	if err != nil || !ok {
		t.Fatalf("expected allow via ownership, got ok=%v err=%v", ok, err)
	}
}

func TestCheckDenyStranger(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	ctx := context.Background()
	o, _ := org.NewStore(pool).CreateOrg(ctx, "Acme")
	svc := NewService(NewStore(pool))
	ok, _ := svc.Check(ctx, "stranger", "doc.edit", Resource{Type: "doc", ID: "d1", OrgID: o.ID})
	if ok {
		t.Fatal("expected deny for principal with no role/ownership")
	}
}

func TestCheckAllowViaTeamRole(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	ctx := context.Background()
	o, _ := org.NewStore(pool).CreateOrg(ctx, "Acme")
	team, _ := org.NewStore(pool).CreateTeam(ctx, o.ID, "Eng")
	rs := role.NewStore(pool)
	r, _ := rs.CreateRole(ctx, o.ID, "editor", []string{"doc.edit"})
	if err := rs.AssignRole(ctx, "user-1", r.ID, "team", team.ID); err != nil {
		t.Fatal(err)
	}

	svc := NewService(NewStore(pool))
	ok, err := svc.Check(ctx, "user-1", "doc.edit", Resource{Type: "doc", ID: "d1", OrgID: o.ID, TeamID: team.ID})
	if err != nil || !ok {
		t.Fatalf("expected allow via team role, got ok=%v err=%v", ok, err)
	}
}

func TestCheckTeamRoleDoesNotLeakToOtherTeam(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	ctx := context.Background()
	o, _ := org.NewStore(pool).CreateOrg(ctx, "Acme")
	orgStore := org.NewStore(pool)
	teamA, _ := orgStore.CreateTeam(ctx, o.ID, "Eng")
	teamB, _ := orgStore.CreateTeam(ctx, o.ID, "Sales")
	rs := role.NewStore(pool)
	r, _ := rs.CreateRole(ctx, o.ID, "editor", []string{"doc.edit"})
	if err := rs.AssignRole(ctx, "user-1", r.ID, "team", teamA.ID); err != nil {
		t.Fatal(err)
	}

	svc := NewService(NewStore(pool))

	// team-A grant must not authorize a team-B resource.
	ok, err := svc.Check(ctx, "user-1", "doc.edit", Resource{Type: "doc", ID: "d2", OrgID: o.ID, TeamID: teamB.ID})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected deny: team-A grant leaked to team-B resource")
	}

	// team grant must not authorize an org-level/no-team check either.
	ok, err = svc.Check(ctx, "user-1", "doc.edit", Resource{Type: "doc", ID: "d2", OrgID: o.ID, TeamID: ""})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected deny: team-scoped grant leaked to no-team check")
	}
}

func TestCheckOrgRoleDoesNotLeakToOtherOrg(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	ctx := context.Background()
	orgStore := org.NewStore(pool)
	orgA, _ := orgStore.CreateOrg(ctx, "Acme")
	orgB, _ := orgStore.CreateOrg(ctx, "Globex")
	rs := role.NewStore(pool)
	r, _ := rs.CreateRole(ctx, orgA.ID, "editor", []string{"doc.edit"})
	if err := rs.AssignRole(ctx, "user-1", r.ID, "org", orgA.ID); err != nil {
		t.Fatal(err)
	}

	svc := NewService(NewStore(pool))
	ok, err := svc.Check(ctx, "user-1", "doc.edit", Resource{Type: "doc", ID: "d3", OrgID: orgB.ID})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected deny: org-A grant leaked to org-B resource")
	}
}
