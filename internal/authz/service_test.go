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
