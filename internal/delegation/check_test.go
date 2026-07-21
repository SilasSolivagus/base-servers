package delegation

import (
	"context"
	"testing"
	"time"

	"github.com/SilasSolivagus/base-servers/internal/authz"
	"github.com/SilasSolivagus/base-servers/internal/org"
	"github.com/SilasSolivagus/base-servers/internal/role"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

func TestCheckDelegatedAllowWithinDelegatorAndScope(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	ctx := context.Background()
	o, _ := org.NewStore(pool).CreateOrg(ctx, "Acme")
	rs := role.NewStore(pool)
	r, _ := rs.CreateRole(ctx, o.ID, "editor", []string{"doc.edit"})
	_ = rs.AssignRole(ctx, "u1", r.ID, "org", o.ID) // delegator u1 可 doc.edit
	sig := NewSigner("base-servers", testKeyset(t))
	st := NewStore(pool)
	chk := NewChecker(st, sig, authz.NewService(authz.NewStore(pool)))
	// 签一枚:agent ag1 代表 u1,scope=[doc.edit]
	tok, _ := issueTestToken(t, st, sig, "ag1", "u1", o.ID, []string{"doc.edit"})

	res := authz.Resource{Type: "doc", ID: "d1", OrgID: o.ID}
	ok, err := chk.CheckDelegated(ctx, tok, "doc.edit", res)
	if err != nil || !ok {
		t.Fatalf("expected allow, got %v %v", ok, err)
	}
	// 越范围:delegator 有 doc.edit 但 scope 不含 doc.delete → deny
	ok, _ = chk.CheckDelegated(ctx, tok, "doc.delete", res)
	if ok {
		t.Fatal("expected deny: action outside delegation scope")
	}
}

func TestCheckDelegatedDenyWhenDelegatorLacksPerm(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	ctx := context.Background()
	o, _ := org.NewStore(pool).CreateOrg(ctx, "Acme")
	sig := NewSigner("base-servers", testKeyset(t))
	st := NewStore(pool)
	chk := NewChecker(st, sig, authz.NewService(authz.NewStore(pool)))
	// delegator u2 没有任何角色;scope 含 doc.edit 也不行
	tok, _ := issueTestToken(t, st, sig, "ag1", "u2", o.ID, []string{"doc.edit"})
	ok, _ := chk.CheckDelegated(ctx, tok, "doc.edit", authz.Resource{Type: "doc", ID: "d1", OrgID: o.ID})
	if ok {
		t.Fatal("expected deny: delegator lacks the permission (agent cannot exceed delegator)")
	}
}

func TestCheckDelegatedDenyAfterRevoke(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	ctx := context.Background()
	o, _ := org.NewStore(pool).CreateOrg(ctx, "Acme")
	rs := role.NewStore(pool)
	r, _ := rs.CreateRole(ctx, o.ID, "editor", []string{"doc.edit"})
	_ = rs.AssignRole(ctx, "u1", r.ID, "org", o.ID)
	sig := NewSigner("base-servers", testKeyset(t))
	st := NewStore(pool)
	chk := NewChecker(st, sig, authz.NewService(authz.NewStore(pool)))
	tok, id := issueTestToken(t, st, sig, "ag1", "u1", o.ID, []string{"doc.edit"})
	res := authz.Resource{Type: "doc", ID: "d1", OrgID: o.ID}
	if ok, _ := chk.CheckDelegated(ctx, tok, "doc.edit", res); !ok {
		t.Fatal("precondition: should allow before revoke")
	}
	_ = st.Revoke(ctx, id)
	if ok, _ := chk.CheckDelegated(ctx, tok, "doc.edit", res); ok {
		t.Fatal("expected deny after revoke")
	}
}

func TestCheckDelegatedIgnoresAgentOwnRoles(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	ctx := context.Background()
	o, _ := org.NewStore(pool).CreateOrg(ctx, "Acme")
	rs := role.NewStore(pool)
	// agent ag1 有自己的组织角色(doc.edit),但 delegator u2 没有任何角色
	r, _ := rs.CreateRole(ctx, o.ID, "editor", []string{"doc.edit"})
	_ = rs.AssignRole(ctx, "ag1", r.ID, "org", o.ID)
	sig := NewSigner("base-servers", testKeyset(t))
	st := NewStore(pool)
	chk := NewChecker(st, sig, authz.NewService(authz.NewStore(pool)))
	tok, _ := issueTestToken(t, st, sig, "ag1", "u2", o.ID, []string{"doc.edit"})

	ok, err := chk.CheckDelegated(ctx, tok, "doc.edit", authz.Resource{Type: "doc", ID: "d1", OrgID: o.ID})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected deny: agent's own roles must not grant delegated access (confused deputy)")
	}
}

func TestCheckDelegatedNarrowsWhenDelegatorRoleRevoked(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	ctx := context.Background()
	o, _ := org.NewStore(pool).CreateOrg(ctx, "Acme")
	rs := role.NewStore(pool)
	r, _ := rs.CreateRole(ctx, o.ID, "editor", []string{"doc.edit"})
	_ = rs.AssignRole(ctx, "u1", r.ID, "org", o.ID)
	sig := NewSigner("base-servers", testKeyset(t))
	st := NewStore(pool)
	chk := NewChecker(st, sig, authz.NewService(authz.NewStore(pool)))
	tok, _ := issueTestToken(t, st, sig, "ag1", "u1", o.ID, []string{"doc.edit"})
	res := authz.Resource{Type: "doc", ID: "d1", OrgID: o.ID}

	if ok, _ := chk.CheckDelegated(ctx, tok, "doc.edit", res); !ok {
		t.Fatal("precondition: should allow before revoking delegator's role")
	}

	// 直接删除授权人的角色分配,模拟其底层权限被撤销(委托记录本身未撤销)
	_, err := pool.Exec(ctx, "DELETE FROM role_assignments WHERE principal_id = $1", "u1")
	if err != nil {
		t.Fatal(err)
	}

	if ok, _ := chk.CheckDelegated(ctx, tok, "doc.edit", res); ok {
		t.Fatal("expected deny: enforcement must use delegator's CURRENT permissions, not a snapshot")
	}
}

func issueTestToken(t *testing.T, st *Store, sig *Signer, agent, delegator, orgID string, scope []string) (string, string) {
	t.Helper()
	exp := time.Now().Add(5 * time.Minute)
	id, err := st.Insert(context.Background(), Delegation{
		AgentID: agent, DelegatorID: delegator, OrgID: orgID, Scope: scope, ExpiresAt: exp,
	})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := sig.Sign(Claims{Subject: agent, Delegator: delegator, DelegationID: id,
		Scope: scope, OrgID: orgID, IssuedAt: time.Now(), ExpiresAt: exp})
	if err != nil {
		t.Fatal(err)
	}
	return tok, id
}
