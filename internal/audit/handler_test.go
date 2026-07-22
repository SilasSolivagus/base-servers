package audit_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/SilasSolivagus/base-servers/gen/baseservers/v1"
	"github.com/SilasSolivagus/base-servers/internal/audit"
	"github.com/SilasSolivagus/base-servers/internal/authn"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

type fakeMembers struct{ member bool }

func (f fakeMembers) IsMember(_ context.Context, _, _ string) (bool, error) { return f.member, nil }

func TestAuditListRequiresMembership(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	s := audit.NewStore(pool)
	_ = s.Append(context.Background(), "o1", []audit.Event{ev("a", "o1")})
	h := audit.NewHandler(s, fakeMembers{member: false})

	// 非成员 → PermissionDenied
	ctx := authn.WithCaller(context.Background(), authn.Caller{PrincipalID: "stranger"})
	_, err := h.List(ctx, connect.NewRequest(&v1.ListRequest{OrgId: "o1"}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-member must be PermissionDenied, got %v", err)
	}

	// 成员 → 拿到事件
	h2 := audit.NewHandler(s, fakeMembers{member: true})
	resp, err := h2.List(authn.WithCaller(context.Background(), authn.Caller{PrincipalID: "u1"}),
		connect.NewRequest(&v1.ListRequest{OrgId: "o1"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Msg.Events) != 1 {
		t.Fatalf("member should see 1 event, got %d", len(resp.Msg.Events))
	}
}

// TestAuditListScopesByChainSymmetricallyWithVerify 复现并锁定 review 发现的
// List/Verify 不对称 bug:List 曾按 org_id 列过滤,Verify/Append 按 chain 过滤,
// 导致 List(org_id="") 退化成无过滤(跨租户泄露),List(org_id="system") 则 0 行。
// 修复后 List 必须与 Verify 一样按 chain 精确匹配。
func TestAuditListScopesByChainSymmetricallyWithVerify(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	s := audit.NewStore(pool)
	ctx := context.Background()
	if err := s.Append(ctx, "o1", []audit.Event{ev("a", "o1"), ev("b", "o1")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(ctx, "o2", []audit.Event{ev("c", "o2")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(ctx, audit.ChainOf(""), []audit.Event{ev("sys1", "")}); err != nil {
		t.Fatal(err)
	}

	h := audit.NewHandler(s, fakeMembers{member: true})
	memberCtx := authn.WithCaller(context.Background(), authn.Caller{PrincipalID: "u1"})
	adminCtx := authn.WithCaller(context.Background(), authn.Caller{SystemAdmin: true})

	// 成员 List(org_id="o1") → 只见 o1,看不到 o2 也看不到 system。
	resp, err := h.List(memberCtx, connect.NewRequest(&v1.ListRequest{OrgId: "o1"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Msg.Events) != 2 {
		t.Fatalf("o1 member should see 2 o1 events, got %d", len(resp.Msg.Events))
	}
	for _, e := range resp.Msg.Events {
		if e.OrgId != "o1" {
			t.Fatalf("cross-tenant leak: got event with org_id=%q while scoped to o1", e.OrgId)
		}
	}

	// admin List(org_id="") → 只见 system 链事件,不是"无过滤"(不含 o1/o2)。
	respEmpty, err := h.List(adminCtx, connect.NewRequest(&v1.ListRequest{OrgId: ""}))
	if err != nil {
		t.Fatal(err)
	}
	if len(respEmpty.Msg.Events) != 1 {
		t.Fatalf(`admin List(org_id="") should see only the 1 system event, got %d`, len(respEmpty.Msg.Events))
	}
	if respEmpty.Msg.Events[0].Action != "sys1" {
		t.Fatalf(`admin List(org_id="") returned wrong event: %+v`, respEmpty.Msg.Events[0])
	}

	// admin List(org_id="system") → 与 org_id="" 结果相同(system 链的显式别名)。
	respSystem, err := h.List(adminCtx, connect.NewRequest(&v1.ListRequest{OrgId: "system"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(respSystem.Msg.Events) != 1 || respSystem.Msg.Events[0].Action != "sys1" {
		t.Fatalf(`admin List(org_id="system") should match List(org_id=""), got %+v`, respSystem.Msg.Events)
	}
}

func TestAuditVerifyOK(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	s := audit.NewStore(pool)
	_ = s.Append(context.Background(), "o1", []audit.Event{ev("a", "o1"), ev("b", "o1")})
	h := audit.NewHandler(s, fakeMembers{member: true})
	resp, err := h.Verify(authn.WithCaller(context.Background(), authn.Caller{PrincipalID: "u1"}),
		connect.NewRequest(&v1.VerifyRequest{OrgId: "o1"}))
	if err != nil || !resp.Msg.Ok {
		t.Fatalf("verify: ok=%v err=%v", resp.Msg.Ok, err)
	}
}
