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

// TestAuditListPaginatesStrictlyOlderEachPage 复现并锁定 review 发现的分页游标
// 方向反了的 bug:ListAuditEvents 的游标谓词曾是 seq > $7,但排序是
// ts DESC, seq DESC(新→旧)。翻页游标本该取"更旧"(seq < cursor),旧谓词却取
// "更新"(seq > cursor),导致深翻页在最新的一页附近打转,永远到不了旧事件。
// 修复后每一页都必须严格比上一页更旧,且全部事件恰好出现一次。
func TestAuditListPaginatesStrictlyOlderEachPage(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	s := audit.NewStore(pool)
	ctx := context.Background()
	const total = 5
	for i := 0; i < total; i++ {
		if err := s.Append(ctx, "o1", []audit.Event{ev("a", "o1")}); err != nil {
			t.Fatal(err)
		}
	}
	h := audit.NewHandler(s, fakeMembers{member: true})
	memberCtx := authn.WithCaller(context.Background(), authn.Caller{PrincipalID: "u1"})

	seen := make(map[int64]bool)
	var afterSeq int64
	prevPageMinSeq := int64(-1) // -1 哨兵:还没有上一页
	pages := 0
	for {
		resp, err := h.List(memberCtx, connect.NewRequest(&v1.ListRequest{
			OrgId: "o1", PageSize: 2, AfterSeq: afterSeq,
		}))
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Msg.Events) == 0 {
			break
		}
		pages++
		if pages > total+2 { // 安全阀:防止回归时在最新页附近打转把测试拖住
			t.Fatalf("paging did not terminate after %d pages (stuck near newest page?) seen=%v", pages, seen)
		}
		pageMaxSeq, pageMinSeq := resp.Msg.Events[0].Seq, resp.Msg.Events[0].Seq
		for _, e := range resp.Msg.Events {
			if seen[e.Seq] {
				t.Fatalf("seq %d returned on more than one page (cursor stuck near newest page): pages=%d", e.Seq, pages)
			}
			seen[e.Seq] = true
			if e.Seq > pageMaxSeq {
				pageMaxSeq = e.Seq
			}
			if e.Seq < pageMinSeq {
				pageMinSeq = e.Seq
			}
		}
		// 核心回归断言:本页的最大 seq 必须严格小于上一页的最小 seq —— 每页都比前一页更旧。
		if prevPageMinSeq != -1 && pageMaxSeq >= prevPageMinSeq {
			t.Fatalf("page %d not strictly older than previous page: pageMaxSeq=%d prevPageMinSeq=%d", pages, pageMaxSeq, prevPageMinSeq)
		}
		prevPageMinSeq = pageMinSeq
		afterSeq = resp.Msg.NextAfterSeq
	}
	if len(seen) != total {
		t.Fatalf("want %d unique events across all pages, got %d: %v", total, len(seen), seen)
	}
	for seq := int64(1); seq <= total; seq++ {
		if !seen[seq] {
			t.Fatalf("seq %d missing from paginated results (gap)", seq)
		}
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
