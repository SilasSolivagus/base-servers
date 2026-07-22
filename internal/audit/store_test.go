package audit_test

import (
	"context"
	"sync"
	"testing"

	"github.com/SilasSolivagus/base-servers/internal/audit"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

func ev(action, org string) audit.Event {
	return audit.Event{ActorID: "u1", ActorType: audit.ActorHuman, Action: action,
		OrgID: org, Outcome: audit.OutcomeSuccess, Detail: map[string]string{"k": "v"}}
}

func TestStoreAppendChainsSequentially(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	s := audit.NewStore(pool)
	ctx := context.Background()
	if err := s.Append(ctx, "o1", []audit.Event{ev("a", "o1"), ev("b", "o1")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(ctx, "o1", []audit.Event{ev("c", "o1")}); err != nil {
		t.Fatal(err)
	}
	got, err := s.List(ctx, audit.ListFilter{Chain: "o1", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 events, got %d", len(got))
	}
}

func TestStoreAppendConcurrentSameChainNoGap(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	s := audit.NewStore(pool) // 单库,多 goroutine 模拟多副本并发写同一链
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = s.Append(ctx, "o1", []audit.Event{ev("x", "o1")}) }()
	}
	wg.Wait()
	got, _ := s.List(ctx, audit.ListFilter{Chain: "o1", Limit: 100})
	if len(got) != 8 {
		t.Fatalf("want 8, got %d (seq gap/collision under concurrency)", len(got))
	}
}

func TestVerifyDetectsTamper(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	s := audit.NewStore(pool)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if err := s.Append(ctx, "o1", []audit.Event{ev("a", "o1")}); err != nil {
			t.Fatal(err)
		}
	}
	ok, broken, err := s.Verify(ctx, "o1")
	if err != nil || !ok {
		t.Fatalf("intact chain must verify: ok=%v broken=%d err=%v", ok, broken, err)
	}
	// 模拟"拿到 superuser 的越权攻击者":append-only 触发器挡住普通改动,只有
	// superuser 显式 SET session_replication_role=replica 才能绕过触发器直改第 3 条;
	// 哈希链 Verify 仍须抓出——这是与体系结构无关的最后一道防线。三条语句走同一次
	// Exec(simple protocol)在同一连接上执行,末尾复位以免污染连接池。
	if _, err := pool.Exec(ctx, `SET session_replication_role = replica;
		UPDATE audit_events SET outcome='tampered' WHERE chain='o1' AND seq=3;
		SET session_replication_role = DEFAULT`); err != nil {
		t.Fatal(err)
	}
	ok, broken, err = s.Verify(ctx, "o1")
	if err != nil {
		t.Fatal(err)
	}
	if ok || broken != 3 {
		t.Fatalf("tamper at seq 3 must be detected: ok=%v broken=%d", ok, broken)
	}
}

// TestAuditEventsRejectsMutation:append-only 触发器对普通(不绕过)UPDATE/DELETE
// 一律拒绝,即便连的是 owner 角色——这是 DB 层不可变的强制层(design §4.3 / §7)。
func TestAuditEventsRejectsMutation(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	s := audit.NewStore(pool)
	ctx := context.Background()
	if err := s.Append(ctx, "o1", []audit.Event{ev("a", "o1")}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE audit_events SET outcome='x' WHERE chain='o1' AND seq=1`); err == nil {
		t.Fatal("UPDATE on audit_events must be rejected by the append-only trigger")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM audit_events WHERE chain='o1' AND seq=1`); err == nil {
		t.Fatal("DELETE on audit_events must be rejected by the append-only trigger")
	}
	// 行仍在、链仍可验。
	ok, _, err := s.Verify(ctx, "o1")
	if err != nil || !ok {
		t.Fatalf("chain must remain intact and verifiable after rejected mutations: ok=%v err=%v", ok, err)
	}
}
