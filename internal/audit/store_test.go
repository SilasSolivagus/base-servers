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
	// 绕过应用直接篡改第 3 条 → Verify 必须抓出
	if _, err := pool.Exec(ctx, `UPDATE audit_events SET outcome='tampered' WHERE chain='o1' AND seq=3`); err != nil {
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
