package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/SilasSolivagus/base-servers/internal/audit"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

func TestRecorderPersistsAsync(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	s := audit.NewStore(pool)
	r := audit.NewRecorder(s, 1024)
	ctx, cancel := context.WithCancel(context.Background())
	go r.Run(ctx)
	for i := 0; i < 20; i++ {
		r.Record(context.Background(), ev("a", "o1"))
	}
	// 轮询等异步排干
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		got, _ := s.List(context.Background(), audit.ListFilter{OrgID: "o1", Limit: 100})
		if len(got) == 20 {
			cancel()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	t.Fatal("recorder did not persist 20 events in time")
}

func TestRecordIsNonBlockingAndDropsWhenFull(t *testing.T) {
	// buf=1、不启动 Run(排不出去)→ 大量 Record 不能阻塞,超出即丢弃并计数
	r := audit.NewRecorder(nil, 1)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			r.Record(context.Background(), audit.Event{Action: "a", Outcome: audit.OutcomeSuccess})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Record blocked — must be non-blocking")
	}
	if r.Dropped() == 0 {
		t.Fatal("expected drops when buffer full and not draining")
	}
}

// TestRecorderDrainsMultipleChainsAndVerifies 验证批量排干按 chain 正确分组:
// 两个不同 org 的事件交替 Record,排干落库后每条链各自的顺序/哈希链仍然 Verify 通过,
// 且总条数、每链条数都对得上——证明批处理没有把不同链的事件串错组。
func TestRecorderDrainsMultipleChainsAndVerifies(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	s := audit.NewStore(pool)
	r := audit.NewRecorder(s, 1024)
	ctx, cancel := context.WithCancel(context.Background())
	go r.Run(ctx)

	const perOrg = 15
	for i := 0; i < perOrg; i++ {
		r.Record(context.Background(), ev("a1", "orgA"))
		r.Record(context.Background(), ev("b1", "orgB"))
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		gotA, _ := s.List(context.Background(), audit.ListFilter{OrgID: "orgA", Limit: 100})
		gotB, _ := s.List(context.Background(), audit.ListFilter{OrgID: "orgB", Limit: 100})
		if len(gotA) == perOrg && len(gotB) == perOrg {
			cancel()
			okA, badSeqA, err := s.Verify(context.Background(), "orgA")
			if err != nil {
				t.Fatalf("verify orgA: %v", err)
			}
			if !okA {
				t.Fatalf("chain orgA failed to verify at seq %d", badSeqA)
			}
			okB, badSeqB, err := s.Verify(context.Background(), "orgB")
			if err != nil {
				t.Fatalf("verify orgB: %v", err)
			}
			if !okB {
				t.Fatalf("chain orgB failed to verify at seq %d", badSeqB)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	t.Fatal("recorder did not persist events for both orgs in time")
}

// TestRecorderFlushesOnShutdown 验证 ctx 取消时,已入缓冲但还没被排干的事件会被
// best-effort 落库,而不是随 Run 退出被静默丢弃。
func TestRecorderFlushesOnShutdown(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	s := audit.NewStore(pool)
	r := audit.NewRecorder(s, 1024)

	// 先把事件攒进缓冲,此时还没有任何 goroutine 在排干它们。
	const n = 10
	for i := 0; i < n; i++ {
		r.Record(context.Background(), ev("shutdown", "orgS"))
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		r.Run(ctx)
		close(runDone)
	}()
	cancel() // 立刻要求关闭,倒逼走 ctx.Done 的尽力排干路径(或排干竞态下的常规路径)

	select {
	case <-runDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}

	got, err := s.List(context.Background(), audit.ListFilter{OrgID: "orgS", Limit: 100})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != n {
		t.Fatalf("expected %d flushed events on shutdown, got %d", n, len(got))
	}
}
