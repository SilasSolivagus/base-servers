package audit

import (
	"context"
	"log"
	"sync/atomic"
	"time"

	"github.com/SilasSolivagus/base-servers/internal/authn"
)

// Recorder 是语义点依赖的最小接口:非阻塞记录一条审计事件。
type Recorder interface {
	Record(ctx context.Context, e Event)
}

type queued struct {
	chain string
	e     Event
}

// AsyncRecorder:Record 入带缓冲 channel(非阻塞,满则丢弃计数);Run 后台成批排干、按链哈希链落库。
type AsyncRecorder struct {
	store   *Store
	ch      chan queued
	dropped int64
}

func NewRecorder(store *Store, buf int) *AsyncRecorder {
	if buf <= 0 {
		buf = 4096
	}
	return &AsyncRecorder{store: store, ch: make(chan queued, buf)}
}

// Record 非阻塞:缓冲满即丢弃并计数,永不阻塞、永不报错调用方。
// 若 e.ActorID 未设置,尽力从 ctx 里的 authn.Caller 补齐(ActorID/SystemAdmin);
// 没有 caller 就保持原样(不臆造 ActorType)。
func (r *AsyncRecorder) Record(ctx context.Context, e Event) {
	if e.ActorID == "" {
		if c, ok := authn.CallerFromContext(ctx); ok {
			e.ActorID = c.PrincipalID
			e.SystemAdmin = c.SystemAdmin
		}
	}
	select {
	case r.ch <- queued{chain: ChainOf(e.OrgID), e: e}:
	default:
		if atomic.AddInt64(&r.dropped, 1) == 1 {
			log.Printf("audit: recorder buffer full, dropping events (best-effort, non-blocking)")
		}
	}
}

func (r *AsyncRecorder) Dropped() int64 { return atomic.LoadInt64(&r.dropped) }

// Run 阻塞到 ctx.Done:每次尽量攒一批(同一 tick 内的事件),按 chain 分组,交给 Store.Append。
// ctx.Done 时尽力排干残余(best-effort flush),再返回。
func (r *AsyncRecorder) Run(ctx context.Context) {
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			r.drainAll() // 尽力排干残余(best-effort,不管多少批)
			return
		case q := <-r.ch:
			// 立刻带上这一条,再顺手把 channel 里已排队的一起攒成批
			batch := append([]queued{q}, drainUpTo(r.ch, 255)...)
			r.append(batch)
		case <-tick.C:
			r.flush(256)
		}
	}
}

func (r *AsyncRecorder) flush(n int) {
	batch := drainUpTo(r.ch, n)
	if len(batch) == 0 {
		return
	}
	r.append(batch)
}

// drainAll 反复攒批直到 channel 排空(用于 ctx.Done 时的尽力排干)。
func (r *AsyncRecorder) drainAll() {
	for {
		batch := drainUpTo(r.ch, 256)
		if len(batch) == 0 {
			return
		}
		r.append(batch)
	}
}

func (r *AsyncRecorder) append(batch []queued) {
	byChain := map[string][]Event{}
	for _, q := range batch {
		byChain[q.chain] = append(byChain[q.chain], q.e)
	}
	for chain, evs := range byChain {
		if err := r.store.Append(context.Background(), chain, evs); err != nil {
			log.Printf("audit: append chain %s (%d events) failed: %v", chain, len(evs), err)
		}
	}
}

func drainUpTo(ch chan queued, n int) []queued {
	out := make([]queued, 0, n)
	for i := 0; i < n; i++ {
		select {
		case q := <-ch:
			out = append(out, q)
		default:
			return out
		}
	}
	return out
}
