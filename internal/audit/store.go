package audit

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	db "github.com/SilasSolivagus/base-servers/internal/audit/db"
)

type Store struct {
	pool *pgxpool.Pool
	q    *db.Queries
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool, q: db.New(pool)} }

var genesis = make([]byte, 32)

// Append 在单事务内为同一链的一批事件算哈希链并插入:
// advisory 锁串行化该链写入(跨副本一致),读链头 → 按序算 seq/prev/hash → 插入。
func (s *Store) Append(ctx context.Context, chain string, events []Event) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	qt := s.q.WithTx(tx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('audit:'||$1))`, chain); err != nil {
		return err
	}
	head, err := qt.AuditChainHead(ctx, chain)
	var seq int64
	prev := genesis
	if err == nil {
		seq = head.Seq
		prev = head.Hash
	} else if err != pgx.ErrNoRows {
		return err
	}
	for _, e := range events {
		seq++
		now := time.Now().Truncate(time.Microsecond)
		e.Detail = Redact(e.Detail)
		h := canonicalHash(seq, now.UnixNano(), e, prev)
		detail, _ := json.Marshal(e.Detail)
		if err := qt.InsertAuditEvent(ctx, db.InsertAuditEventParams{
			Chain: chain, Seq: seq, Ts: pgtype.Timestamptz{Time: now, Valid: true},
			ActorID: e.ActorID, ActorType: e.ActorType, SystemAdmin: e.SystemAdmin,
			Action: e.Action, TargetType: e.TargetType, TargetID: e.TargetID, OrgID: e.OrgID,
			Outcome: e.Outcome, Detail: detail, PrevHash: prev, Hash: h,
		}); err != nil {
			return err
		}
		prev = h
	}
	return tx.Commit(ctx)
}

type StoredEvent struct {
	Seq                int64
	Ts                 time.Time
	ActorID, ActorType string
	SystemAdmin        bool
	Action, TargetType string
	TargetID, OrgID    string
	Outcome            string
	Detail             map[string]string
}

type ListFilter struct {
	OrgID, ActorID, Action, Outcome string
	From, To                        time.Time
	Limit                           int32
	AfterSeq                        int64
}

func (s *Store) List(ctx context.Context, f ListFilter) ([]StoredEvent, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 100
	}
	from := f.From
	if from.IsZero() {
		from = time.Unix(0, 0)
	}
	to := f.To
	if to.IsZero() {
		to = time.Now().Add(time.Hour)
	}
	rows, err := s.q.ListAuditEvents(ctx, db.ListAuditEventsParams{
		Column1: f.OrgID, Column2: f.ActorID, Column3: f.Action, Column4: f.Outcome,
		Ts: pgtype.Timestamptz{Time: from, Valid: true}, Ts_2: pgtype.Timestamptz{Time: to, Valid: true},
		Seq: f.AfterSeq, Limit: f.Limit,
	})
	if err != nil {
		return nil, err
	}
	out := make([]StoredEvent, 0, len(rows))
	for _, r := range rows {
		var d map[string]string
		_ = json.Unmarshal(r.Detail, &d)
		out = append(out, StoredEvent{
			Seq: r.Seq, Ts: r.Ts.Time, ActorID: r.ActorID, ActorType: r.ActorType, SystemAdmin: r.SystemAdmin,
			Action: r.Action, TargetType: r.TargetType, TargetID: r.TargetID, OrgID: r.OrgID, Outcome: r.Outcome, Detail: d,
		})
	}
	return out, nil
}
