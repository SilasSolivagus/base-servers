package signingkey

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	db "github.com/SilasSolivagus/base-servers/internal/signingkey/db"
)

// ErrNoActive 表示库中当前没有 active 签名键。
var ErrNoActive = errors.New("no active signing key")

// KeyRow 是 signing_keys 一行的领域视图。
type KeyRow struct {
	Kid, Alg, State string
	PrivateEnc      []byte
	RetireAfter     time.Time
}

type Store struct {
	pool *pgxpool.Pool
	q    *db.Queries
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool, q: db.New(pool)} }

func ts(t time.Time) pgtype.Timestamptz {
	if t.IsZero() {
		return pgtype.Timestamptz{Valid: false}
	}
	return pgtype.Timestamptz{Time: t, Valid: true}
}

func (s *Store) Insert(ctx context.Context, r KeyRow) error {
	return s.q.InsertSigningKey(ctx, db.InsertSigningKeyParams{
		Kid: r.Kid, Alg: r.Alg, PrivateEnc: r.PrivateEnc, State: r.State,
		RetireAfter: ts(r.RetireAfter),
	})
}

func (s *Store) GetActive(ctx context.Context) (KeyRow, error) {
	row, err := s.q.GetActiveSigningKey(ctx)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return KeyRow{}, ErrNoActive
		}
		return KeyRow{}, err
	}
	return toKeyRow(row.Kid, row.Alg, row.State, row.PrivateEnc, row.RetireAfter), nil
}

func (s *Store) ListLive(ctx context.Context) ([]KeyRow, error) {
	rows, err := s.q.ListLiveSigningKeys(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]KeyRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, toKeyRow(row.Kid, row.Alg, row.State, row.PrivateEnc, row.RetireAfter))
	}
	return out, nil
}

// Rotate 在单事务内把当前 active 降级为 retiring(带 retire_after),再插入新 active。
// 并发轮换:第二个事务的新 active 插入会撞分区唯一索引而失败 → 收敛到单活跃键。
func (s *Store) Rotate(ctx context.Context, newActive KeyRow, retireAfter time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	qt := s.q.WithTx(tx)
	if err := qt.DemoteActiveSigningKey(ctx, ts(retireAfter)); err != nil {
		return err
	}
	if err := qt.InsertSigningKey(ctx, db.InsertSigningKeyParams{
		Kid: newActive.Kid, Alg: newActive.Alg, PrivateEnc: newActive.PrivateEnc,
		State: "active", RetireAfter: ts(newActive.RetireAfter),
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) RetireExpired(ctx context.Context) (int64, error) {
	return s.q.DeleteExpiredSigningKeys(ctx)
}

func toKeyRow(kid, alg, state string, enc []byte, ra pgtype.Timestamptz) KeyRow {
	r := KeyRow{Kid: kid, Alg: alg, State: state, PrivateEnc: enc}
	if ra.Valid {
		r.RetireAfter = ra.Time
	}
	return r
}
