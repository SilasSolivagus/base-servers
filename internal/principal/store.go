package principal

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/SilasSolivagus/base-servers/internal/engine"
	db "github.com/SilasSolivagus/base-servers/internal/principal/db"
)

// 放在 store.go 顶部
func pgText(s string) pgtype.Text { return pgtype.Text{String: s, Valid: s != ""} }

type Store struct{ q *db.Queries }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{q: db.New(pool)} }

func (s *Store) Insert(ctx context.Context, p Principal) error {
	return s.q.InsertPrincipal(ctx, db.InsertPrincipalParams{
		ID:               p.ID,
		Type:             string(p.Type),
		DisplayName:      p.DisplayName,
		OwnerPrincipalID: pgText(p.OwnerPrincipalID),
		Capabilities:     p.Capabilities,
		Purpose:          p.Purpose,
		OnBehalfOf:       p.OnBehalfOf,
	})
}

func (s *Store) Get(ctx context.Context, id string) (Principal, error) {
	row, err := s.q.GetPrincipal(ctx, id)
	if err != nil {
		return Principal{}, err
	}
	return Principal{
		ID:               row.ID,
		Type:             engine.PrincipalType(row.Type),
		DisplayName:      row.DisplayName,
		OwnerPrincipalID: row.OwnerPrincipalID.String,
		Capabilities:     row.Capabilities,
		Purpose:          row.Purpose,
		OnBehalfOf:       row.OnBehalfOf,
	}, nil
}
