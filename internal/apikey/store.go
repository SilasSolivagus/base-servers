package apikey

import (
	"context"
	"time"

	"github.com/SilasSolivagus/base-servers/internal/apikey/db"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type StoredKey struct {
	KeyID, PrincipalID, OrgID, Name string
	Hash                            []byte
	HashVersion                     int16
	ReadOnly, Revoked               bool
	CreatedAt                       time.Time
	ExpiresAt, LastUsedAt           *time.Time
}

type NewKey struct {
	KeyID, PrincipalID, OrgID, Name string
	Hash                            []byte
	ReadOnly                        bool
	ExpiresAt                       *time.Time
}

type Store struct{ q *db.Queries }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{q: db.New(pool)} }

func tsPtr(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{Valid: false}
	}
	return pgtype.Timestamptz{Time: *t, Valid: true}
}
func ptrTS(ts pgtype.Timestamptz) *time.Time {
	if !ts.Valid {
		return nil
	}
	t := ts.Time
	return &t
}

func (s *Store) Insert(ctx context.Context, k NewKey) error {
	return s.q.InsertApiKey(ctx, db.InsertApiKeyParams{
		KeyID: k.KeyID, PrincipalID: k.PrincipalID, OrgID: k.OrgID, Name: k.Name,
		Hash: k.Hash, ReadOnly: k.ReadOnly, ExpiresAt: tsPtr(k.ExpiresAt),
	})
}

func row(r db.ApiKey) StoredKey {
	return StoredKey{
		KeyID: r.KeyID, PrincipalID: r.PrincipalID, OrgID: r.OrgID, Name: r.Name,
		Hash: r.Hash, HashVersion: r.HashVersion, ReadOnly: r.ReadOnly, Revoked: r.Revoked,
		CreatedAt: r.CreatedAt.Time, ExpiresAt: ptrTS(r.ExpiresAt), LastUsedAt: ptrTS(r.LastUsedAt),
	}
}

func (s *Store) GetByKeyID(ctx context.Context, keyID string) (StoredKey, error) {
	r, err := s.q.GetApiKey(ctx, keyID)
	if err != nil {
		return StoredKey{}, err
	}
	return row(r), nil
}

func (s *Store) ListByPrincipal(ctx context.Context, principalID string, after *time.Time, limit int32) ([]StoredKey, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := s.q.ListApiKeysByPrincipal(ctx, db.ListApiKeysByPrincipalParams{
		PrincipalID: principalID, Column2: tsPtr(after), Limit: limit,
	})
	if err != nil {
		return nil, err
	}
	out := make([]StoredKey, 0, len(rows))
	for _, r := range rows {
		out = append(out, row(r))
	}
	return out, nil
}

func (s *Store) Revoke(ctx context.Context, keyID string) (StoredKey, error) {
	r, err := s.q.RevokeApiKey(ctx, keyID)
	if err != nil {
		return StoredKey{}, err
	}
	return row(r), nil
}

func (s *Store) TouchLastUsed(ctx context.Context, keyID string) error {
	return s.q.TouchApiKeyLastUsed(ctx, keyID)
}

func (s *Store) CountActive(ctx context.Context, principalID string) (int, error) {
	n, err := s.q.CountActiveApiKeys(ctx, principalID)
	return int(n), err
}
