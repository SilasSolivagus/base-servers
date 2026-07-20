package delegation

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	db "github.com/SilasSolivagus/base-servers/internal/delegation/db"
)

var ErrNotFound = errors.New("delegation not found")

type Store struct{ q *db.Queries }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{q: db.New(pool)} }

func uuid(s string) (pgtype.UUID, error) { var u pgtype.UUID; return u, u.Scan(s) }

func (s *Store) Insert(ctx context.Context, d Delegation) (string, error) {
	oid, err := uuid(d.OrgID)
	if err != nil {
		return "", err
	}
	scope := d.Scope
	if scope == nil {
		scope = []string{}
	}
	row, err := s.q.InsertDelegation(ctx, db.InsertDelegationParams{
		AgentPrincipalID:     d.AgentID,
		DelegatorPrincipalID: d.DelegatorID,
		OrgID:                oid,
		Scope:                scope,
		CnfJkt:               d.CnfJkt,
		ExpiresAt:            pgtype.Timestamptz{Time: d.ExpiresAt, Valid: true},
	})
	if err != nil {
		return "", err
	}
	return row.String(), nil
}

func (s *Store) Get(ctx context.Context, id string) (Delegation, error) {
	uid, err := uuid(id)
	if err != nil {
		return Delegation{}, ErrNotFound
	}
	r, err := s.q.GetDelegation(ctx, uid)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Delegation{}, ErrNotFound
		}
		return Delegation{}, err
	}
	return Delegation{
		ID: r.ID.String(), AgentID: r.AgentPrincipalID, DelegatorID: r.DelegatorPrincipalID,
		OrgID: r.OrgID.String(), Scope: r.Scope, CnfJkt: r.CnfJkt,
		ExpiresAt: r.ExpiresAt.Time, Revoked: r.Revoked,
	}, nil
}

func (s *Store) Revoke(ctx context.Context, id string) error {
	uid, err := uuid(id)
	if err != nil {
		return ErrNotFound
	}
	n, err := s.q.RevokeDelegation(ctx, uid)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
