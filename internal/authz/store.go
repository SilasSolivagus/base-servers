package authz

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	db "github.com/SilasSolivagus/base-servers/internal/authz/db"
)

var ErrInvalidInput = errors.New("invalid authz input")

type Store struct{ q *db.Queries }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{q: db.New(pool)} }

func uuid(s string) (pgtype.UUID, error) {
	var u pgtype.UUID
	err := u.Scan(s)
	return u, err
}

func (s *Store) RegisterOwnership(ctx context.Context, resType, resID, owner, orgID string) error {
	oid, err := uuid(orgID)
	if err != nil {
		return fmt.Errorf("%w: bad org id: %v", ErrInvalidInput, err)
	}
	return s.q.RegisterOwnership(ctx, db.RegisterOwnershipParams{
		ResourceType: resType, ResourceID: resID, OwnerPrincipalID: owner, OrgID: oid,
	})
}

func (s *Store) IsOwner(ctx context.Context, resType, resID, principalID string) (bool, error) {
	return s.q.IsOwner(ctx, db.IsOwnerParams{ResourceType: resType, ResourceID: resID, OwnerPrincipalID: principalID})
}

func (s *Store) HasPermission(ctx context.Context, principalID, action, orgID, teamID string) (bool, error) {
	oid, err := uuid(orgID)
	if err != nil {
		return false, fmt.Errorf("%w: bad org id: %v", ErrInvalidInput, err)
	}
	var tid pgtype.UUID
	if teamID != "" {
		if tid, err = uuid(teamID); err != nil {
			return false, fmt.Errorf("%w: bad team id: %v", ErrInvalidInput, err)
		}
	}
	return s.q.HasPermission(ctx, db.HasPermissionParams{
		PrincipalID: principalID, Action: action, OrgID: oid, TeamID: tid,
	})
}
