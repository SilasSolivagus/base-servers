package org

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	db "github.com/SilasSolivagus/base-servers/internal/org/db"
)

var ErrNotFound = errors.New("organization not found")

type Store struct{ q *db.Queries }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{q: db.New(pool)} }

func parseUUID(s string) (pgtype.UUID, error) {
	var u pgtype.UUID
	err := u.Scan(s)
	return u, err
}

// parentIDString adapts the CreateOrg/GetOrg queries' parent_id column.
// It is COALESCE(parent_id::text, ''), and sqlc infers that expression's
// Go type as `interface{}` rather than `string`, so it must be asserted
// here instead of assigned directly.
func parentIDString(v interface{}) string {
	if v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

func (s *Store) CreateOrg(ctx context.Context, name string) (Organization, error) {
	row, err := s.q.CreateOrg(ctx, name)
	if err != nil {
		return Organization{}, err
	}
	return Organization{ID: row.ID.String(), Name: row.Name, ParentID: parentIDString(row.ParentID)}, nil
}

func (s *Store) GetOrg(ctx context.Context, id string) (Organization, error) {
	uid, err := parseUUID(id)
	if err != nil {
		return Organization{}, ErrNotFound
	}
	row, err := s.q.GetOrg(ctx, uid)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Organization{}, ErrNotFound
		}
		return Organization{}, err
	}
	return Organization{ID: row.ID.String(), Name: row.Name, ParentID: parentIDString(row.ParentID)}, nil
}

func (s *Store) DeleteOrg(ctx context.Context, id string) error {
	uid, err := parseUUID(id)
	if err != nil {
		return ErrNotFound
	}
	return s.q.DeleteOrg(ctx, uid)
}

func (s *Store) CreateTeam(ctx context.Context, orgID, name string) (Team, error) {
	uid, err := parseUUID(orgID)
	if err != nil {
		return Team{}, ErrNotFound
	}
	row, err := s.q.CreateTeam(ctx, db.CreateTeamParams{OrgID: uid, Name: name})
	if err != nil {
		return Team{}, err
	}
	return Team{ID: row.ID.String(), OrgID: row.OrgID.String(), Name: row.Name}, nil
}

func (s *Store) AddMember(ctx context.Context, principalID, orgID string) error {
	uid, err := parseUUID(orgID)
	if err != nil {
		return ErrNotFound
	}
	return s.q.AddMember(ctx, db.AddMemberParams{PrincipalID: principalID, OrgID: uid})
}

func (s *Store) AddTeamMember(ctx context.Context, principalID, teamID string) error {
	uid, err := parseUUID(teamID)
	if err != nil {
		return ErrNotFound
	}
	return s.q.AddTeamMember(ctx, db.AddTeamMemberParams{PrincipalID: principalID, TeamID: uid})
}

func (s *Store) IsMember(ctx context.Context, principalID, orgID string) (bool, error) {
	oid, err := parseUUID(orgID)
	if err != nil {
		return false, nil // bad org_id treated as non-member (fail-safe)
	}
	return s.q.IsMember(ctx, db.IsMemberParams{PrincipalID: principalID, OrgID: oid})
}
