package role

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	db "github.com/SilasSolivagus/base-servers/internal/role/db"
)

var ErrNotFound = errors.New("role not found")

type Store struct{ q *db.Queries }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{q: db.New(pool)} }

func uuid(s string) (pgtype.UUID, error) {
	var u pgtype.UUID
	err := u.Scan(s)
	return u, err
}

func (s *Store) CreateRole(ctx context.Context, orgID, name string, perms []string) (Role, error) {
	oid, err := uuid(orgID)
	if err != nil {
		return Role{}, fmt.Errorf("%w: bad org id: %v", ErrInvalidInput, err)
	}
	if perms == nil {
		perms = []string{}
	}
	row, err := s.q.CreateRole(ctx, db.CreateRoleParams{OrgID: oid, Name: name, Permissions: perms})
	if err != nil {
		return Role{}, err
	}
	return Role{ID: row.ID.String(), OrgID: row.OrgID.String(), Name: row.Name, Permissions: row.Permissions}, nil
}

func (s *Store) AssignRole(ctx context.Context, principalID, roleID, scopeType, scopeID string) error {
	rid, err := uuid(roleID)
	if err != nil {
		return fmt.Errorf("%w: bad role id: %v", ErrInvalidInput, err)
	}
	sid, err := uuid(scopeID)
	if err != nil {
		return fmt.Errorf("%w: bad scope id: %v", ErrInvalidInput, err)
	}
	return s.q.AssignRole(ctx, db.AssignRoleParams{
		PrincipalID: principalID, RoleID: rid, ScopeType: scopeType, ScopeID: sid,
	})
}

// RoleOrg returns the org_id that owns the given role. Returns ErrNotFound
// if roleID is malformed or the role does not exist.
func (s *Store) RoleOrg(ctx context.Context, roleID string) (string, error) {
	rid, err := uuid(roleID)
	if err != nil {
		return "", ErrNotFound
	}
	orgID, err := s.q.GetRoleOrg(ctx, rid)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	return orgID.String(), nil
}

// TeamOrg returns the org_id that owns the given team. Returns ErrNotFound
// if teamID is malformed or the team does not exist.
func (s *Store) TeamOrg(ctx context.Context, teamID string) (string, error) {
	tid, err := uuid(teamID)
	if err != nil {
		return "", ErrNotFound
	}
	orgID, err := s.q.GetTeamOrg(ctx, tid)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	return orgID.String(), nil
}

func (s *Store) SeedDefaults(ctx context.Context, orgID string) error {
	for _, d := range DefaultRoles {
		if _, err := s.CreateRole(ctx, orgID, d.Name, d.Permissions); err != nil {
			return fmt.Errorf("seed role %q: %w", d.Name, err)
		}
	}
	return nil
}
