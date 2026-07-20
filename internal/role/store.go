package role

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	db "github.com/SilasSolivagus/base-servers/internal/role/db"
)

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
		return Role{}, fmt.Errorf("bad org id: %w", err)
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
		return fmt.Errorf("bad role id: %w", err)
	}
	sid, err := uuid(scopeID)
	if err != nil {
		return fmt.Errorf("bad scope id: %w", err)
	}
	return s.q.AssignRole(ctx, db.AssignRoleParams{
		PrincipalID: principalID, RoleID: rid, ScopeType: scopeType, ScopeID: sid,
	})
}

func (s *Store) SeedDefaults(ctx context.Context, orgID string) error {
	for _, d := range DefaultRoles {
		if _, err := s.CreateRole(ctx, orgID, d.Name, d.Permissions); err != nil {
			return fmt.Errorf("seed role %q: %w", d.Name, err)
		}
	}
	return nil
}
