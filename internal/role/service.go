package role

import (
	"context"
	"errors"
	"fmt"
)

var ErrInvalidInput = errors.New("invalid role input")

type Service struct{ store *Store }

func NewService(store *Store) *Service { return &Service{store: store} }

func (s *Service) CreateRole(ctx context.Context, orgID, name string, perms []string) (Role, error) {
	if orgID == "" || name == "" {
		return Role{}, fmt.Errorf("%w: org_id and name required", ErrInvalidInput)
	}
	return s.store.CreateRole(ctx, orgID, name, perms)
}

func (s *Service) AssignRole(ctx context.Context, principalID, roleID, scopeType, scopeID string) error {
	if principalID == "" || roleID == "" || scopeID == "" {
		return fmt.Errorf("%w: principal_id, role_id, scope_id required", ErrInvalidInput)
	}
	if scopeType != "org" && scopeType != "team" {
		return fmt.Errorf("%w: scope_type must be org or team", ErrInvalidInput)
	}

	roleOrg, err := s.store.RoleOrg(ctx, roleID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return fmt.Errorf("%w: role or scope not found", ErrInvalidInput)
		}
		return err
	}
	scopeOrg := scopeID
	if scopeType == "team" {
		scopeOrg, err = s.store.TeamOrg(ctx, scopeID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return fmt.Errorf("%w: role or scope not found", ErrInvalidInput)
			}
			return err
		}
	}
	if scopeOrg != roleOrg {
		return fmt.Errorf("%w: role's org does not match scope's org", ErrInvalidInput)
	}

	return s.store.AssignRole(ctx, principalID, roleID, scopeType, scopeID)
}
