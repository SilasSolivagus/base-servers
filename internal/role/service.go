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
	return s.store.AssignRole(ctx, principalID, roleID, scopeType, scopeID)
}
