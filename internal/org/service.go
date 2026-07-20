package org

import (
	"context"
	"errors"
	"fmt"

	"github.com/SilasSolivagus/base-servers/internal/role"
)

var ErrInvalidInput = errors.New("invalid org input")

type Service struct {
	store *Store
	roles *role.Store
}

func NewService(store *Store, roles *role.Store) *Service {
	return &Service{store: store, roles: roles}
}

func (s *Service) CreateOrg(ctx context.Context, name string) (Organization, error) {
	if name == "" {
		return Organization{}, fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	o, err := s.store.CreateOrg(ctx, name)
	if err != nil {
		return Organization{}, err
	}
	if err := s.roles.SeedDefaults(ctx, o.ID); err != nil {
		return Organization{}, fmt.Errorf("seed default roles: %w", err)
	}
	return o, nil
}

func (s *Service) CreateTeam(ctx context.Context, orgID, name string) (Team, error) {
	if orgID == "" || name == "" {
		return Team{}, fmt.Errorf("%w: org_id and name required", ErrInvalidInput)
	}
	return s.store.CreateTeam(ctx, orgID, name)
}

func (s *Service) AddMember(ctx context.Context, principalID, orgID string) error {
	if principalID == "" || orgID == "" {
		return fmt.Errorf("%w: principal_id and org_id required", ErrInvalidInput)
	}
	return s.store.AddMember(ctx, principalID, orgID)
}

func (s *Service) AddTeamMember(ctx context.Context, principalID, teamID string) error {
	if principalID == "" || teamID == "" {
		return fmt.Errorf("%w: principal_id and team_id required", ErrInvalidInput)
	}
	return s.store.AddTeamMember(ctx, principalID, teamID)
}
