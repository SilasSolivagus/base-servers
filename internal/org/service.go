package org

import (
	"context"
	"errors"
	"fmt"
)

var ErrInvalidInput = errors.New("invalid org input")

// RoleSeeder seeds an organization's default roles. Implemented by *role.Store.
type RoleSeeder interface {
	SeedDefaults(ctx context.Context, orgID string) error
}

type Service struct {
	store *Store
	roles RoleSeeder
}

func NewService(store *Store, roles RoleSeeder) *Service {
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
	// Seeding roles is not transactional with org creation. If it fails, an
	// org with no roles would be left behind and unadministrable, so we
	// compensate by deleting the org (its roles cascade-delete) before
	// returning the error. Best-effort: the delete error is not surfaced.
	if err := s.roles.SeedDefaults(ctx, o.ID); err != nil {
		_ = s.store.DeleteOrg(ctx, o.ID)
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
