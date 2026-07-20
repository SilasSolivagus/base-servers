package principal

import (
	"context"
	"fmt"

	"github.com/SilasSolivagus/base-servers/internal/engine"
)

type Service struct {
	eng   engine.IdentityEngine
	store *Store
}

func NewService(eng engine.IdentityEngine, store *Store) *Service {
	return &Service{eng: eng, store: store}
}

func (s *Service) Create(ctx context.Context, in NewInput) (Principal, error) {
	if err := Validate(in); err != nil {
		return Principal{}, err
	}
	meta := map[string]string{}
	if in.OwnerPrincipalID != "" {
		meta["owner"] = in.OwnerPrincipalID
	}
	if in.Purpose != "" {
		meta["purpose"] = in.Purpose
	}
	id, err := s.eng.CreatePrincipal(ctx, engine.EnginePrincipal{
		Type: in.Type, DisplayName: in.DisplayName, Metadata: meta,
	})
	if err != nil {
		return Principal{}, fmt.Errorf("engine create: %w", err)
	}
	p := Principal{
		ID: id, Type: in.Type, DisplayName: in.DisplayName,
		OwnerPrincipalID: in.OwnerPrincipalID, Capabilities: in.Capabilities, Purpose: in.Purpose,
	}
	if err := s.store.Insert(ctx, p); err != nil {
		return Principal{}, fmt.Errorf("store insert: %w", err)
	}
	return p, nil
}

func (s *Service) Get(ctx context.Context, id string) (Principal, error) {
	return s.store.Get(ctx, id)
}

// TypeOf implements delegation.PrincipalTyper.
func (s *Service) TypeOf(ctx context.Context, id string) (engine.PrincipalType, error) {
	p, err := s.store.Get(ctx, id)
	if err != nil {
		return "", err
	}
	return p.Type, nil
}
