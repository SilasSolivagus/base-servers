package authz

import "context"

// Checker is satisfied by *Service; lets other packages depend on the
// interface rather than the concrete authz store wiring.
type Checker interface {
	Check(ctx context.Context, subject, action string, res Resource) (bool, error)
}

type Service struct{ store *Store }

func NewService(store *Store) *Service { return &Service{store: store} }

// Check = 归属 ∨ RBAC。
func (s *Service) Check(ctx context.Context, subject, action string, res Resource) (bool, error) {
	owner, err := s.store.IsOwner(ctx, res.Type, res.ID, subject)
	if err != nil {
		return false, err
	}
	if owner {
		return true, nil
	}
	return s.store.HasPermission(ctx, subject, action, res.OrgID, res.TeamID)
}
