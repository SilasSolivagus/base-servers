package authz

import "context"

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
