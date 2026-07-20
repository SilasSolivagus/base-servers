package delegation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/SilasSolivagus/base-servers/internal/engine"
)

var ErrInvalidInput = errors.New("invalid delegation input")

type PrincipalTyper interface {
	TypeOf(ctx context.Context, id string) (engine.PrincipalType, error)
}

type IssueInput struct {
	AgentID, DelegatorID, OrgID string
	Scope                       []string
	TTLSeconds                  int64
	CnfJkt                      string // 3c
}

type Service struct {
	store      *Store
	signer     *Signer
	principals PrincipalTyper
}

func NewService(store *Store, signer *Signer, principals PrincipalTyper) *Service {
	return &Service{store: store, signer: signer, principals: principals}
}

func (s *Service) Issue(ctx context.Context, in IssueInput) (string, string, error) {
	if in.AgentID == "" || in.DelegatorID == "" || in.OrgID == "" || len(in.Scope) == 0 || in.TTLSeconds <= 0 {
		return "", "", fmt.Errorf("%w: agent_id, delegator_id, org_id, scope, ttl required", ErrInvalidInput)
	}
	dt, err := s.principals.TypeOf(ctx, in.DelegatorID)
	if err != nil {
		return "", "", err
	}
	if dt == engine.Agent {
		return "", "", fmt.Errorf("%w: delegator must not be an agent (v1)", ErrInvalidInput)
	}
	exp := time.Now().Add(time.Duration(in.TTLSeconds) * time.Second)
	id, err := s.store.Insert(ctx, Delegation{
		AgentID: in.AgentID, DelegatorID: in.DelegatorID, OrgID: in.OrgID,
		Scope: in.Scope, CnfJkt: in.CnfJkt, ExpiresAt: exp,
	})
	if err != nil {
		return "", "", err
	}
	tok, err := s.signer.Sign(Claims{
		Subject: in.AgentID, Delegator: in.DelegatorID, DelegationID: id, Scope: in.Scope,
		OrgID: in.OrgID, CnfJkt: in.CnfJkt, IssuedAt: time.Now(), ExpiresAt: exp,
	})
	if err != nil {
		return "", "", err
	}
	return tok, id, nil
}

func (s *Service) Revoke(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("%w: delegation_id required", ErrInvalidInput)
	}
	return s.store.Revoke(ctx, id)
}
