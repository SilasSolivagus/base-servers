package principal

import (
	"fmt"

	"github.com/SilasSolivagus/base-servers/internal/engine"
)

type Principal struct {
	ID               string
	Type             engine.PrincipalType
	DisplayName      string
	OwnerPrincipalID string
	Capabilities     []string
	Purpose          string
	OnBehalfOf       string
}

type NewInput struct {
	Type             engine.PrincipalType
	DisplayName      string
	OwnerPrincipalID string
	Capabilities     []string
	Purpose          string
}

func Validate(in NewInput) error {
	switch in.Type {
	case engine.Human, engine.Service, engine.Agent:
	default:
		return fmt.Errorf("invalid principal type %q", in.Type)
	}
	if in.DisplayName == "" {
		return fmt.Errorf("display_name is required")
	}
	isAgent := in.Type == engine.Agent
	if isAgent && in.OwnerPrincipalID == "" {
		return fmt.Errorf("agent requires owner_principal_id")
	}
	if !isAgent && (in.OwnerPrincipalID != "" || in.Purpose != "" || len(in.Capabilities) > 0) {
		return fmt.Errorf("agent-only fields not allowed for type %q", in.Type)
	}
	return nil
}
