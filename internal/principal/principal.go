package principal

import (
	"errors"
	"fmt"

	"github.com/SilasSolivagus/base-servers/internal/engine"
)

var ErrInvalidInput = errors.New("invalid principal input")

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
		return fmt.Errorf("%w: invalid principal type %q", ErrInvalidInput, in.Type)
	}
	if in.DisplayName == "" {
		return fmt.Errorf("%w: display_name is required", ErrInvalidInput)
	}
	isAgent := in.Type == engine.Agent
	if isAgent && in.OwnerPrincipalID == "" {
		return fmt.Errorf("%w: agent requires owner_principal_id", ErrInvalidInput)
	}
	if !isAgent && (in.OwnerPrincipalID != "" || in.Purpose != "" || len(in.Capabilities) > 0) {
		return fmt.Errorf("%w: agent-only fields not allowed for type %q", ErrInvalidInput, in.Type)
	}
	return nil
}
