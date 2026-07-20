package principal

import (
	"testing"

	"github.com/SilasSolivagus/base-servers/internal/engine"
)

func TestValidateAgentRequiresOwner(t *testing.T) {
	err := Validate(NewInput{Type: engine.Agent, DisplayName: "planner"})
	if err == nil {
		t.Fatal("agent without owner must be rejected")
	}
}

func TestValidateHumanRejectsAgentFields(t *testing.T) {
	err := Validate(NewInput{Type: engine.Human, DisplayName: "alice", Purpose: "x"})
	if err == nil {
		t.Fatal("human with agent-only field must be rejected")
	}
}

func TestValidateAgentOK(t *testing.T) {
	err := Validate(NewInput{Type: engine.Agent, DisplayName: "planner", OwnerPrincipalID: "u1", Purpose: "triage"})
	if err != nil {
		t.Fatalf("valid agent rejected: %v", err)
	}
}
