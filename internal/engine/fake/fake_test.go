package fake

import (
	"context"
	"testing"

	"github.com/SilasSolivagus/base-servers/internal/engine"
)

func TestFakeCreateAndGet(t *testing.T) {
	e := New()
	id, err := e.CreatePrincipal(context.Background(), engine.EnginePrincipal{
		Type: engine.Agent, DisplayName: "planner",
		Metadata: map[string]string{"owner": "u1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.GetPrincipal(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != engine.Agent || got.Metadata["owner"] != "u1" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestFakeCapabilitiesConfigurable(t *testing.T) {
	e := New()
	e.Caps = engine.Capabilities{TokenExchange: true, DPoP: true}
	if !e.Capabilities().TokenExchange {
		t.Fatal("expected TokenExchange capability")
	}
}
