package principal

import (
	"context"
	"testing"

	"github.com/SilasSolivagus/base-servers/internal/engine"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

func TestStoreRoundTrip(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	s := NewStore(pool)
	ctx := context.Background()
	p := Principal{
		ID: "p-1", Type: engine.Agent, DisplayName: "planner",
		OwnerPrincipalID: "u1", Capabilities: []string{"search"}, Purpose: "triage",
	}
	if err := s.Insert(ctx, p); err != nil {
		t.Fatalf("insert: %v", err)
	}
	got, err := s.Get(ctx, "p-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Type != engine.Agent || got.OwnerPrincipalID != "u1" || got.Purpose != "triage" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}
