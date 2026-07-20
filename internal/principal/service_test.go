package principal

import (
	"context"
	"testing"

	"github.com/SilasSolivagus/base-servers/internal/engine"
	"github.com/SilasSolivagus/base-servers/internal/engine/fake"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

func TestServiceCreateAgentPersists(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	svc := NewService(fake.New(), NewStore(pool))
	got, err := svc.Create(context.Background(), NewInput{
		Type: engine.Agent, DisplayName: "planner", OwnerPrincipalID: "u1", Purpose: "triage",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	reloaded, err := svc.Get(context.Background(), got.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if reloaded.OwnerPrincipalID != "u1" || reloaded.Type != engine.Agent {
		t.Fatalf("mismatch: %+v", reloaded)
	}
}

func TestServiceCreateRejectsInvalid(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	eng := fake.New()
	svc := NewService(eng, NewStore(pool))
	_, err := svc.Create(context.Background(), NewInput{Type: engine.Agent, DisplayName: "x"}) // 缺 owner
	if err == nil {
		t.Fatal("expected validation error for agent without owner")
	}
	if eng.CreatePrincipalCalls != 0 {
		t.Fatalf("expected 0 engine calls on validation error, got %d", eng.CreatePrincipalCalls)
	}
}
