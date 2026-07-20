package role

import (
	"context"
	"errors"
	"testing"

	"github.com/SilasSolivagus/base-servers/internal/org"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

func TestRoleStoreCreateAssignSeed(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	o, err := org.NewStore(pool).CreateOrg(context.Background(), "Acme")
	if err != nil {
		t.Fatal(err)
	}
	s := NewStore(pool)
	ctx := context.Background()

	r, err := s.CreateRole(ctx, o.ID, "editor", []string{"doc.edit", "doc.read"})
	if err != nil || r.ID == "" || len(r.Permissions) != 2 {
		t.Fatalf("create role: %v %+v", err, r)
	}
	if err := s.AssignRole(ctx, "user-1", r.ID, "org", o.ID); err != nil {
		t.Fatalf("assign role: %v", err)
	}
	if err := s.SeedDefaults(ctx, o.ID); err != nil {
		t.Fatalf("seed defaults: %v", err)
	}
}

func TestAssignRoleRejectsCrossOrgScope(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	ctx := context.Background()
	orgStore := org.NewStore(pool)
	orgA, err := orgStore.CreateOrg(ctx, "Acme")
	if err != nil {
		t.Fatal(err)
	}
	orgB, err := orgStore.CreateOrg(ctx, "Globex")
	if err != nil {
		t.Fatal(err)
	}

	store := NewStore(pool)
	svc := NewService(store)

	roleA, err := store.CreateRole(ctx, orgA.ID, "editor", []string{"doc.edit"})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	// Cross-org: role belongs to org A, scope is org B — must be rejected.
	err = svc.AssignRole(ctx, "user-1", roleA.ID, "org", orgB.ID)
	if err == nil {
		t.Fatal("expected error assigning cross-org role, got nil")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected errors.Is(err, ErrInvalidInput), got %v", err)
	}

	// Same-org assignment must still succeed.
	if err := svc.AssignRole(ctx, "user-1", roleA.ID, "org", orgA.ID); err != nil {
		t.Fatalf("expected same-org assignment to succeed, got %v", err)
	}
}
