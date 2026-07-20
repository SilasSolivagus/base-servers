package role

import (
	"context"
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
