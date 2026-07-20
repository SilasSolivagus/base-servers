package org

import (
	"context"
	"testing"

	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

func TestOrgStoreCreateAndMembers(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	s := NewStore(pool)
	ctx := context.Background()

	o, err := s.CreateOrg(ctx, "Acme")
	if err != nil || o.ID == "" || o.Name != "Acme" {
		t.Fatalf("create org: %v %+v", err, o)
	}
	got, err := s.GetOrg(ctx, o.ID)
	if err != nil || got.Name != "Acme" {
		t.Fatalf("get org: %v %+v", err, got)
	}
	team, err := s.CreateTeam(ctx, o.ID, "Eng")
	if err != nil || team.ID == "" || team.OrgID != o.ID {
		t.Fatalf("create team: %v %+v", err, team)
	}
	if err := s.AddMember(ctx, "user-1", o.ID); err != nil {
		t.Fatalf("add member: %v", err)
	}
	if err := s.AddMember(ctx, "user-1", o.ID); err != nil { // idempotent
		t.Fatalf("add member twice: %v", err)
	}
	if err := s.AddTeamMember(ctx, "user-1", team.ID); err != nil {
		t.Fatalf("add team member: %v", err)
	}
}

func TestOrgStoreGetNotFound(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	s := NewStore(pool)
	_, err := s.GetOrg(context.Background(), "00000000-0000-0000-0000-000000000000")
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
