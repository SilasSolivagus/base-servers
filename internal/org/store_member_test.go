package org

import (
	"context"
	"testing"

	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

func TestOrgStoreIsMember(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	s := NewStore(pool)
	ctx := context.Background()

	o, err := s.CreateOrg(ctx, "Acme")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	if err := s.AddMember(ctx, "user-1", o.ID); err != nil {
		t.Fatalf("add member: %v", err)
	}

	is, err := s.IsMember(ctx, "user-1", o.ID)
	if err != nil || !is {
		t.Fatalf("want member true, got %v %v", is, err)
	}

	is, err = s.IsMember(ctx, "user-2", o.ID)
	if err != nil || is {
		t.Fatalf("want member false, got %v %v", is, err)
	}

	is, err = s.IsMember(ctx, "user-1", "not-a-uuid")
	if err != nil || is {
		t.Fatalf("want bad org_id -> false, nil, got %v %v", is, err)
	}
}
