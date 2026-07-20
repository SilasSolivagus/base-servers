package org

import (
	"context"
	"testing"

	"github.com/SilasSolivagus/base-servers/internal/role"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

func TestServiceCreateOrgSeedsDefaultRoles(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	svc := NewService(NewStore(pool), role.NewStore(pool))
	o, err := svc.CreateOrg(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	// 默认角色应已种下:owner/admin/member 三行
	var n int
	if err := pool.QueryRow(context.Background(),
		"SELECT count(*) FROM roles WHERE org_id=$1", o.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("expected 3 default roles, got %d", n)
	}
}

func TestServiceCreateOrgRejectsEmpty(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	svc := NewService(NewStore(pool), role.NewStore(pool))
	if _, err := svc.CreateOrg(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty name")
	}
}
