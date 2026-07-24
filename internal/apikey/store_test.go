package apikey_test

import (
	"context"
	"testing"
	"time"

	"github.com/SilasSolivagus/base-servers/internal/apikey"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
	"github.com/jackc/pgx/v5"
)

func TestStoreInsertGetRevoke(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	s := apikey.NewStore(pool)
	ctx := context.Background()
	exp := time.Now().Add(time.Hour)
	if err := s.Insert(ctx, apikey.NewKey{KeyID: "k1", PrincipalID: "p1", OrgID: "o1", Name: "ci", Hash: []byte("h1"), ReadOnly: true, ExpiresAt: &exp}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetByKeyID(ctx, "k1")
	if err != nil {
		t.Fatal(err)
	}
	if got.PrincipalID != "p1" || got.OrgID != "o1" || !got.ReadOnly || string(got.Hash) != "h1" || got.Revoked {
		t.Fatalf("unexpected stored key: %+v", got)
	}
	r, err := s.Revoke(ctx, "k1")
	if err != nil || r.PrincipalID != "p1" {
		t.Fatalf("revoke returned wrong owner: %+v err=%v", r, err)
	}
	got2, _ := s.GetByKeyID(ctx, "k1")
	if !got2.Revoked {
		t.Fatal("key must be revoked")
	}
	if _, err := s.GetByKeyID(ctx, "missing"); err != pgx.ErrNoRows {
		t.Fatalf("missing key must return pgx.ErrNoRows, got %v", err)
	}
}

func TestStoreListPaginatesAndCounts(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	s := apikey.NewStore(pool)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if err := s.Insert(ctx, apikey.NewKey{KeyID: string(rune('a' + i)), PrincipalID: "p1", OrgID: "o1", Hash: []byte("h")}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond) // distinct created_at for stable cursor
	}
	n, err := s.CountActive(ctx, "p1")
	if err != nil || n != 5 {
		t.Fatalf("CountActive=%d err=%v", n, err)
	}
	page1, _ := s.ListByPrincipal(ctx, "p1", nil, 2)
	if len(page1) != 2 {
		t.Fatalf("page1 len=%d", len(page1))
	}
	cur := page1[len(page1)-1].CreatedAt
	page2, _ := s.ListByPrincipal(ctx, "p1", &cur, 2)
	if len(page2) != 2 {
		t.Fatalf("page2 len=%d", len(page2))
	}
	if !page2[0].CreatedAt.Before(page1[len(page1)-1].CreatedAt) {
		t.Fatal("page2 must be strictly older than page1")
	}
}
