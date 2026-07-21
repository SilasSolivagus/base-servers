package signingkey_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/SilasSolivagus/base-servers/internal/signingkey"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

func TestStoreInsertGetActive(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	s := signingkey.NewStore(pool)
	ctx := context.Background()

	if _, err := s.GetActive(ctx); !errors.Is(err, signingkey.ErrNoActive) {
		t.Fatalf("empty table: want ErrNoActive, got %v", err)
	}
	row := signingkey.KeyRow{Kid: "kid-a", Alg: "ES256", State: "active", PrivateEnc: []byte("enc-a")}
	if err := s.Insert(ctx, row); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetActive(ctx)
	if err != nil || got.Kid != "kid-a" || string(got.PrivateEnc) != "enc-a" {
		t.Fatalf("get active: %v %+v", err, got)
	}
}

func TestStoreSecondActiveConflicts(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	s := signingkey.NewStore(pool)
	ctx := context.Background()
	_ = s.Insert(ctx, signingkey.KeyRow{Kid: "k1", Alg: "ES256", State: "active", PrivateEnc: []byte("e1")})
	err := s.Insert(ctx, signingkey.KeyRow{Kid: "k2", Alg: "ES256", State: "active", PrivateEnc: []byte("e2")})
	if err == nil {
		t.Fatal("expected second active insert to conflict")
	}
}

func TestStoreRotate(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	s := signingkey.NewStore(pool)
	ctx := context.Background()
	_ = s.Insert(ctx, signingkey.KeyRow{Kid: "old", Alg: "ES256", State: "active", PrivateEnc: []byte("eo")})

	newRow := signingkey.KeyRow{Kid: "new", Alg: "ES256", State: "active", PrivateEnc: []byte("en")}
	if err := s.Rotate(ctx, newRow, time.Now().Add(25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	live, err := s.ListLive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 2 {
		t.Fatalf("want 2 live keys, got %d", len(live))
	}
	act, _ := s.GetActive(ctx)
	if act.Kid != "new" {
		t.Fatalf("want active=new, got %q", act.Kid)
	}
}

func TestStoreRetireExpired(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	s := signingkey.NewStore(pool)
	ctx := context.Background()
	// 一把已过退休期的 retiring 键
	_ = s.Insert(ctx, signingkey.KeyRow{
		Kid: "stale", Alg: "ES256", State: "retiring",
		PrivateEnc: []byte("es"), RetireAfter: time.Now().Add(-time.Hour),
	})
	n, err := s.RetireExpired(ctx)
	if err != nil || n != 1 {
		t.Fatalf("retire expired: n=%d err=%v", n, err)
	}
	live, _ := s.ListLive(ctx)
	if len(live) != 0 {
		t.Fatalf("want 0 live after retire, got %d", len(live))
	}
}
