package signingkey_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/SilasSolivagus/base-servers/internal/signingkey"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

func testCipher(t *testing.T) *signingkey.Cipher {
	t.Helper()
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 1)
	}
	c, err := signingkey.NewCipher(kek)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestManagerEnsureActiveCreatesOne(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	m := signingkey.NewManager(signingkey.NewStore(pool), testCipher(t))
	ctx := context.Background()
	if err := m.EnsureActive(ctx); err != nil {
		t.Fatal(err)
	}
	ks := m.Keyset()
	if ks.Active.Kid == "" || len(ks.All) != 1 {
		t.Fatalf("want 1 live active key, got active=%q all=%d", ks.Active.Kid, len(ks.All))
	}
}

func TestManagerEnsureActiveIdempotent(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	store := signingkey.NewStore(pool)
	m1 := signingkey.NewManager(store, testCipher(t))
	m2 := signingkey.NewManager(store, testCipher(t)) // 同 KEK,模拟第二副本
	ctx := context.Background()
	if err := m1.EnsureActive(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m2.EnsureActive(ctx); err != nil {
		t.Fatal(err)
	}
	if m1.Keyset().Active.Kid != m2.Keyset().Active.Kid {
		t.Fatal("two replicas must share the same active kid")
	}
}

func TestManagerEnsureActiveConcurrentSingleWinner(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	store := signingkey.NewStore(pool)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m := signingkey.NewManager(store, testCipher(t))
			if err := m.EnsureActive(ctx); err != nil {
				t.Errorf("ensure: %v", err)
			}
		}()
	}
	wg.Wait()
	live, err := store.ListLive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 1 {
		t.Fatalf("concurrent first-boot must converge to 1 key, got %d", len(live))
	}
}

func TestManagerWrongKEKRefuses(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	store := signingkey.NewStore(pool)
	ctx := context.Background()
	if err := signingkey.NewManager(store, testCipher(t)).EnsureActive(ctx); err != nil {
		t.Fatal(err)
	}
	// 换一把不同 KEK 的 cipher:必须解不开现有 active 键 → EnsureActive 报错,不新铸
	otherKEK := make([]byte, 32)
	for i := range otherKEK {
		otherKEK[i] = byte(200 - i)
	}
	oc, _ := signingkey.NewCipher(otherKEK)
	if err := signingkey.NewManager(store, oc).EnsureActive(ctx); err == nil {
		t.Fatal("expected wrong-KEK EnsureActive to fail")
	}
	if live, _ := store.ListLive(ctx); len(live) != 1 {
		t.Fatalf("wrong KEK must not mint a new key; live=%d", len(live))
	}
}

func TestManagerRotateKeepsBothLive(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	m := signingkey.NewManagerWithOptions(signingkey.NewStore(pool), testCipher(t),
		signingkey.Options{RetireWindow: time.Hour, CacheTTL: 0})
	ctx := context.Background()
	if err := m.EnsureActive(ctx); err != nil {
		t.Fatal(err)
	}
	old := m.Keyset().Active.Kid
	nk, err := m.Rotate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ks := m.Keyset()
	if ks.Active.Kid != nk.Kid || ks.Active.Kid == old {
		t.Fatalf("active must be new key: active=%q new=%q old=%q", ks.Active.Kid, nk.Kid, old)
	}
	if len(ks.All) != 2 {
		t.Fatalf("want 2 live keys after rotate, got %d", len(ks.All))
	}
}
