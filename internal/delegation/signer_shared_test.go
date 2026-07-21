package delegation_test

import (
	"context"
	"testing"
	"time"

	"github.com/SilasSolivagus/base-servers/internal/delegation"
	"github.com/SilasSolivagus/base-servers/internal/signingkey"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

func sharedCipher(t *testing.T) *signingkey.Cipher {
	t.Helper()
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(7)
	}
	c, err := signingkey.NewCipher(kek)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// 两个 Manager(模拟两副本)共享同一 DB+KEK:A 签的委托令牌 B 能验。
func TestTwoReplicasShareSigningKey(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	store := signingkey.NewStore(pool)
	ctx := context.Background()

	mgrA := signingkey.NewManager(store, sharedCipher(t))
	mgrB := signingkey.NewManager(store, sharedCipher(t))
	if err := mgrA.EnsureActive(ctx); err != nil {
		t.Fatal(err)
	}
	if err := mgrB.EnsureActive(ctx); err != nil {
		t.Fatal(err)
	}

	signerA := delegation.NewSigner("base-servers", mgrA.Keyset)
	signerB := delegation.NewSigner("base-servers", mgrB.Keyset)

	tok, err := signerA.Sign(delegation.Claims{
		Subject: "agent-1", Delegator: "user-1", DelegationID: "d1",
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signerB.Verify(tok); err != nil {
		t.Fatalf("replica B must verify replica A's token: %v", err)
	}
}
