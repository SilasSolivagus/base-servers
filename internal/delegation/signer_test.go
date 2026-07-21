package delegation

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/SilasSolivagus/base-servers/internal/signingkey"
)

func testKeyset(t *testing.T, keys ...*signingkey.Key) func() signingkey.Keyset {
	t.Helper()
	if len(keys) == 0 {
		k, err := signingkey.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		keys = []*signingkey.Key{k}
	}
	ks := signingkey.Keyset{Active: *keys[0]}
	for _, k := range keys {
		ks.All = append(ks.All, *k)
	}
	return func() signingkey.Keyset { return ks }
}

func TestSignerRoundTrip(t *testing.T) {
	s := NewSigner("base-servers", testKeyset(t))
	tok, err := s.Sign(Claims{
		Subject: "agent-1", Delegator: "user-1", DelegationID: "d1",
		Scope: []string{"doc.edit"}, OrgID: "o1",
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Verify(tok)
	if err != nil || c.Subject != "agent-1" || c.Delegator != "user-1" || c.DelegationID != "d1" {
		t.Fatalf("verify: %v %+v", err, c)
	}
}

func TestSignerRejectsExpired(t *testing.T) {
	s := NewSigner("base-servers", testKeyset(t))
	tok, _ := s.Sign(Claims{Subject: "a", Delegator: "u", DelegationID: "d",
		IssuedAt: time.Now().Add(-2 * time.Minute), ExpiresAt: time.Now().Add(-time.Minute)})
	if _, err := s.Verify(tok); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}

func TestSignerRejectsTampered(t *testing.T) {
	s := NewSigner("base-servers", testKeyset(t))
	tok, _ := s.Sign(Claims{Subject: "a", Delegator: "u", DelegationID: "d",
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)})
	if _, err := s.Verify(tok + "x"); err == nil {
		t.Fatal("expected tampered token to be rejected")
	}
	if len(s.JWKS()) == 0 {
		t.Fatal("expected non-empty JWKS")
	}
}

// 轮换语义:上一把键签的令牌,在新 active 上任仍可验(keyset.All 含 retiring)。
func TestSignerVerifiesPreviousKey(t *testing.T) {
	oldK, _ := signingkey.GenerateKey()
	newK, _ := signingkey.GenerateKey()
	// signer A:只有 old(它是 active)
	sOld := NewSigner("base-servers", testKeyset(t, oldK))
	tok, _ := sOld.Sign(Claims{Subject: "a", Delegator: "u", DelegationID: "d",
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)})
	// signer B:active=new,但 all 含 old(retiring)→ 必须能验 old 签的令牌
	sNew := NewSigner("base-servers", testKeyset(t, newK, oldK))
	if _, err := sNew.Verify(tok); err != nil {
		t.Fatalf("expected previous-key token to verify: %v", err)
	}
	// JWKS 必须含两把公钥
	if n := countJWKSKeys(t, sNew.JWKS()); n != 2 {
		t.Fatalf("want 2 keys in JWKS, got %d", n)
	}
}

func countJWKSKeys(t *testing.T, raw []byte) int {
	t.Helper()
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatal(err)
	}
	return len(set.Keys)
}
