package delegation

import (
	"testing"
	"time"
)

func TestSignerRoundTrip(t *testing.T) {
	s, err := NewSigner("base-servers")
	if err != nil {
		t.Fatal(err)
	}
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
	s, _ := NewSigner("base-servers")
	tok, _ := s.Sign(Claims{Subject: "a", Delegator: "u", DelegationID: "d",
		IssuedAt: time.Now().Add(-2 * time.Minute), ExpiresAt: time.Now().Add(-time.Minute)})
	if _, err := s.Verify(tok); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}

func TestSignerRejectsTampered(t *testing.T) {
	s, _ := NewSigner("base-servers")
	tok, _ := s.Sign(Claims{Subject: "a", Delegator: "u", DelegationID: "d",
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)})
	if _, err := s.Verify(tok + "x"); err == nil {
		t.Fatal("expected tampered token to be rejected")
	}
	if len(s.JWKS()) == 0 {
		t.Fatal("expected non-empty JWKS")
	}
}
