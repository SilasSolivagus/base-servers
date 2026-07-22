package audit

import (
	"bytes"
	"testing"
	"time"
)

func TestChainOf(t *testing.T) {
	if ChainOf("") != "system" {
		t.Fatal("empty org must map to system chain")
	}
	if ChainOf("org-1") != "org-1" {
		t.Fatal("org chain must be the org id")
	}
}

func TestCanonicalHashDeterministicAndChained(t *testing.T) {
	ts := time.Unix(1700000000, 0).UTC()
	e := Event{ActorID: "u1", ActorType: ActorHuman, Action: "org.create",
		TargetType: "org", TargetID: "o1", OrgID: "o1", Outcome: OutcomeSuccess,
		Detail: map[string]string{"name": "Acme"}}
	prev := make([]byte, 32)
	h1 := canonicalHash(1, ts.UnixNano(), e, prev)
	h2 := canonicalHash(1, ts.UnixNano(), e, prev)
	if !bytes.Equal(h1, h2) {
		t.Fatal("hash must be deterministic")
	}
	// 改一个字段 → 哈希变
	e2 := e
	e2.Outcome = OutcomeDenied
	if bytes.Equal(canonicalHash(1, ts.UnixNano(), e2, prev), h1) {
		t.Fatal("changing a field must change the hash")
	}
	// 改 prev → 哈希变(链敏感)
	prev2 := make([]byte, 32)
	prev2[0] = 1
	if bytes.Equal(canonicalHash(1, ts.UnixNano(), e, prev2), h1) {
		t.Fatal("changing prev_hash must change the hash")
	}
	if len(h1) != 32 {
		t.Fatalf("hash must be 32 bytes, got %d", len(h1))
	}
}

func TestRedactDropsSecretishKeys(t *testing.T) {
	got := Redact(map[string]string{"name": "Acme", "token": "x", "secret": "y", "kek": "z", "password": "p"})
	if got["name"] != "Acme" {
		t.Fatal("allowed key dropped")
	}
	for _, k := range []string{"token", "secret", "kek", "password"} {
		if _, ok := got[k]; ok {
			t.Fatalf("secretish key %q must be redacted", k)
		}
	}
}
