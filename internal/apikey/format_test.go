package apikey

import (
	"strings"
	"testing"
)

func TestGenerateAndParseRoundTrip(t *testing.T) {
	pt, keyID, secret, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pt, Prefix) {
		t.Fatalf("plaintext must start with %q: %q", Prefix, pt)
	}
	if len(keyID) != 16 || len(secret) != 32 {
		t.Fatalf("unexpected lengths keyID=%d secret=%d", len(keyID), len(secret))
	}
	gotID, gotSecret, ok := Parse(pt)
	if !ok || gotID != keyID || gotSecret != secret {
		t.Fatalf("round-trip failed: ok=%v id=%q/%q secret=%q/%q", ok, gotID, keyID, gotSecret, secret)
	}
}

func TestParseRejectsTamper(t *testing.T) {
	pt, _, _, _ := Generate()
	// flip the last char (part of CRC) -> bad CRC
	bad := pt[:len(pt)-1] + flip(pt[len(pt)-1])
	if _, _, ok := Parse(bad); ok {
		t.Fatal("tampered CRC must not parse")
	}
	// flip a secret char -> CRC mismatch
	i := len(Prefix) + 16 + 1 + 2
	bad2 := pt[:i] + flip(pt[i]) + pt[i+1:]
	if _, _, ok := Parse(bad2); ok {
		t.Fatal("tampered secret must not parse (CRC)")
	}
	for _, junk := range []string{"", "nope", "bsk_", "bsk_short", "eyJhbGc.jwt.here"} {
		if _, _, ok := Parse(junk); ok {
			t.Fatalf("junk must not parse: %q", junk)
		}
	}
}

func flip(b byte) string {
	if b == 'A' {
		return "B"
	}
	return "A"
}

func TestGenerateIsUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		_, id, _, _ := Generate()
		if seen[id] {
			t.Fatal("keyID collision")
		}
		seen[id] = true
	}
}
