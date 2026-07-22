package signingkey

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

func TestGenerateKeyDeterministicKid(t *testing.T) {
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if k.Kid == "" {
		t.Fatal("expected non-empty kid")
	}
	if k.Priv == nil {
		t.Fatal("expected private key")
	}
	// kid 由公钥 thumbprint 派生 → 同一公钥必得同一 kid
	kid2, err := thumbprintKid(&k.Priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if kid2 != k.Kid {
		t.Fatalf("kid not stable from public key: %q vs %q", k.Kid, kid2)
	}
}

func TestDistinctKeysDistinctKids(t *testing.T) {
	a, _ := GenerateKey()
	b, _ := GenerateKey()
	if a.Kid == b.Kid {
		t.Fatal("expected distinct keys to have distinct kids")
	}
}

func TestMarshalParsePrivRoundTrip(t *testing.T) {
	k, _ := GenerateKey()
	der, err := MarshalPriv(k.Priv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParsePriv(der)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(k.Priv) {
		t.Fatal("round-tripped private key differs")
	}
	var _ *ecdsa.PrivateKey = got
}

func TestParsePrivRejectsNonECDSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePriv(der); err == nil {
		t.Fatal("expected error when parsing a non-ECDSA private key")
	}
}
