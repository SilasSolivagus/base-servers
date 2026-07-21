package signingkey

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func newTestKEK(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestCipherRoundTrip(t *testing.T) {
	c, err := NewCipher(newTestKEK(t))
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte("super secret private key bytes")
	blob, err := c.Seal("kid-1", pt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, pt) {
		t.Fatal("ciphertext leaks plaintext")
	}
	got, err := c.Open("kid-1", blob)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("open: %v got=%q", err, got)
	}
}

func TestCipherWrongKEKFails(t *testing.T) {
	c1, _ := NewCipher(newTestKEK(t))
	c2, _ := NewCipher(newTestKEK(t))
	blob, _ := c1.Seal("kid-1", []byte("x"))
	if _, err := c2.Open("kid-1", blob); err == nil {
		t.Fatal("expected wrong-KEK open to fail")
	}
}

func TestCipherWrongKidFails(t *testing.T) {
	c, _ := NewCipher(newTestKEK(t))
	blob, _ := c.Seal("kid-1", []byte("x"))
	if _, err := c.Open("kid-2", blob); err == nil {
		t.Fatal("expected wrong-kid (AAD) open to fail")
	}
}

func TestNewCipherRejectsBadLength(t *testing.T) {
	if _, err := NewCipher([]byte("short")); err == nil {
		t.Fatal("expected bad-length KEK to be rejected")
	}
}

func TestNonceIsRandom(t *testing.T) {
	c, _ := NewCipher(newTestKEK(t))
	a, _ := c.Seal("kid-1", []byte("same"))
	b, _ := c.Seal("kid-1", []byte("same"))
	if bytes.Equal(a, b) {
		t.Fatal("expected distinct nonces to yield distinct ciphertexts")
	}
}
