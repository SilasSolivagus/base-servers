package signingkey

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"os"
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

func TestKEKFromEnv(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		t.Setenv("BS_SIGNING_KEK", "placeholder")
		os.Unsetenv("BS_SIGNING_KEK")
		if _, err := KEKFromEnv(); err == nil {
			t.Fatal("expected error when BS_SIGNING_KEK is unset")
		}
	})

	t.Run("not valid base64", func(t *testing.T) {
		t.Setenv("BS_SIGNING_KEK", "not-valid-base64!!!")
		if _, err := KEKFromEnv(); err == nil {
			t.Fatal("expected error for invalid base64")
		}
	})

	t.Run("wrong length", func(t *testing.T) {
		wrong := make([]byte, 16)
		t.Setenv("BS_SIGNING_KEK", base64.StdEncoding.EncodeToString(wrong))
		if _, err := KEKFromEnv(); err == nil {
			t.Fatal("expected error for wrong-length key")
		}
	})

	t.Run("valid 32 bytes", func(t *testing.T) {
		good := make([]byte, 32)
		if _, err := rand.Read(good); err != nil {
			t.Fatal(err)
		}
		t.Setenv("BS_SIGNING_KEK", base64.StdEncoding.EncodeToString(good))
		kek, err := KEKFromEnv()
		if err != nil {
			t.Fatal(err)
		}
		if len(kek) != 32 {
			t.Fatalf("expected 32 bytes, got %d", len(kek))
		}
	})
}
