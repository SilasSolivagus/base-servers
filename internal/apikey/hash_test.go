package apikey

import (
	"encoding/base64"
	"testing"
)

func testPepper(t *testing.T) []byte {
	t.Helper()
	p, err := LoadPepper(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadPepperFailClosed(t *testing.T) {
	if _, err := LoadPepper(""); err == nil {
		t.Fatal("empty pepper must error")
	}
	if _, err := LoadPepper(base64.StdEncoding.EncodeToString(make([]byte, 16))); err == nil {
		t.Fatal("short pepper (<32) must error")
	}
	if _, err := LoadPepper("!!!not-base64!!!"); err == nil {
		t.Fatal("non-base64 pepper must error")
	}
}

func TestHashDeterministicAndVerify(t *testing.T) {
	h, err := NewHasher(testPepper(t))
	if err != nil {
		t.Fatal(err)
	}
	a := h.Hash("s3cr3t")
	b := h.Hash("s3cr3t")
	if len(a) != 32 {
		t.Fatalf("HMAC-SHA256 must be 32 bytes, got %d", len(a))
	}
	if string(a) != string(b) {
		t.Fatal("hash must be deterministic")
	}
	if !h.Equal("s3cr3t", a) {
		t.Fatal("Equal must accept the right secret")
	}
	if h.Equal("wrong", a) {
		t.Fatal("Equal must reject a wrong secret")
	}
}

func TestDifferentPepperDifferentHash(t *testing.T) {
	h1, _ := NewHasher(testPepper(t))
	p2 := make([]byte, 32)
	p2[0] = 1
	h2, _ := NewHasher(p2)
	if string(h1.Hash("x")) == string(h2.Hash("x")) {
		t.Fatal("different pepper must produce different hash")
	}
}
