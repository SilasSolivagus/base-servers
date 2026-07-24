package apikey

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

// LoadPepper decodes a base64 pepper and enforces >=32 bytes (fail-closed).
func LoadPepper(b64 string) ([]byte, error) {
	if b64 == "" {
		return nil, fmt.Errorf("BS_APIKEY_PEPPER is required")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("BS_APIKEY_PEPPER not valid base64: %w", err)
	}
	if len(raw) < 32 {
		return nil, fmt.Errorf("BS_APIKEY_PEPPER must be >=32 bytes, got %d", len(raw))
	}
	return raw, nil
}

type Hasher struct{ pepper []byte }

func NewHasher(pepper []byte) (*Hasher, error) {
	if len(pepper) < 32 {
		return nil, fmt.Errorf("pepper must be >=32 bytes")
	}
	return &Hasher{pepper: pepper}, nil
}

func (h *Hasher) Hash(secret string) []byte {
	m := hmac.New(sha256.New, h.pepper)
	m.Write([]byte(secret))
	return m.Sum(nil)
}

func (h *Hasher) Equal(secret string, stored []byte) bool {
	return subtle.ConstantTimeCompare(h.Hash(secret), stored) == 1
}
