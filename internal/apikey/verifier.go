package apikey

import (
	"context"
	"errors"
	"time"
)

var ErrInvalidKey = errors.New("invalid api key")

type Verifier struct {
	store *Store
	h     *Hasher
}

func NewVerifier(store *Store, h *Hasher) *Verifier { return &Verifier{store: store, h: h} }

// Verify parses+authenticates a presented token. Fail-closed: any defect -> ErrInvalidKey.
// The secret is never logged and never leaves this function.
func (v *Verifier) Verify(ctx context.Context, token string) (string, bool, error) {
	keyID, secret, ok := Parse(token)
	if !ok {
		return "", false, ErrInvalidKey
	}
	rec, err := v.store.GetByKeyID(ctx, keyID)
	if err != nil {
		// unknown keyid (pgx.ErrNoRows) or any DB error -> fail closed, do not distinguish to caller
		return "", false, ErrInvalidKey
	}
	if !v.h.Equal(secret, rec.Hash) {
		return "", false, ErrInvalidKey
	}
	if rec.Revoked || (rec.ExpiresAt != nil && time.Now().After(*rec.ExpiresAt)) {
		return "", false, ErrInvalidKey
	}
	// best-effort last_used update; never block/fail the request
	go func() {
		bg, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = v.store.TouchLastUsed(bg, keyID)
	}()
	return rec.PrincipalID, rec.ReadOnly, nil
}
