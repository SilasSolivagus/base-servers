package apikey_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/SilasSolivagus/base-servers/internal/apikey"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

func TestVerifierAcceptsValidRejectsAll(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	store := apikey.NewStore(pool)
	pepper, _ := apikey.LoadPepper(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	h, _ := apikey.NewHasher(pepper)
	v := apikey.NewVerifier(store, h)
	ctx := context.Background()

	pt, keyID, secret, _ := apikey.Generate()
	exp := time.Now().Add(time.Hour)
	if err := store.Insert(ctx, apikey.NewKey{KeyID: keyID, PrincipalID: "p1", OrgID: "o1", Hash: h.Hash(secret), ReadOnly: true, ExpiresAt: &exp}); err != nil {
		t.Fatal(err)
	}

	pid, ro, err := v.Verify(ctx, pt)
	if err != nil || pid != "p1" || !ro {
		t.Fatalf("valid key must verify: pid=%q ro=%v err=%v", pid, ro, err)
	}

	// tampered secret
	bad := pt[:len(pt)-7] + "XXXXXX" + pt[len(pt)-1:]
	if _, _, err := v.Verify(ctx, bad); err != apikey.ErrInvalidKey {
		t.Fatalf("tampered key must be ErrInvalidKey, got %v", err)
	}
	// unknown keyid (valid shape, random)
	pt2, _, _, _ := apikey.Generate()
	if _, _, err := v.Verify(ctx, pt2); err != apikey.ErrInvalidKey {
		t.Fatalf("unknown key must be ErrInvalidKey, got %v", err)
	}
	// revoked
	store.Revoke(ctx, keyID)
	if _, _, err := v.Verify(ctx, pt); err != apikey.ErrInvalidKey {
		t.Fatalf("revoked key must be ErrInvalidKey, got %v", err)
	}
}

// TestVerifierRejectsWrongSecretForKnownKeyID reaches the h.Equal(secret,
// rec.Hash) mismatch branch in Verify specifically -- as opposed to the
// "tampered" case in TestVerifierAcceptsValidRejectsAll, which corrupts the
// CRC region and so is rejected earlier by Parse and never reaches
// ConstantTimeCompare. Here the presented token is well-formed (valid
// prefix/shape/CRC, so Parse succeeds) and its keyID is known (so
// GetByKeyID succeeds), but the stored hash was computed over a DIFFERENT
// secret than the one embedded in the token -- proving the credential-
// guessing path (right keyID, wrong secret) is rejected by the hash
// comparison itself, not by an earlier guard.
func TestVerifierRejectsWrongSecretForKnownKeyID(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	store := apikey.NewStore(pool)
	pepper, _ := apikey.LoadPepper(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	h, _ := apikey.NewHasher(pepper)
	v := apikey.NewVerifier(store, h)
	ctx := context.Background()

	// A fresh, well-formed token: valid prefix/shape and a correctly
	// recomputed CRC over its own keyID+secret, so Parse succeeds.
	pt, keyID, _, err := apikey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	// Insert a record under that SAME keyID, but hash a secret that is NOT
	// the one embedded in pt. GetByKeyID will find the record; only
	// h.Equal(secret, rec.Hash) can catch the mismatch.
	if err := store.Insert(ctx, apikey.NewKey{KeyID: keyID, PrincipalID: "p1", OrgID: "o1", Hash: h.Hash("some-OTHER-secret")}); err != nil {
		t.Fatal(err)
	}

	if _, _, err := v.Verify(ctx, pt); err != apikey.ErrInvalidKey {
		t.Fatalf("wrong-secret for known keyid must be ErrInvalidKey (hash-mismatch branch), got %v", err)
	}
}

func TestVerifierRejectsExpired(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	store := apikey.NewStore(pool)
	pepper, _ := apikey.LoadPepper(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	h, _ := apikey.NewHasher(pepper)
	v := apikey.NewVerifier(store, h)
	ctx := context.Background()
	pt, keyID, secret, _ := apikey.Generate()
	past := time.Now().Add(-time.Minute)
	store.Insert(ctx, apikey.NewKey{KeyID: keyID, PrincipalID: "p1", OrgID: "o1", Hash: h.Hash(secret), ExpiresAt: &past})
	if _, _, err := v.Verify(ctx, pt); err != apikey.ErrInvalidKey {
		t.Fatalf("expired key must be ErrInvalidKey, got %v", err)
	}
}
