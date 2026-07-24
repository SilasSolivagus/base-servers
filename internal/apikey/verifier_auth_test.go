package apikey_test

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/SilasSolivagus/base-servers/internal/apikey"
	"github.com/SilasSolivagus/base-servers/internal/audit"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

func TestApikeyAuthTelemetryKnownFullFidelity(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	store := apikey.NewStore(pool)
	pepper, _ := apikey.LoadPepper(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	h, _ := apikey.NewHasher(pepper)
	rec := &audit.FakeRecorder{}
	v := apikey.NewVerifier(store, h, rec)
	ctx := context.Background()

	// known keyid, wrong secret: insert a key, then present a token for its keyid with a different secret.
	pt, keyID, _, _ := apikey.Generate()
	store.Insert(ctx, apikey.NewKey{KeyID: keyID, PrincipalID: "p1", OrgID: "o1", Hash: h.Hash("OTHER-secret")})
	if _, _, err := v.Verify(ctx, pt); err == nil {
		t.Fatal("wrong secret must fail")
	}
	var authEvents int
	for _, e := range rec.Events {
		if e.Action == "apikey.auth" {
			authEvents++
			for k, val := range e.Detail {
				_ = k
				if val == "OTHER-secret" || len(val) >= 32 { // no secret material
					t.Fatalf("apikey.auth detail leaked secret-ish value: %q", val)
				}
			}
		}
	}
	if authEvents != 1 {
		t.Fatalf("known-keyid failure emits exactly one apikey.auth, got %d", authEvents)
	}
}

func TestApikeyAuthSuccessEmitsNothing(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	store := apikey.NewStore(pool)
	pepper, _ := apikey.LoadPepper(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	h, _ := apikey.NewHasher(pepper)
	rec := &audit.FakeRecorder{}
	v := apikey.NewVerifier(store, h, rec)
	ctx := context.Background()
	pt, keyID, secret, _ := apikey.Generate()
	store.Insert(ctx, apikey.NewKey{KeyID: keyID, PrincipalID: "p1", OrgID: "o1", Hash: h.Hash(secret)})
	if _, _, err := v.Verify(ctx, pt); err != nil {
		t.Fatalf("valid key: %v", err)
	}
	for _, e := range rec.Events {
		if e.Action == "apikey.auth" {
			t.Fatal("successful auth must emit no apikey.auth event")
		}
	}
}
