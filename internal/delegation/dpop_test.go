package delegation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// buildDPoPProof constructs and signs a real DPoP proof JWS (RFC 9449) using
// the given EC private key, embedding its public key in the protected
// header via go-jose's EmbedJWK signer option.
func buildDPoPProof(t *testing.T, key *ecdsa.PrivateKey, htm, htu, ath string) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt"),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(dpopPayload{
		Htm: htm,
		Htu: htu,
		Iat: time.Now().Unix(),
		Jti: "test-jti",
		Ath: ath,
	})
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestVerifyDPoPAllowsMatchingProof(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof := buildDPoPProof(t, key, "POST", "https://api.example/x", "abc")
	jkt, err := JKTFromProof(proof)
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyDPoP(proof, jkt, "POST", "https://api.example/x", "abc"); err != nil {
		t.Fatalf("expected valid proof to verify, got %v", err)
	}
}

func TestVerifyDPoPDeniesWrongKey(t *testing.T) {
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jkt1, err := JKTFromProof(buildDPoPProof(t, key1, "POST", "https://api.example/x", "abc"))
	if err != nil {
		t.Fatal(err)
	}
	// Proof signed by key2, but we check it against key1's jkt (as if a
	// stolen token were replayed with a different key).
	proofFromKey2 := buildDPoPProof(t, key2, "POST", "https://api.example/x", "abc")

	err = VerifyDPoP(proofFromKey2, jkt1, "POST", "https://api.example/x", "abc")
	if err == nil {
		t.Fatal("expected jkt mismatch error, got nil")
	}
}

func TestVerifyDPoPDeniesWrongHTU(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof := buildDPoPProof(t, key, "POST", "https://api.example/x", "abc")
	jkt, err := JKTFromProof(proof)
	if err != nil {
		t.Fatal(err)
	}

	err = VerifyDPoP(proof, jkt, "POST", "https://api.example/other", "abc")
	if err == nil {
		t.Fatal("expected htu mismatch error, got nil")
	}
}
