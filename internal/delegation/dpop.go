package delegation

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// dpopPayload is the claim set of a DPoP proof JWT (RFC 9449 section 4.2).
type dpopPayload struct {
	Htm string `json:"htm"`
	Htu string `json:"htu"`
	Iat int64  `json:"iat"`
	Jti string `json:"jti"`
	Ath string `json:"ath,omitempty"`
}

// ATH computes the DPoP "ath" claim value for an access token: base64url
// (no padding) of the SHA-256 hash of the token's ASCII bytes.
func ATH(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// parseDPoPProof parses a DPoP proof JWS, verifies its signature against the
// public key embedded in its own protected header (a DPoP proof is
// self-signed by the holder's key), and returns that key plus the decoded
// payload. It does NOT check jkt/htm/htu/ath - callers do that.
func parseDPoPProof(proofJWT string) (*jose.JSONWebKey, dpopPayload, error) {
	jws, err := jose.ParseSigned(proofJWT, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, dpopPayload{}, fmt.Errorf("dpop: parse proof: %w", err)
	}
	if len(jws.Signatures) != 1 {
		return nil, dpopPayload{}, errors.New("dpop: expected exactly one signature")
	}
	sig := jws.Signatures[0]

	typ, _ := sig.Protected.ExtraHeaders[jose.HeaderType].(string)
	if typ != "dpop+jwt" {
		return nil, dpopPayload{}, fmt.Errorf("dpop: unexpected typ %q", typ)
	}

	jwk := sig.Protected.JSONWebKey
	if jwk == nil {
		return nil, dpopPayload{}, errors.New("dpop: missing embedded jwk header")
	}

	payloadBytes, err := jws.Verify(jwk.Key)
	if err != nil {
		return nil, dpopPayload{}, fmt.Errorf("dpop: signature verification failed: %w", err)
	}

	var p dpopPayload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return nil, dpopPayload{}, fmt.Errorf("dpop: invalid payload: %w", err)
	}
	return jwk, p, nil
}

// jktFromJWK computes the RFC 9449 jkt value (base64url of the SHA-256 RFC
// 7638 JWK thumbprint) for a public key.
func jktFromJWK(jwk *jose.JSONWebKey) (string, error) {
	thumb, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("dpop: jwk thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(thumb), nil
}

// JKTFromProof parses a DPoP proof JWT and computes the jkt (RFC 9449) of
// its embedded public key, without verifying htm/htu/ath binding. Used at
// issue time to bind a newly-minted delegation token to the holder's key.
func JKTFromProof(proofJWT string) (string, error) {
	jwk, _, err := parseDPoPProof(proofJWT)
	if err != nil {
		return "", err
	}
	return jktFromJWK(jwk)
}

// VerifyDPoP verifies a DPoP proof JWT (RFC 9449) presented alongside a
// delegation token bound to expectedJkt. It fails closed: any parse,
// signature, jkt, htm, htu, or ath mismatch returns a non-nil error.
//
//   - proofJWT: the compact DPoP proof JWS from the "DPoP" request header.
//   - expectedJkt: the cnf.jkt bound into the delegation token at issue time.
//   - htm: the HTTP method of the request being authorized (e.g. "POST").
//   - htu: the HTTP URI of the request, without query or fragment.
//   - ath: if non-empty, the expected ATH(access_token) value.
func VerifyDPoP(proofJWT, expectedJkt, htm, htu, ath string) error {
	jwk, payload, err := parseDPoPProof(proofJWT)
	if err != nil {
		return err
	}

	jkt, err := jktFromJWK(jwk)
	if err != nil {
		return err
	}
	if jkt != expectedJkt {
		return errors.New("dpop: jkt mismatch")
	}
	if payload.Htm != htm {
		return errors.New("dpop: htm mismatch")
	}
	if payload.Htu != htu {
		return errors.New("dpop: htu mismatch")
	}
	if ath != "" && payload.Ath != ath {
		return errors.New("dpop: ath mismatch")
	}
	return nil
}
