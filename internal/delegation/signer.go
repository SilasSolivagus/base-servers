package delegation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type Claims struct {
	Subject, Delegator, DelegationID string
	Scope                            []string
	OrgID                            string
	CnfJkt                           string
	IssuedAt, ExpiresAt              time.Time
}

// tokenClaims is the shape that lands in the JWT (self-signed, matching the
// RFC 8693 act shape).
type tokenClaims struct {
	Iss   string   `json:"iss"`
	Sub   string   `json:"sub"`
	Exp   int64    `json:"exp"`
	Iat   int64    `json:"iat"`
	Act   actClaim `json:"act"`
	DID   string   `json:"delegation_id"`
	Scope []string `json:"scope"`
	Org   string   `json:"org_id"`
	Cnf   *cnf     `json:"cnf,omitempty"`
}
type actClaim struct {
	Sub string `json:"sub"`
}
type cnf struct {
	Jkt string `json:"jkt"`
}

type Signer struct {
	issuer string
	key    *ecdsa.PrivateKey
	kid    string
	signer jose.Signer
}

func NewSigner(issuer string) (*Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	kid := "bs-del-1"
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	if err != nil {
		return nil, err
	}
	return &Signer{issuer: issuer, key: key, kid: kid, signer: sig}, nil
}

func (s *Signer) Sign(c Claims) (string, error) {
	tc := tokenClaims{
		Iss: s.issuer, Sub: c.Subject, Exp: c.ExpiresAt.Unix(), Iat: c.IssuedAt.Unix(),
		Act: actClaim{Sub: c.Delegator}, DID: c.DelegationID, Scope: c.Scope, Org: c.OrgID,
	}
	if c.CnfJkt != "" {
		tc.Cnf = &cnf{Jkt: c.CnfJkt}
	}
	return jwt.Signed(s.signer).Claims(tc).Serialize()
}

func (s *Signer) Verify(token string) (Claims, error) {
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return Claims{}, err
	}
	var tc tokenClaims
	if err := parsed.Claims(&s.key.PublicKey, &tc); err != nil {
		return Claims{}, err
	}
	now := time.Now()
	if now.Unix() >= tc.Exp {
		return Claims{}, fmt.Errorf("delegation token expired")
	}
	if tc.Iss != s.issuer {
		return Claims{}, fmt.Errorf("unexpected issuer %q", tc.Iss)
	}
	out := Claims{
		Subject: tc.Sub, Delegator: tc.Act.Sub, DelegationID: tc.DID, Scope: tc.Scope,
		OrgID: tc.Org, IssuedAt: time.Unix(tc.Iat, 0), ExpiresAt: time.Unix(tc.Exp, 0),
	}
	if tc.Cnf != nil {
		out.CnfJkt = tc.Cnf.Jkt
	}
	return out, nil
}

func (s *Signer) JWKS() []byte {
	jwk := jose.JSONWebKey{Key: &s.key.PublicKey, KeyID: s.kid, Algorithm: "ES256", Use: "sig"}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
	b, _ := json.Marshal(set)
	return b
}
