package delegation

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/SilasSolivagus/base-servers/internal/signingkey"
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
	keyset func() signingkey.Keyset
}

// NewSigner 由外部提供 keyset(生产传 signingkey.Manager.Keyset)。
func NewSigner(issuer string, keyset func() signingkey.Keyset) *Signer {
	return &Signer{issuer: issuer, keyset: keyset}
}

func (s *Signer) newJOSESigner(k signingkey.Key) (jose.Signer, error) {
	return jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: k.Priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", k.Kid),
	)
}

func (s *Signer) Sign(c Claims) (string, error) {
	active := s.keyset().Active
	if active.Priv == nil {
		return "", fmt.Errorf("no active signing key")
	}
	sig, err := s.newJOSESigner(active)
	if err != nil {
		return "", err
	}
	tc := tokenClaims{
		Iss: s.issuer, Sub: c.Subject, Exp: c.ExpiresAt.Unix(), Iat: c.IssuedAt.Unix(),
		Act: actClaim{Sub: c.Delegator}, DID: c.DelegationID, Scope: c.Scope, Org: c.OrgID,
	}
	if c.CnfJkt != "" {
		tc.Cnf = &cnf{Jkt: c.CnfJkt}
	}
	return jwt.Signed(sig).Claims(tc).Serialize()
}

func (s *Signer) Verify(token string) (Claims, error) {
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return Claims{}, err
	}
	ks := s.keyset()
	pub, err := s.publicFor(parsed, ks)
	if err != nil {
		return Claims{}, err
	}
	var tc tokenClaims
	if err := parsed.Claims(pub, &tc); err != nil {
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

// publicFor 按令牌头 kid 命中公钥;kid 缺失/未命中时返回错误(fail-closed)。
func (s *Signer) publicFor(parsed *jwt.JSONWebToken, ks signingkey.Keyset) (*ecdsa.PublicKey, error) {
	var kid string
	if len(parsed.Headers) > 0 {
		kid = parsed.Headers[0].KeyID
	}
	for _, k := range ks.All {
		if k.Kid == kid {
			return &k.Priv.PublicKey, nil
		}
	}
	return nil, fmt.Errorf("no signing key for kid %q", kid)
}

func (s *Signer) JWKS() []byte {
	var jwks []jose.JSONWebKey
	for _, k := range s.keyset().All {
		jwks = append(jwks, jose.JSONWebKey{
			Key: &k.Priv.PublicKey, KeyID: k.Kid, Algorithm: "ES256", Use: "sig",
		})
	}
	b, _ := json.Marshal(jose.JSONWebKeySet{Keys: jwks})
	return b
}
