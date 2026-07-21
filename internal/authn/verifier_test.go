package authn_test

import (
	"context"
	"testing"

	"github.com/Nerzal/gocloak/v13"
	"github.com/SilasSolivagus/base-servers/internal/authn"
	"github.com/SilasSolivagus/base-servers/internal/engine/keycloak"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

// 起真 Keycloak、供给 realm+clients、用服务 client 换令牌,验证器应通过并给出 sub。
func TestVerifierAcceptsValidServiceToken(t *testing.T) {
	baseURL, _, user, pass := testsupport.StartKeycloak(t)
	a, _ := keycloak.New(keycloak.Config{
		BaseURL: baseURL, Realm: "base-servers", AdminUser: user, AdminPass: pass,
		LoginClientID: "base-servers-login", LoginRedirectURIs: []string{"https://app/cb"},
		ServiceClientID: "base-servers-service", ServiceClientSecret: "svc-secret-123",
	})
	ctx := context.Background()
	if err := a.EnsureProvisioned(ctx); err != nil {
		t.Fatal(err)
	}
	tok, err := gocloak.NewClient(baseURL).LoginClient(ctx, "base-servers-service", "svc-secret-123", "base-servers")
	if err != nil {
		t.Fatal(err)
	}
	// issuer = Keycloak 自身发出的(测试里无网关/KC_HOSTNAME):用 realm 的实际 issuer。
	issuer := baseURL + "/realms/base-servers"
	jwksURL := baseURL + "/realms/base-servers/protocol/openid-connect/certs"
	v := authn.NewVerifier(jwksURL, issuer, []string{"base-servers-service", "base-servers-login"})

	c, err := v.Verify(ctx, tok.AccessToken)
	if err != nil {
		t.Fatalf("verify valid token: %v", err)
	}
	if c.PrincipalID == "" {
		t.Fatal("expected non-empty sub as PrincipalID")
	}
}

func TestVerifierRejectsGarbageAndWrongIssuer(t *testing.T) {
	v := authn.NewVerifier("http://127.0.0.1:1/certs", "https://issuer.example", []string{"base-servers-service"})
	if _, err := v.Verify(context.Background(), "not.a.jwt"); err == nil {
		t.Fatal("expected garbage token to be rejected")
	}
}
