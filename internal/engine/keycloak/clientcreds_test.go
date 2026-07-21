package keycloak_test

import (
	"context"
	"testing"

	"github.com/Nerzal/gocloak/v13"
	"github.com/SilasSolivagus/base-servers/internal/engine/keycloak"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

// 供给后,服务 client 能用 client-credentials 换到 access token(证 OIDC 前门服务侧可用)。
func TestServiceClientCredentialsFlow(t *testing.T) {
	baseURL, _, user, pass := testsupport.StartKeycloak(t)
	a, err := keycloak.New(keycloak.Config{
		BaseURL: baseURL, Realm: "base-servers", AdminUser: user, AdminPass: pass,
		LoginClientID: "base-servers-login", LoginRedirectURIs: []string{"https://app.example.com/cb"},
		ServiceClientID: "base-servers-service", ServiceClientSecret: "svc-secret-123",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := a.EnsureProvisioned(ctx); err != nil {
		t.Fatal(err)
	}
	// 直接用一个裸 gocloak 客户端走 client-credentials(模拟外部服务调用方)
	cli := gocloak.NewClient(baseURL)
	tok, err := cli.LoginClient(ctx, "base-servers-service", "svc-secret-123", "base-servers")
	if err != nil {
		t.Fatalf("client-credentials login: %v", err)
	}
	if tok.AccessToken == "" {
		t.Fatal("empty access token")
	}
}
