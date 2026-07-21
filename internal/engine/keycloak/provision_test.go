package keycloak_test

import (
	"context"
	"testing"

	"github.com/SilasSolivagus/base-servers/internal/engine/keycloak"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

func provAdapter(t *testing.T) *keycloak.Adapter {
	t.Helper()
	baseURL, _, user, pass := testsupport.StartKeycloak(t)
	a, err := keycloak.New(keycloak.Config{
		BaseURL: baseURL, Realm: "base-servers", AdminUser: user, AdminPass: pass,
		LoginClientID: "base-servers-login", LoginRedirectURIs: []string{"https://app.example.com/callback"},
		ServiceClientID: "base-servers-service", ServiceClientSecret: "svc-secret-123",
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestEnsureProvisionedCreatesRealmAndClients(t *testing.T) {
	a := provAdapter(t)
	ctx := context.Background()
	if err := a.EnsureProvisioned(ctx); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	// 幂等:再跑一次不报错
	if err := a.EnsureProvisioned(ctx); err != nil {
		t.Fatalf("ensure (idempotent): %v", err)
	}
	// 用适配器暴露的只读校验(Step 4 会加):realm 存在 + 两个 client 配置正确
	assertRealmProvisioned(t, a, ctx)
}

func assertRealmProvisioned(t *testing.T, a *keycloak.Adapter, ctx context.Context) {
	t.Helper()
	st, err := a.ProvisionStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !st.RealmExists {
		t.Fatal("realm base-servers not created")
	}
	if !st.LoginClient.Public || !st.LoginClient.StandardFlow || st.LoginClient.PKCE != "S256" {
		t.Fatalf("login client misconfigured: %+v", st.LoginClient)
	}
	if len(st.LoginClient.RedirectURIs) == 0 {
		t.Fatal("login client has no redirect URIs")
	}
	if st.ServiceClient.Public || !st.ServiceClient.ServiceAccounts {
		t.Fatalf("service client must be confidential + service-accounts: %+v", st.ServiceClient)
	}
	if st.ServiceClient.DirectAccessGrants {
		t.Fatalf("service client must reject direct-access-grants (ROPC password grant): %+v", st.ServiceClient)
	}
}
