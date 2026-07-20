package keycloak_test

import (
	"context"
	"testing"

	"github.com/SilasSolivagus/base-servers/internal/engine"
	"github.com/SilasSolivagus/base-servers/internal/engine/keycloak"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

func TestKeycloakCreateAgentPrincipal(t *testing.T) {
	base, realm, user, pass := testsupport.StartKeycloak(t)
	ad, err := keycloak.New(keycloak.Config{BaseURL: base, Realm: realm, AdminUser: user, AdminPass: pass})
	if err != nil {
		t.Fatalf("new adapter: %v", err)
	}
	id, err := ad.CreatePrincipal(context.Background(), engine.EnginePrincipal{
		Type: engine.Agent, DisplayName: "planner",
		Metadata: map[string]string{"owner": "u1", "purpose": "triage"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := ad.GetPrincipal(context.Background(), id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Type != engine.Agent || got.Metadata["owner"] != "u1" {
		t.Fatalf("mismatch: %+v", got)
	}
}

func TestKeycloakCapabilities(t *testing.T) {
	base, realm, user, pass := testsupport.StartKeycloak(t)
	ad, _ := keycloak.New(keycloak.Config{BaseURL: base, Realm: realm, AdminUser: user, AdminPass: pass})
	caps := ad.Capabilities()
	if !caps.TokenExchange || !caps.DPoP {
		t.Fatalf("expected token-exchange+dpop caps, got %+v", caps)
	}
}
