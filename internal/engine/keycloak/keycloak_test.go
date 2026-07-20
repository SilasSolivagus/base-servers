package keycloak_test

import (
	"context"
	"fmt"
	"sync"
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

func TestKeycloakCreateHumanPrincipal(t *testing.T) {
	base, realm, user, pass := testsupport.StartKeycloak(t)
	ad, err := keycloak.New(keycloak.Config{BaseURL: base, Realm: realm, AdminUser: user, AdminPass: pass})
	if err != nil {
		t.Fatalf("new adapter: %v", err)
	}
	id, err := ad.CreatePrincipal(context.Background(), engine.EnginePrincipal{
		Type: engine.Human, DisplayName: "alice",
		Metadata: map[string]string{"purpose": "ops"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := ad.GetPrincipal(context.Background(), id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Type != engine.Human || got.Metadata["purpose"] != "ops" {
		t.Fatalf("mismatch: %+v", got)
	}
}

func TestKeycloakCapabilities(t *testing.T) {
	// Capabilities() makes zero Keycloak calls, so no container is needed here.
	ad, err := keycloak.New(keycloak.Config{BaseURL: "http://dummy", Realm: "dummy", AdminUser: "dummy", AdminPass: "dummy"})
	if err != nil {
		t.Fatalf("new adapter: %v", err)
	}
	caps := ad.Capabilities()
	if !caps.TokenExchange || !caps.DPoP {
		t.Fatalf("expected token-exchange+dpop caps, got %+v", caps)
	}
}

func TestKeycloakConcurrentHumanCreates(t *testing.T) {
	base, realm, user, pass := testsupport.StartKeycloak(t)
	ad, err := keycloak.New(keycloak.Config{BaseURL: base, Realm: realm, AdminUser: user, AdminPass: pass})
	if err != nil {
		t.Fatalf("new adapter: %v", err)
	}

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := ad.CreatePrincipal(context.Background(), engine.EnginePrincipal{
				Type:        engine.Human,
				DisplayName: fmt.Sprintf("concurrent-user-%d", i),
				Metadata:    map[string]string{"purpose": "race-test"},
			})
			errs[i] = err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: create: %v", i, err)
		}
	}
}
