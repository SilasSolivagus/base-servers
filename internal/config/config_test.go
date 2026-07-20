package config

import "testing"

func TestLoadDefaults(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://base:base@localhost:5432/baseservers")
	t.Setenv("KEYCLOAK_URL", "http://localhost:8080")
	c, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.HTTPAddr != ":8081" {
		t.Errorf("HTTPAddr default = %q, want :8081", c.HTTPAddr)
	}
	if c.KeycloakRealm != "base-servers" {
		t.Errorf("KeycloakRealm default = %q, want base-servers", c.KeycloakRealm)
	}
}

func TestLoadMissingDatabaseURL(t *testing.T) {
	t.Setenv("KEYCLOAK_URL", "http://localhost:8080")
	if _, err := Load(); err == nil {
		t.Fatal("expected error when DATABASE_URL is unset")
	}
}
