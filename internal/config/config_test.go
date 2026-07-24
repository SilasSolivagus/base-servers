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

func TestLoadRateLimitDefaults(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://base:base@localhost:5432/baseservers")
	t.Setenv("KEYCLOAK_URL", "http://localhost:8080")
	c, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.RateLimitEnabled {
		t.Error("RateLimitEnabled default = false, want true (kill switch off by default)")
	}
	if c.RateLimitIPRPS != 20 || c.RateLimitIPBurst != 40 {
		t.Errorf("RateLimitIP default = %v/%v, want 20/40", c.RateLimitIPRPS, c.RateLimitIPBurst)
	}
	if c.RateLimitGlobalRPS != 500 || c.RateLimitGlobalBurst != 1000 {
		t.Errorf("RateLimitGlobal default = %v/%v, want 500/1000", c.RateLimitGlobalRPS, c.RateLimitGlobalBurst)
	}
	if c.RateLimitPrincipalRPS != 10 || c.RateLimitPrincipalBurst != 20 {
		t.Errorf("RateLimitPrincipal default = %v/%v, want 10/20", c.RateLimitPrincipalRPS, c.RateLimitPrincipalBurst)
	}
	if c.RateLimitTrustedProxyCIDRs != "127.0.0.0/8,::1/128,172.16.0.0/12" {
		t.Errorf("RateLimitTrustedProxyCIDRs default = %q", c.RateLimitTrustedProxyCIDRs)
	}
	if c.RateLimitMaxKeys != 4096 {
		t.Errorf("RateLimitMaxKeys default = %v, want 4096", c.RateLimitMaxKeys)
	}
}

// TestLoadRateLimitKillSwitch verifies BS_RATELIMIT_ENABLED=false disables rate limiting
// at the config level (main.go's runServer swaps every limiter for ratelimit.AllowAll{}
// when this is false — see cmd/base-servers/main.go).
func TestLoadRateLimitKillSwitch(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://base:base@localhost:5432/baseservers")
	t.Setenv("KEYCLOAK_URL", "http://localhost:8080")
	t.Setenv("BS_RATELIMIT_ENABLED", "false")
	c, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.RateLimitEnabled {
		t.Error("RateLimitEnabled = true with BS_RATELIMIT_ENABLED=false, want false")
	}
}
