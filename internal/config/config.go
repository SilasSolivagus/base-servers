package config

import (
	"fmt"
	"os"
)

type Config struct {
	HTTPAddr          string
	DatabaseURL       string
	KeycloakURL       string
	KeycloakRealm     string
	KeycloakAdminUser string
	KeycloakAdminPass string
	DelegationIssuer  string
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func Load() (Config, error) {
	c := Config{
		HTTPAddr:          env("HTTP_ADDR", ":8081"),
		DatabaseURL:       os.Getenv("DATABASE_URL"),
		KeycloakURL:       os.Getenv("KEYCLOAK_URL"),
		KeycloakRealm:     env("KEYCLOAK_REALM", "base-servers"),
		KeycloakAdminUser: env("KEYCLOAK_ADMIN_USER", "admin"),
		KeycloakAdminPass: env("KEYCLOAK_ADMIN_PASS", "admin"),
		DelegationIssuer:  env("DELEGATION_ISSUER", "base-servers"),
	}
	if c.DatabaseURL == "" {
		return Config{}, fmt.Errorf("DATABASE_URL is required")
	}
	if c.KeycloakURL == "" {
		return Config{}, fmt.Errorf("KEYCLOAK_URL is required")
	}
	return c, nil
}
