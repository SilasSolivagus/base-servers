package config

import (
	"fmt"
	"os"
	"strings"
)

type Config struct {
	HTTPAddr                string
	DatabaseURL             string
	KeycloakURL             string
	KeycloakRealm           string
	KeycloakAdminUser       string
	KeycloakAdminPass       string
	DelegationIssuer        string
	OIDCLoginClientID       string
	OIDCLoginRedirectURIs   []string
	OIDCServiceClientID     string
	OIDCServiceClientSecret string
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func Load() (Config, error) {
	c := Config{
		HTTPAddr:                env("HTTP_ADDR", ":8081"),
		DatabaseURL:             os.Getenv("DATABASE_URL"),
		KeycloakURL:             os.Getenv("KEYCLOAK_URL"),
		KeycloakRealm:           env("KEYCLOAK_REALM", "base-servers"),
		KeycloakAdminUser:       env("KEYCLOAK_ADMIN_USER", "admin"),
		KeycloakAdminPass:       env("KEYCLOAK_ADMIN_PASS", "admin"),
		DelegationIssuer:        env("DELEGATION_ISSUER", "base-servers"),
		OIDCLoginClientID:       env("OIDC_LOGIN_CLIENT_ID", "base-servers-login"),
		OIDCLoginRedirectURIs:   splitCSV(os.Getenv("OIDC_LOGIN_REDIRECT_URIS")),
		OIDCServiceClientID:     env("OIDC_SERVICE_CLIENT_ID", "base-servers-service"),
		OIDCServiceClientSecret: os.Getenv("BS_SERVICE_CLIENT_SECRET"),
	}
	if c.DatabaseURL == "" {
		return Config{}, fmt.Errorf("DATABASE_URL is required")
	}
	if c.KeycloakURL == "" {
		return Config{}, fmt.Errorf("KEYCLOAK_URL is required")
	}
	return c, nil
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
