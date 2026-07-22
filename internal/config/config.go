package config

import (
	"fmt"
	"os"
	"strconv"
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
	PublicIssuer            string // BS_PUBLIC_ISSUER,如 http://localhost:8088/oidc/realms/base-servers
	RootToken               string // BS_ROOT_TOKEN(bootstrap break-glass)
	AuditBuffer             int    // AUDIT_BUFFER:异步审计记录器缓冲区大小
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
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
		PublicIssuer:            os.Getenv("BS_PUBLIC_ISSUER"),
		RootToken:               os.Getenv("BS_ROOT_TOKEN"),
		AuditBuffer:             envInt("AUDIT_BUFFER", 4096),
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
