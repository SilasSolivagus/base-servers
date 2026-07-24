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
	APIKeyPepper            string // BS_APIKEY_PEPPER(base64,>=32字节)—必需,fail-closed
	APIKeyMaxTTLSeconds     int    // BS_APIKEY_MAX_TTL_SECONDS,默认7776000=90天
	APIKeyAllowNeverExpire  bool   // BS_APIKEY_ALLOW_NEVER_EXPIRE,默认false

	RateLimitEnabled           bool    // BS_RATELIMIT_ENABLED,默认true—kill switch
	RateLimitIPRPS             float64 // BS_RATELIMIT_IP_RPS,默认20
	RateLimitIPBurst           int     // BS_RATELIMIT_IP_BURST,默认40
	RateLimitGlobalRPS         float64 // BS_RATELIMIT_GLOBAL_RPS,默认500(灾难兜底,非主限流)
	RateLimitGlobalBurst       int     // BS_RATELIMIT_GLOBAL_BURST,默认1000
	RateLimitPrincipalRPS      float64 // BS_RATELIMIT_PRINCIPAL_RPS,默认10
	RateLimitPrincipalBurst    int     // BS_RATELIMIT_PRINCIPAL_BURST,默认20
	RateLimitTrustedProxyCIDRs string  // BS_RATELIMIT_TRUSTED_PROXY_CIDRS,逗号分隔
	RateLimitMaxKeys           int     // BS_RATELIMIT_MAX_KEYS,默认4096
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

func envFloat(key string, def float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseFloat(v, 64)
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
		APIKeyPepper:            os.Getenv("BS_APIKEY_PEPPER"),
		APIKeyMaxTTLSeconds:     envInt("BS_APIKEY_MAX_TTL_SECONDS", 7776000),
		APIKeyAllowNeverExpire:  os.Getenv("BS_APIKEY_ALLOW_NEVER_EXPIRE") == "true",

		RateLimitEnabled:           os.Getenv("BS_RATELIMIT_ENABLED") != "false",
		RateLimitIPRPS:             envFloat("BS_RATELIMIT_IP_RPS", 20),
		RateLimitIPBurst:           envInt("BS_RATELIMIT_IP_BURST", 40),
		RateLimitGlobalRPS:         envFloat("BS_RATELIMIT_GLOBAL_RPS", 500),
		RateLimitGlobalBurst:       envInt("BS_RATELIMIT_GLOBAL_BURST", 1000),
		RateLimitPrincipalRPS:      envFloat("BS_RATELIMIT_PRINCIPAL_RPS", 10),
		RateLimitPrincipalBurst:    envInt("BS_RATELIMIT_PRINCIPAL_BURST", 20),
		RateLimitTrustedProxyCIDRs: env("BS_RATELIMIT_TRUSTED_PROXY_CIDRS", "127.0.0.0/8,::1/128,172.16.0.0/12"),
		RateLimitMaxKeys:           envInt("BS_RATELIMIT_MAX_KEYS", 4096),
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
