package main

import (
	"context"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/SilasSolivagus/base-servers/internal/config"
	"github.com/SilasSolivagus/base-servers/internal/engine/keycloak"
	"github.com/SilasSolivagus/base-servers/internal/principal"
	"github.com/SilasSolivagus/base-servers/internal/server"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	pool, err := pgxpool.New(context.Background(), cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer pool.Close()

	eng, err := keycloak.New(keycloak.Config{
		BaseURL: cfg.KeycloakURL, Realm: cfg.KeycloakRealm,
		AdminUser: cfg.KeycloakAdminUser, AdminPass: cfg.KeycloakAdminPass,
	})
	if err != nil {
		log.Fatalf("keycloak: %v", err)
	}

	svc := principal.NewService(eng, principal.NewStore(pool))
	srv := server.New(cfg, principal.NewHandler(svc))
	log.Printf("base-servers listening on %s", cfg.HTTPAddr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
