package main

import (
	"context"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/SilasSolivagus/base-servers/internal/authz"
	"github.com/SilasSolivagus/base-servers/internal/config"
	"github.com/SilasSolivagus/base-servers/internal/delegation"
	"github.com/SilasSolivagus/base-servers/internal/engine/keycloak"
	"github.com/SilasSolivagus/base-servers/internal/org"
	"github.com/SilasSolivagus/base-servers/internal/principal"
	"github.com/SilasSolivagus/base-servers/internal/role"
	"github.com/SilasSolivagus/base-servers/internal/server"
	"github.com/SilasSolivagus/base-servers/internal/signingkey"
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

	orgSvc := org.NewService(org.NewStore(pool), role.NewStore(pool))
	roleSvc := role.NewService(role.NewStore(pool))
	authzStore := authz.NewStore(pool)
	authzSvc := authz.NewService(authzStore)

	// TODO(signingkey wiring task): replace with a signingkey.Manager-backed keyset
	// (persisted key, KEK from env, EnsureActive at startup) so signing keys survive
	// restarts and are shared across replicas. For now this preserves the prior
	// single-ephemeral-key-per-process behavior, adapted to the new keyset-driven
	// NewSigner signature.
	signingK, err := signingkey.GenerateKey()
	if err != nil {
		log.Fatalf("delegation signer: %v", err)
	}
	ks := signingkey.Keyset{Active: *signingK, All: []signingkey.Key{*signingK}}
	signer := delegation.NewSigner(cfg.DelegationIssuer, func() signingkey.Keyset { return ks })
	delStore := delegation.NewStore(pool)
	delSvc := delegation.NewService(delStore, signer, svc)
	delChecker := delegation.NewChecker(delStore, signer, authzSvc)

	srv := server.New(cfg,
		principal.NewHandler(svc),
		org.NewHandler(orgSvc),
		role.NewHandler(roleSvc),
		authz.NewHandler(authzSvc, authzStore),
		delegation.NewHandler(delSvc, delChecker),
		delegation.NewJWKSHandler(signer),
	)
	log.Printf("base-servers listening on %s", cfg.HTTPAddr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
