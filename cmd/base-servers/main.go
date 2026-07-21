package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/SilasSolivagus/base-servers/internal/authz"
	"github.com/SilasSolivagus/base-servers/internal/config"
	"github.com/SilasSolivagus/base-servers/internal/delegation"
	"github.com/SilasSolivagus/base-servers/internal/engine/keycloak"
	"github.com/SilasSolivagus/base-servers/internal/migrate"
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

	// KEK fail-closed:未设/错长 → 直接退出,绝不降级明文。
	kek, err := signingkey.KEKFromEnv()
	if err != nil {
		log.Fatalf("signing KEK: %v", err)
	}
	cipher, err := signingkey.NewCipher(kek)
	if err != nil {
		log.Fatalf("signing cipher: %v", err)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer pool.Close()

	if err := migrate.Apply(ctx, pool); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	keyMgr := signingkey.NewManager(signingkey.NewStore(pool), cipher)
	if err := keyMgr.EnsureActive(ctx); err != nil {
		// 含错-KEK(解不开现有 active 键)→ 拒绝启动,不新铸。
		log.Fatalf("signing key: %v", err)
	}

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

	signer := delegation.NewSigner(cfg.DelegationIssuer, keyMgr.Keyset)
	delStore := delegation.NewStore(pool)
	delSvc := delegation.NewService(delStore, signer, svc)
	delChecker := delegation.NewChecker(delStore, signer, authzSvc)

	ready := func(ctx context.Context) error {
		if err := pool.Ping(ctx); err != nil {
			return err
		}
		return keycloakReachable(ctx, cfg.KeycloakURL, cfg.KeycloakRealm)
	}

	srv := server.New(cfg, ready,
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

func keycloakReachable(ctx context.Context, baseURL, realm string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/realms/"+realm, nil)
	if err != nil {
		return err
	}
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return http.ErrServerClosed
	}
	return nil
}
