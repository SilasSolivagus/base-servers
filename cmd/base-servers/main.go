package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/SilasSolivagus/base-servers/internal/apikey"
	"github.com/SilasSolivagus/base-servers/internal/audit"
	"github.com/SilasSolivagus/base-servers/internal/authn"
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
	if len(os.Args) > 1 && os.Args[1] == "rotate-signing-key" {
		runRotate()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		runHealthcheck()
		return
	}
	runServer()
}

func runServer() {
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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
		LoginClientID: cfg.OIDCLoginClientID, LoginRedirectURIs: cfg.OIDCLoginRedirectURIs,
		ServiceClientID: cfg.OIDCServiceClientID, ServiceClientSecret: cfg.OIDCServiceClientSecret,
	})
	if err != nil {
		log.Fatalf("keycloak: %v", err)
	}

	// 服务 client 密钥 fail-closed:与 KEK 同风格,空密钥即拒绝启动,绝不明文降级。
	if cfg.OIDCServiceClientSecret == "" {
		log.Fatalf("BS_SERVICE_CLIENT_SECRET is required")
	}
	// OIDC 前门供给:realm + 两 client(幂等)。admin 凭证特权,失败即 fail-closed。
	if err := eng.EnsureProvisioned(ctx); err != nil {
		log.Fatalf("provision oidc: %v", err)
	}

	// 认证 fail-closed:公开 issuer 未设 → 拒绝启动,绝不降级为匿名放行。
	if cfg.PublicIssuer == "" {
		log.Fatalf("BS_PUBLIC_ISSUER is required")
	}
	jwksURL := cfg.KeycloakURL + "/realms/" + cfg.KeycloakRealm + "/protocol/openid-connect/certs"
	verifier := authn.NewVerifier(jwksURL, cfg.PublicIssuer,
		[]string{cfg.OIDCLoginClientID, cfg.OIDCServiceClientID})

	svc := principal.NewService(eng, principal.NewStore(pool))
	orgStore := org.NewStore(pool)
	orgSvc := org.NewService(orgStore, role.NewStore(pool))
	roleSvc := role.NewService(role.NewStore(pool))
	authzStore := authz.NewStore(pool)
	authzSvc := authz.NewService(authzStore)

	// API key pepper fail-closed:未设/非法 base64/短于32字节 → 拒绝启动,绝不降级明文比较。
	pepper, err := apikey.LoadPepper(cfg.APIKeyPepper)
	if err != nil {
		log.Fatalf("api key pepper: %v", err)
	}
	apikeyStore := apikey.NewStore(pool)
	apikeyHasher, err := apikey.NewHasher(pepper)
	if err != nil {
		log.Fatalf("api key hasher: %v", err)
	}
	apikeyVerifier := apikey.NewVerifier(apikeyStore, apikeyHasher)

	authInterceptor := connect.WithInterceptors(authn.Interceptor(verifier, apikeyVerifier, cfg.RootToken))

	auditStore := audit.NewStore(pool)
	auditRec := audit.NewRecorder(auditStore, cfg.AuditBuffer)
	// 审计排干的取消与信号 ctx 解耦:必须在 srv.Shutdown 返回(所有在途请求
	// 已跑完、不再有 rec.Record 生产者)之后才取消,否则 Run 可能在信号一到就
	// 排干退出,而慢请求随后写入的事件落进无人接收的 channel 被静默丢弃。
	auditCtx, auditCancel := context.WithCancel(context.Background())
	auditDone := make(chan struct{})
	go func() {
		auditRec.Run(auditCtx)
		close(auditDone)
	}()

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

	srv := server.New(cfg, ready, []connect.HandlerOption{authInterceptor},
		principal.NewHandler(svc, auditRec),
		org.NewHandler(orgSvc, orgStore, auditRec),
		role.NewHandler(roleSvc, orgStore, auditRec),
		authz.NewHandler(authzSvc, authzStore, orgStore, auditRec),
		delegation.NewHandler(delSvc, delChecker, auditRec),
		delegation.NewJWKSHandler(signer),
		audit.NewHandler(auditStore, orgStore),
		apikey.NewHandler(apikeyStore, apikeyHasher, orgStore,
			time.Duration(cfg.APIKeyMaxTTLSeconds)*time.Second, cfg.APIKeyAllowNeverExpire, 50, auditRec),
	)

	go func() {
		log.Printf("base-servers listening on %s", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %v", err)
		}
	}()

	<-ctx.Done() // SIGINT/SIGTERM → 先停 HTTP 收尾在途请求,再排干审计缓冲
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
	auditCancel() // Shutdown 已返回 → 不再有生产者,现在才触发排干
	<-auditDone   // 等审计记录器排干残余事件,再放 pool.Close() 执行
}

func runRotate() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
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

	mgr := signingkey.NewManager(signingkey.NewStore(pool), cipher)
	if err := mgr.EnsureActive(ctx); err != nil {
		log.Fatalf("signing key: %v", err)
	}
	k, err := mgr.Rotate(ctx)
	if err != nil {
		log.Fatalf("rotate: %v", err)
	}
	log.Printf("rotated: new active signing key kid=%s (previous key retiring)", k.Kid)
	log.Printf("operators: allow ~90s for replicas/verifiers to converge (internal keyset cache + JWKS max-age) before considering rotation complete or rotating again")
}

func runHealthcheck() {
	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = ":8081"
	}
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get("http://localhost" + addr + "/readyz")
	if err != nil {
		log.Printf("healthcheck: %v", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("healthcheck: /readyz status = %d, want 200", resp.StatusCode)
		os.Exit(1)
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
