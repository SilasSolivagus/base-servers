package testsupport

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpg "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// StartPostgres 起一个真 Postgres,应用迁移,返回连接池。
func StartPostgres(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	c, err := tcpg.Run(ctx, "postgres:16",
		tcpg.WithDatabase("baseservers"),
		tcpg.WithUsername("base"), tcpg.WithPassword("base"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("5432/tcp")),
	)
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })
	dsn, err := c.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyMigrations(t, pool)
	return pool
}

// StartKeycloak 起一个真 Keycloak(master realm),返回 baseURL/realm/admin 账号密码。
// 用 master realm 简化 Phase 1;Phase 4 换成专用 realm 引导。
func StartKeycloak(t *testing.T) (baseURL, realm, user, pass string) {
	t.Helper()
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "quay.io/keycloak/keycloak:26.4",
		Cmd:          []string{"start-dev"},
		ExposedPorts: []string{"8080/tcp"},
		Env: map[string]string{
			"KC_BOOTSTRAP_ADMIN_USERNAME": "admin",
			"KC_BOOTSTRAP_ADMIN_PASSWORD": "admin",
			"KC_FEATURES":                 "token-exchange,dpop",
		},
		WaitingFor: wait.ForHTTP("/realms/master").WithPort("8080/tcp").WithStartupTimeout(180 * time.Second),
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req, Started: true,
	})
	if err != nil {
		t.Fatalf("start keycloak: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })
	host, _ := c.Host(ctx)
	port, _ := c.MappedPort(ctx, "8080/tcp")
	return "http://" + host + ":" + port.Port(), "master", "admin", "admin"
}

func applyMigrations(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	sql, err := os.ReadFile("../../db/migrations/0001_principal.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	// 只取 +goose Up 段(-- +goose Down 之前)
	up := string(sql)
	if i := indexOf(up, "-- +goose Down"); i >= 0 {
		up = up[:i]
	}
	if _, err := pool.Exec(context.Background(), up); err != nil {
		t.Fatalf("apply migration: %v", err)
	}
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
