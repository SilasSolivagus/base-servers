package testsupport

import (
	"context"
	"io"
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

	// master realm 默认 sslRequired=external:该机器的 Docker 网络会让
	// admin-login 请求被判定为外部来源,从而要求 HTTPS。从容器内部(loopback)
	// 用 kcadm 把 sslRequired 降为 NONE,让外部的 HTTP admin login(gocloak 用的
	// 就是这个)能通过。
	execKcadm(ctx, t, c, "/opt/keycloak/bin/kcadm.sh", "config", "credentials",
		"--server", "http://localhost:8080", "--realm", "master",
		"--user", "admin", "--password", "admin")
	execKcadm(ctx, t, c, "/opt/keycloak/bin/kcadm.sh", "update", "realms/master",
		"-s", "sslRequired=NONE")

	host, _ := c.Host(ctx)
	port, _ := c.MappedPort(ctx, "8080/tcp")
	return "http://" + host + ":" + port.Port(), "master", "admin", "admin"
}

// execKcadm 在容器内跑一条命令,exec 出错或非 0 退出码都直接 t.Fatalf,
// 带上完整输出,不吞错误。
func execKcadm(ctx context.Context, t *testing.T, c testcontainers.Container, args ...string) {
	t.Helper()
	code, out, err := c.Exec(ctx, args)
	if err != nil {
		t.Fatalf("exec %v: %v", args, err)
	}
	output, _ := io.ReadAll(out)
	if code != 0 {
		t.Fatalf("exec %v: exit %d: %s", args, code, output)
	}
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
