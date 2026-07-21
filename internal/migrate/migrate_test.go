package migrate_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpg "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/SilasSolivagus/base-servers/internal/migrate"
)

func rawPostgres(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	c, err := tcpg.Run(ctx, "postgres:16",
		tcpg.WithDatabase("baseservers"), tcpg.WithUsername("base"), tcpg.WithPassword("base"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("5432/tcp")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })
	dsn, _ := c.ConnectionString(ctx, "sslmode=disable")
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestApplyCreatesTablesIdempotently(t *testing.T) {
	pool := rawPostgres(t)
	ctx := context.Background()
	if err := migrate.Apply(ctx, pool); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	// 再跑一次必须幂等(不因 CREATE TABLE 重复而失败)
	if err := migrate.Apply(ctx, pool); err != nil {
		t.Fatalf("second apply must be idempotent: %v", err)
	}
	// 抽查两张关键表存在
	for _, tbl := range []string{"principals", "signing_keys"} {
		var reg *string
		if err := pool.QueryRow(ctx, "SELECT to_regclass($1)", tbl).Scan(&reg); err != nil {
			t.Fatal(err)
		}
		if reg == nil {
			t.Fatalf("table %q not created", tbl)
		}
	}
}
