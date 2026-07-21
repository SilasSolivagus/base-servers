package migrate_test

import (
	"context"
	"os"
	"strings"
	"sync"
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

// TestApplyConcurrentIsSafe 验证多副本滚动部署下并发调用 Apply 不会因
// TOCTOU 竞态导致 PK 冲突/崩溃或迁移重复应用:advisory lock 应把并发调用
// 串行化,后来者会发现台账已全部写入并直接跳过。
func TestApplyConcurrentIsSafe(t *testing.T) {
	pool := rawPostgres(t)
	ctx := context.Background()

	const n = 5
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = migrate.Apply(ctx, pool)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent apply %d: %v", i, err)
		}
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

	// schema_migrations 每个迁移文件恰好一行,无重复、无部分失败。
	entries, err := os.ReadDir("../../db/migrations")
	if err != nil {
		t.Fatal(err)
	}
	want := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			want++
		}
	}

	var total, distinct int
	if err := pool.QueryRow(ctx, `SELECT count(*), count(DISTINCT version) FROM schema_migrations`).Scan(&total, &distinct); err != nil {
		t.Fatal(err)
	}
	if total != want || distinct != want {
		t.Fatalf("schema_migrations rows = %d (distinct %d), want %d", total, distinct, want)
	}
}
