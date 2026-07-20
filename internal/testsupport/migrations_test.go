package testsupport

import (
	"context"
	"testing"
)

func TestAllMigrationsApplied(t *testing.T) {
	pool := StartPostgres(t)
	for _, table := range []string{"principals", "organizations", "teams", "roles", "role_assignments", "ownership"} {
		var exists bool
		err := pool.QueryRow(context.Background(),
			"SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name=$1)", table).Scan(&exists)
		if err != nil {
			t.Fatalf("query %s: %v", table, err)
		}
		if !exists {
			t.Fatalf("table %q not created by migrations", table)
		}
	}
}
