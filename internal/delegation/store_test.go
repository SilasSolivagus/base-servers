package delegation

import (
	"context"
	"testing"
	"time"

	"github.com/SilasSolivagus/base-servers/internal/org"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

func TestStoreInsertGetRevoke(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	o, _ := org.NewStore(pool).CreateOrg(context.Background(), "Acme")
	s := NewStore(pool)
	ctx := context.Background()
	id, err := s.Insert(ctx, Delegation{
		AgentID: "agent-1", DelegatorID: "user-1", OrgID: o.ID,
		Scope: []string{"doc.edit"}, ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil || id == "" {
		t.Fatalf("insert: %v %q", err, id)
	}
	d, err := s.Get(ctx, id)
	if err != nil || d.DelegatorID != "user-1" || len(d.Scope) != 1 || d.Revoked {
		t.Fatalf("get: %v %+v", err, d)
	}
	if err := s.Revoke(ctx, id); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	d2, _ := s.Get(ctx, id)
	if !d2.Revoked {
		t.Fatal("expected revoked=true after Revoke")
	}
}
