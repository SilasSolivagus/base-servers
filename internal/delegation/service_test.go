package delegation

import (
	"context"
	"testing"

	"github.com/SilasSolivagus/base-servers/internal/engine"
	"github.com/SilasSolivagus/base-servers/internal/org"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

type fakeTyper map[string]engine.PrincipalType

func (f fakeTyper) TypeOf(_ context.Context, id string) (engine.PrincipalType, error) {
	return f[id], nil
}

func TestIssueRejectsDelegatorIsAgent(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	o, _ := org.NewStore(pool).CreateOrg(context.Background(), "Acme")
	sig, _ := NewSigner("base-servers")
	svc := NewService(NewStore(pool), sig, fakeTyper{"u1": engine.Human, "ag1": engine.Agent, "ag2": engine.Agent})
	_, _, err := svc.Issue(context.Background(), IssueInput{
		AgentID: "ag1", DelegatorID: "ag2", OrgID: o.ID, Scope: []string{"doc.edit"}, TTLSeconds: 300,
	})
	if err == nil {
		t.Fatal("expected error: delegator must not be an agent")
	}
}

func TestIssueOKAndRevoke(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	o, _ := org.NewStore(pool).CreateOrg(context.Background(), "Acme")
	sig, _ := NewSigner("base-servers")
	svc := NewService(NewStore(pool), sig, fakeTyper{"u1": engine.Human, "ag1": engine.Agent})
	tok, id, err := svc.Issue(context.Background(), IssueInput{
		AgentID: "ag1", DelegatorID: "u1", OrgID: o.ID, Scope: []string{"doc.edit"}, TTLSeconds: 300,
	})
	if err != nil || tok == "" || id == "" {
		t.Fatalf("issue: %v", err)
	}
	c, err := sig.Verify(tok)
	if err != nil || c.Subject != "ag1" || c.Delegator != "u1" || c.DelegationID != id {
		t.Fatalf("token claims: %v %+v", err, c)
	}
	if err := svc.Revoke(context.Background(), id); err != nil {
		t.Fatalf("revoke: %v", err)
	}
}
