package delegation_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgxpool"

	v1 "github.com/SilasSolivagus/base-servers/gen/baseservers/v1"
	"github.com/SilasSolivagus/base-servers/gen/baseservers/v1/baseserversv1connect"
	"github.com/SilasSolivagus/base-servers/internal/authz"
	"github.com/SilasSolivagus/base-servers/internal/delegation"
	"github.com/SilasSolivagus/base-servers/internal/engine"
	"github.com/SilasSolivagus/base-servers/internal/org"
	"github.com/SilasSolivagus/base-servers/internal/role"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

type fakeTyper map[string]engine.PrincipalType

func (f fakeTyper) TypeOf(_ context.Context, id string) (engine.PrincipalType, error) {
	return f[id], nil
}

func newTestServer(t *testing.T, pool *pgxpool.Pool, typer fakeTyper) *httptest.Server {
	t.Helper()
	sig, err := delegation.NewSigner("base-servers")
	if err != nil {
		t.Fatal(err)
	}
	st := delegation.NewStore(pool)
	svc := delegation.NewService(st, sig, typer)
	checker := delegation.NewChecker(st, sig, authz.NewService(authz.NewStore(pool)))
	mux := http.NewServeMux()
	delegation.NewHandler(svc, checker).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestDelegationHandlerIssueAndRevoke(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	srv := newTestServer(t, pool, fakeTyper{"u1": engine.Human, "ag1": engine.Agent})
	o, err := org.NewStore(pool).CreateOrg(context.Background(), "Acme")
	if err != nil {
		t.Fatal(err)
	}

	c := baseserversv1connect.NewDelegationServiceClient(http.DefaultClient, srv.URL)
	resp, err := c.Issue(context.Background(), connect.NewRequest(&v1.IssueRequest{
		AgentId: "ag1", DelegatorId: "u1", OrgId: o.ID, Scope: []string{"doc.edit"}, TtlSeconds: 300,
	}))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if resp.Msg.Token == "" || resp.Msg.DelegationId == "" {
		t.Fatalf("expected token and delegation_id, got %+v", resp.Msg)
	}

	_, err = c.Revoke(context.Background(), connect.NewRequest(&v1.RevokeRequest{
		DelegationId: resp.Msg.DelegationId,
	}))
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
}

func TestDelegationHandlerCheckDelegatedAllowThenDenyAfterRevoke(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	srv := newTestServer(t, pool, fakeTyper{"u1": engine.Human, "ag1": engine.Agent})
	o, err := org.NewStore(pool).CreateOrg(context.Background(), "Acme")
	if err != nil {
		t.Fatal(err)
	}
	r, err := role.NewStore(pool).CreateRole(context.Background(), o.ID, "editor", []string{"doc.edit"})
	if err != nil {
		t.Fatal(err)
	}
	if err := role.NewStore(pool).AssignRole(context.Background(), "u1", r.ID, "org", o.ID); err != nil {
		t.Fatal(err)
	}

	c := baseserversv1connect.NewDelegationServiceClient(http.DefaultClient, srv.URL)
	issueResp, err := c.Issue(context.Background(), connect.NewRequest(&v1.IssueRequest{
		AgentId: "ag1", DelegatorId: "u1", OrgId: o.ID, Scope: []string{"doc.edit"}, TtlSeconds: 300,
	}))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	checkResp, err := c.CheckDelegated(context.Background(), connect.NewRequest(&v1.CheckDelegatedRequest{
		Token: issueResp.Msg.Token, Action: "doc.edit", ResourceType: "doc", ResourceId: "d1", OrgId: o.ID,
	}))
	if err != nil {
		t.Fatalf("check delegated: %v", err)
	}
	if !checkResp.Msg.Allowed {
		t.Fatal("expected allowed=true before revoke")
	}

	_, err = c.Revoke(context.Background(), connect.NewRequest(&v1.RevokeRequest{
		DelegationId: issueResp.Msg.DelegationId,
	}))
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}

	checkResp, err = c.CheckDelegated(context.Background(), connect.NewRequest(&v1.CheckDelegatedRequest{
		Token: issueResp.Msg.Token, Action: "doc.edit", ResourceType: "doc", ResourceId: "d1", OrgId: o.ID,
	}))
	if err != nil {
		t.Fatalf("check delegated after revoke: %v", err)
	}
	if checkResp.Msg.Allowed {
		t.Fatal("expected allowed=false after revoke")
	}
}

func TestDelegationHandlerIssueRejectsDelegatorIsAgent(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	srv := newTestServer(t, pool, fakeTyper{"ag1": engine.Agent, "ag2": engine.Agent})
	o, err := org.NewStore(pool).CreateOrg(context.Background(), "Acme")
	if err != nil {
		t.Fatal(err)
	}

	c := baseserversv1connect.NewDelegationServiceClient(http.DefaultClient, srv.URL)
	_, err = c.Issue(context.Background(), connect.NewRequest(&v1.IssueRequest{
		AgentId: "ag1", DelegatorId: "ag2", OrgId: o.ID, Scope: []string{"doc.edit"}, TtlSeconds: 300,
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", connect.CodeOf(err))
	}
}
