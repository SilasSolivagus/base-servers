package delegation_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgxpool"

	v1 "github.com/SilasSolivagus/base-servers/gen/baseservers/v1"
	"github.com/SilasSolivagus/base-servers/gen/baseservers/v1/baseserversv1connect"
	"github.com/SilasSolivagus/base-servers/internal/audit"
	"github.com/SilasSolivagus/base-servers/internal/authn"
	"github.com/SilasSolivagus/base-servers/internal/authz"
	"github.com/SilasSolivagus/base-servers/internal/delegation"
	"github.com/SilasSolivagus/base-servers/internal/engine"
	"github.com/SilasSolivagus/base-servers/internal/org"
	"github.com/SilasSolivagus/base-servers/internal/role"
	"github.com/SilasSolivagus/base-servers/internal/signingkey"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

type fakeTyper map[string]engine.PrincipalType

func (f fakeTyper) TypeOf(_ context.Context, id string) (engine.PrincipalType, error) {
	return f[id], nil
}

func newTestServer(t *testing.T, pool *pgxpool.Pool, typer fakeTyper, rec audit.Recorder) *httptest.Server {
	t.Helper()
	k, err := signingkey.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ks := signingkey.Keyset{Active: *k, All: []signingkey.Key{*k}}
	sig := delegation.NewSigner("base-servers", func() signingkey.Keyset { return ks })
	st := delegation.NewStore(pool)
	svc := delegation.NewService(st, sig, typer)
	checker := delegation.NewChecker(st, sig, authz.NewService(authz.NewStore(pool)))
	mux := http.NewServeMux()
	delegation.NewHandler(svc, checker, rec).Register(mux, connect.WithInterceptors(authn.Interceptor(nil, testsupport.RootToken)))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestDelegationHandlerIssueAndRevoke(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	srv := newTestServer(t, pool, fakeTyper{"u1": engine.Human, "ag1": engine.Agent}, audit.NewRecorder(nil, 1))
	o, err := org.NewStore(pool).CreateOrg(context.Background(), "Acme")
	if err != nil {
		t.Fatal(err)
	}

	c := baseserversv1connect.NewDelegationServiceClient(http.DefaultClient, srv.URL, testsupport.ClientOpts()...)
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
	rec := &audit.FakeRecorder{}
	srv := newTestServer(t, pool, fakeTyper{"u1": engine.Human, "ag1": engine.Agent}, rec)
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

	c := baseserversv1connect.NewDelegationServiceClient(http.DefaultClient, srv.URL, testsupport.ClientOpts()...)
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
	if n := len(rec.Events); n != 2 {
		t.Fatalf("expected 2 events after issue+check (issue, decision), got %d: %+v", n, rec.Events)
	}
	allowEvt := rec.Events[len(rec.Events)-1]
	if allowEvt.Action != "authz.decision" || allowEvt.Outcome != audit.OutcomeSuccess || allowEvt.Detail["allowed"] != "true" || allowEvt.Detail["via"] != "delegation" {
		t.Fatalf("expected authz.decision success allowed=true via=delegation, got %+v", allowEvt)
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
	denyEvt := rec.Events[len(rec.Events)-1]
	if denyEvt.Action != "authz.decision" || denyEvt.Outcome != audit.OutcomeDenied || denyEvt.Detail["allowed"] != "false" || denyEvt.Detail["via"] != "delegation" {
		t.Fatalf("expected authz.decision denied allowed=false via=delegation, got %+v", denyEvt)
	}
}

// newTestHandler builds a *delegation.Handler directly (no HTTP layer) so
// tests can inject an authn.Caller into ctx and call handler methods
// in-process, mirroring the pattern used by internal/role/handler_test.go.
func newTestHandler(t *testing.T, pool *pgxpool.Pool, typer fakeTyper, rec audit.Recorder) *delegation.Handler {
	t.Helper()
	k, err := signingkey.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ks := signingkey.Keyset{Active: *k, All: []signingkey.Key{*k}}
	sig := delegation.NewSigner("base-servers", func() signingkey.Keyset { return ks })
	st := delegation.NewStore(pool)
	svc := delegation.NewService(st, sig, typer)
	checker := delegation.NewChecker(st, sig, authz.NewService(authz.NewStore(pool)))
	return delegation.NewHandler(svc, checker, rec)
}

// Confused-deputy guard: Issue must reject a caller naming a delegator other
// than itself, unless the caller is a system-admin.
func TestDelegationHandlerIssueRequiresCallerIsDelegator(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	h := newTestHandler(t, pool, fakeTyper{"u1": engine.Human, "u2": engine.Human, "ag1": engine.Agent}, audit.NewRecorder(nil, 1))
	o, err := org.NewStore(pool).CreateOrg(context.Background(), "Acme")
	if err != nil {
		t.Fatal(err)
	}
	issueReq := func(delegatorID string) *connect.Request[v1.IssueRequest] {
		return connect.NewRequest(&v1.IssueRequest{
			AgentId: "ag1", DelegatorId: delegatorID, OrgId: o.ID, Scope: []string{"doc.edit"}, TtlSeconds: 300,
		})
	}

	// No caller in ctx: Unauthenticated.
	if _, err := h.Issue(context.Background(), issueReq("u1")); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("no caller: expected Unauthenticated, got %v (%v)", connect.CodeOf(err), err)
	}

	// u2 tries to mint a delegation naming u1 as delegator: confused-deputy, denied.
	confusedCtx := authn.WithCaller(context.Background(), authn.Caller{PrincipalID: "u2", SystemAdmin: false})
	if _, err := h.Issue(confusedCtx, issueReq("u1")); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("confused-deputy Issue: expected PermissionDenied, got %v (%v)", connect.CodeOf(err), err)
	}

	// caller == delegator: issues normally.
	selfCtx := authn.WithCaller(context.Background(), authn.Caller{PrincipalID: "u1", SystemAdmin: false})
	resp, err := h.Issue(selfCtx, issueReq("u1"))
	if err != nil {
		t.Fatalf("self-delegation Issue: expected success, got %v", err)
	}
	if resp.Msg.Token == "" || resp.Msg.DelegationId == "" {
		t.Fatalf("expected token and delegation_id, got %+v", resp.Msg)
	}

	// SystemAdmin escape hatch: allowed even though it isn't the named delegator.
	adminCtx := authn.WithCaller(context.Background(), authn.Caller{PrincipalID: "root", SystemAdmin: true})
	if _, err := h.Issue(adminCtx, issueReq("u1")); err != nil {
		t.Fatalf("system-admin Issue: expected success, got %v", err)
	}
}

// Revoke must be restricted to the delegation's own delegator or a
// system-admin; any other authenticated caller is denied.
func TestDelegationHandlerRevokeRequiresDelegatorOrSystemAdmin(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	h := newTestHandler(t, pool, fakeTyper{"u1": engine.Human, "ag1": engine.Agent}, audit.NewRecorder(nil, 1))
	o, err := org.NewStore(pool).CreateOrg(context.Background(), "Acme")
	if err != nil {
		t.Fatal(err)
	}
	selfCtx := authn.WithCaller(context.Background(), authn.Caller{PrincipalID: "u1", SystemAdmin: false})
	issueReq := connect.NewRequest(&v1.IssueRequest{
		AgentId: "ag1", DelegatorId: "u1", OrgId: o.ID, Scope: []string{"doc.edit"}, TtlSeconds: 300,
	})

	// No caller in ctx: Unauthenticated.
	if _, err := h.Revoke(context.Background(), connect.NewRequest(&v1.RevokeRequest{DelegationId: "00000000-0000-0000-0000-000000000000"})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("no caller: expected Unauthenticated, got %v (%v)", connect.CodeOf(err), err)
	}

	// Unknown delegation id: NotFound.
	if _, err := h.Revoke(selfCtx, connect.NewRequest(&v1.RevokeRequest{DelegationId: "00000000-0000-0000-0000-000000000000"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("unknown delegation: expected NotFound, got %v (%v)", connect.CodeOf(err), err)
	}

	// A non-delegator, non-admin caller is denied.
	issued, err := h.Issue(selfCtx, issueReq)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	strangerCtx := authn.WithCaller(context.Background(), authn.Caller{PrincipalID: "stranger", SystemAdmin: false})
	if _, err := h.Revoke(strangerCtx, connect.NewRequest(&v1.RevokeRequest{DelegationId: issued.Msg.DelegationId})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-delegator Revoke: expected PermissionDenied, got %v (%v)", connect.CodeOf(err), err)
	}

	// The delegator itself is allowed.
	if _, err := h.Revoke(selfCtx, connect.NewRequest(&v1.RevokeRequest{DelegationId: issued.Msg.DelegationId})); err != nil {
		t.Fatalf("delegator Revoke: expected success, got %v", err)
	}

	// SystemAdmin escape hatch: allowed on a fresh delegation it didn't issue.
	issued2, err := h.Issue(selfCtx, issueReq)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	adminCtx := authn.WithCaller(context.Background(), authn.Caller{PrincipalID: "root", SystemAdmin: true})
	if _, err := h.Revoke(adminCtx, connect.NewRequest(&v1.RevokeRequest{DelegationId: issued2.Msg.DelegationId})); err != nil {
		t.Fatalf("system-admin Revoke: expected success, got %v", err)
	}
}

func TestDelegationHandlerIssueRejectsDelegatorIsAgent(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	srv := newTestServer(t, pool, fakeTyper{"ag1": engine.Agent, "ag2": engine.Agent}, audit.NewRecorder(nil, 1))
	o, err := org.NewStore(pool).CreateOrg(context.Background(), "Acme")
	if err != nil {
		t.Fatal(err)
	}

	c := baseserversv1connect.NewDelegationServiceClient(http.DefaultClient, srv.URL, testsupport.ClientOpts()...)
	_, err = c.Issue(context.Background(), connect.NewRequest(&v1.IssueRequest{
		AgentId: "ag1", DelegatorId: "ag2", OrgId: o.ID, Scope: []string{"doc.edit"}, TtlSeconds: 300,
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", connect.CodeOf(err))
	}
}

// Adversarial redaction acceptance: Issue mints and returns a real signed
// delegation token, and CheckDelegated/Revoke handle it too. None of that
// token material may ever end up in an audit Detail — the audit trail must
// never become a secret-leak surface. This walks every event the
// FakeRecorder captured and every Detail k/v within it.
func TestDelegationHandlerAuditNeverLeaksSecrets(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	rec := &audit.FakeRecorder{}
	h := newTestHandler(t, pool, fakeTyper{"u1": engine.Human, "ag1": engine.Agent}, rec)
	o, err := org.NewStore(pool).CreateOrg(context.Background(), "Acme")
	if err != nil {
		t.Fatal(err)
	}
	selfCtx := authn.WithCaller(context.Background(), authn.Caller{PrincipalID: "u1", SystemAdmin: false})

	issued, err := h.Issue(selfCtx, connect.NewRequest(&v1.IssueRequest{
		AgentId: "ag1", DelegatorId: "u1", OrgId: o.ID, Scope: []string{"doc.edit"}, TtlSeconds: 300,
	}))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	token := issued.Msg.Token
	if token == "" {
		t.Fatal("expected a real signed token")
	}

	if _, err := h.CheckDelegated(context.Background(), connect.NewRequest(&v1.CheckDelegatedRequest{
		Token: token, Action: "doc.edit", ResourceType: "doc", ResourceId: "d1", OrgId: o.ID,
	})); err != nil {
		t.Fatalf("check delegated: %v", err)
	}

	if _, err := h.Revoke(selfCtx, connect.NewRequest(&v1.RevokeRequest{DelegationId: issued.Msg.DelegationId})); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if len(rec.Events) == 0 {
		t.Fatal("expected at least one audit event")
	}
	secretishMarkers := []string{"token", "secret", "kek", "password", "proof", "key", "dpop", "cnf"}
	for _, e := range rec.Events {
		for k, v := range e.Detail {
			lk := strings.ToLower(k)
			for _, marker := range secretishMarkers {
				if strings.Contains(lk, marker) {
					t.Fatalf("event %q detail key %q looks secret-carrying", e.Action, k)
				}
			}
			if token != "" && strings.Contains(v, token) {
				t.Fatalf("event %q detail[%q] leaked the issued token", e.Action, k)
			}
		}
	}
}
