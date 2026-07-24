package apikey_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/SilasSolivagus/base-servers/gen/baseservers/v1"
	"github.com/SilasSolivagus/base-servers/internal/apikey"
	"github.com/SilasSolivagus/base-servers/internal/audit"
	"github.com/SilasSolivagus/base-servers/internal/authn"
	"github.com/SilasSolivagus/base-servers/internal/authz"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

type members map[string]bool // "principal|org" -> member

func (m members) IsMember(_ context.Context, principalID, orgID string) (bool, error) {
	return m[principalID+"|"+orgID], nil
}

// fakeAuthz maps "principal|org" -> org-admin (org.manage) true/false.
type fakeAuthz map[string]bool

func (f fakeAuthz) Check(_ context.Context, subject, action string, res authz.Resource) (bool, error) {
	if action != "org.manage" {
		return false, nil
	}
	return f[subject+"|"+res.OrgID], nil
}

func newHandler(t *testing.T) (*apikey.Handler, *apikey.Store) {
	return newHandlerWithAuthz(t, fakeAuthz{})
}

func newHandlerWithAuthz(t *testing.T, az fakeAuthz) (*apikey.Handler, *apikey.Store) {
	pool := testsupport.StartPostgres(t)
	store := apikey.NewStore(pool)
	pepper, _ := apikey.LoadPepper(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	h, _ := apikey.NewHasher(pepper)
	rec := &audit.FakeRecorder{}
	mc := members{"p1|o1": true}
	return apikey.NewHandler(store, h, mc, 90*24*time.Hour, false, 50, rec, az), store
}

func TestIssueSelfSignAndKeyCannotMintKey(t *testing.T) {
	h, _ := newHandler(t)
	// self-sign as p1 in o1 (member) via oidc -> OK
	ctx := authn.WithCaller(context.Background(), authn.Caller{PrincipalID: "p1", AuthMethod: "oidc"})
	resp, err := h.Issue(ctx, connect.NewRequest(&v1.IssueApiKeyRequest{PrincipalId: "p1", OrgId: "o1", Name: "ci"}))
	if err != nil {
		t.Fatalf("self-sign should succeed: %v", err)
	}
	if resp.Msg.Secret == "" || resp.Msg.KeyId == "" {
		t.Fatal("issue must return a one-time secret + key id")
	}
	// C2: an API-key-authenticated caller may NOT Issue
	akCtx := authn.WithCaller(context.Background(), authn.Caller{PrincipalID: "p1", AuthMethod: "apikey"})
	if _, err := h.Issue(akCtx, connect.NewRequest(&v1.IssueApiKeyRequest{PrincipalId: "p1", OrgId: "o1"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("api key must not mint keys: %v", err)
	}
}

func TestIssueForOtherDenied(t *testing.T) {
	h, _ := newHandler(t)
	ctx := authn.WithCaller(context.Background(), authn.Caller{PrincipalID: "p1", AuthMethod: "oidc"})
	// p1 tries to sign for p2 -> PermissionDenied (K8)
	if _, err := h.Issue(ctx, connect.NewRequest(&v1.IssueApiKeyRequest{PrincipalId: "p2", OrgId: "o1"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("cross-principal issue must be denied: %v", err)
	}
}

func TestSystemAdminBootstrapsBypassesMembership(t *testing.T) {
	h, _ := newHandler(t)
	// root/system-admin issues for a service principal p9 in o1 (admin not a member) -> OK (I4)
	ctx := authn.WithCaller(context.Background(), authn.Caller{SystemAdmin: true, AuthMethod: "root"})
	if _, err := h.Issue(ctx, connect.NewRequest(&v1.IssueApiKeyRequest{PrincipalId: "p9", OrgId: "o1"})); err != nil {
		t.Fatalf("system-admin bootstrap must succeed: %v", err)
	}
}

func TestRevokeAndList(t *testing.T) {
	h, _ := newHandler(t)
	ctx := authn.WithCaller(context.Background(), authn.Caller{PrincipalID: "p1", AuthMethod: "oidc"})
	iss, _ := h.Issue(ctx, connect.NewRequest(&v1.IssueApiKeyRequest{PrincipalId: "p1", OrgId: "o1", Name: "a"}))
	lst, _ := h.List(ctx, connect.NewRequest(&v1.ListApiKeysRequest{PrincipalId: "p1"}))
	if len(lst.Msg.Keys) != 1 || lst.Msg.Keys[0].KeyId != iss.Msg.KeyId {
		t.Fatalf("list should show the issued key")
	}
	if _, err := h.Revoke(ctx, connect.NewRequest(&v1.RevokeApiKeyRequest{KeyId: iss.Msg.KeyId})); err != nil {
		t.Fatalf("owner revoke should succeed: %v", err)
	}
}

func TestRevokeAllowsOrgAdmin(t *testing.T) {
	az := fakeAuthz{"admin1|o1": true}
	h, _ := newHandlerWithAuthz(t, az)
	ownerCtx := authn.WithCaller(context.Background(), authn.Caller{PrincipalID: "p1", AuthMethod: "oidc"})

	// admin1 is org-admin of o1 -> may revoke p1's key in o1.
	iss1, err := h.Issue(ownerCtx, connect.NewRequest(&v1.IssueApiKeyRequest{PrincipalId: "p1", OrgId: "o1", Name: "a"}))
	if err != nil {
		t.Fatalf("issue should succeed: %v", err)
	}
	adminCtx := authn.WithCaller(context.Background(), authn.Caller{PrincipalID: "admin1", AuthMethod: "oidc"})
	if _, err := h.Revoke(adminCtx, connect.NewRequest(&v1.RevokeApiKeyRequest{KeyId: iss1.Msg.KeyId})); err != nil {
		t.Fatalf("org-admin revoke should succeed: %v", err)
	}

	// rando is neither self, system-admin, nor org-admin of o1 -> denied.
	iss2, err := h.Issue(ownerCtx, connect.NewRequest(&v1.IssueApiKeyRequest{PrincipalId: "p1", OrgId: "o1", Name: "b"}))
	if err != nil {
		t.Fatalf("issue should succeed: %v", err)
	}
	randoCtx := authn.WithCaller(context.Background(), authn.Caller{PrincipalID: "rando", AuthMethod: "oidc"})
	if _, err := h.Revoke(randoCtx, connect.NewRequest(&v1.RevokeApiKeyRequest{KeyId: iss2.Msg.KeyId})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-admin, non-owner revoke must be denied: %v", err)
	}

	// admin2 is org-admin of a DIFFERENT org (o2), not o1 -> denied.
	az2 := fakeAuthz{"admin2|o2": true}
	h2, _ := newHandlerWithAuthz(t, az2)
	iss3, err := h2.Issue(ownerCtx, connect.NewRequest(&v1.IssueApiKeyRequest{PrincipalId: "p1", OrgId: "o1", Name: "c"}))
	if err != nil {
		t.Fatalf("issue should succeed: %v", err)
	}
	admin2Ctx := authn.WithCaller(context.Background(), authn.Caller{PrincipalID: "admin2", AuthMethod: "oidc"})
	if _, err := h2.Revoke(admin2Ctx, connect.NewRequest(&v1.RevokeApiKeyRequest{KeyId: iss3.Msg.KeyId})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("wrong-org admin revoke must be denied: %v", err)
	}
}
