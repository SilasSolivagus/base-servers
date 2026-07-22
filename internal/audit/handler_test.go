package audit_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	v1 "github.com/SilasSolivagus/base-servers/gen/baseservers/v1"
	"github.com/SilasSolivagus/base-servers/internal/audit"
	"github.com/SilasSolivagus/base-servers/internal/authn"
	"github.com/SilasSolivagus/base-servers/internal/testsupport"
)

type fakeMembers struct{ member bool }

func (f fakeMembers) IsMember(_ context.Context, _, _ string) (bool, error) { return f.member, nil }

func TestAuditListRequiresMembership(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	s := audit.NewStore(pool)
	_ = s.Append(context.Background(), "o1", []audit.Event{ev("a", "o1")})
	h := audit.NewHandler(s, fakeMembers{member: false})

	// 非成员 → PermissionDenied
	ctx := authn.WithCaller(context.Background(), authn.Caller{PrincipalID: "stranger"})
	_, err := h.List(ctx, connect.NewRequest(&v1.ListRequest{OrgId: "o1"}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("non-member must be PermissionDenied, got %v", err)
	}

	// 成员 → 拿到事件
	h2 := audit.NewHandler(s, fakeMembers{member: true})
	resp, err := h2.List(authn.WithCaller(context.Background(), authn.Caller{PrincipalID: "u1"}),
		connect.NewRequest(&v1.ListRequest{OrgId: "o1"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Msg.Events) != 1 {
		t.Fatalf("member should see 1 event, got %d", len(resp.Msg.Events))
	}
}

func TestAuditVerifyOK(t *testing.T) {
	pool := testsupport.StartPostgres(t)
	s := audit.NewStore(pool)
	_ = s.Append(context.Background(), "o1", []audit.Event{ev("a", "o1"), ev("b", "o1")})
	h := audit.NewHandler(s, fakeMembers{member: true})
	resp, err := h.Verify(authn.WithCaller(context.Background(), authn.Caller{PrincipalID: "u1"}),
		connect.NewRequest(&v1.VerifyRequest{OrgId: "o1"}))
	if err != nil || !resp.Msg.Ok {
		t.Fatalf("verify: ok=%v err=%v", resp.Msg.Ok, err)
	}
}
