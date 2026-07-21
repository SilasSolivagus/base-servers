package authn

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
)

type fakeMemberChecker struct {
	member bool
	err    error
}

func (f fakeMemberChecker) IsMember(_ context.Context, _, _ string) (bool, error) {
	return f.member, f.err
}

func TestRequireSystemAdminNoCaller(t *testing.T) {
	err := RequireSystemAdmin(context.Background())
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("want Unauthenticated, got %v", err)
	}
}

func TestRequireSystemAdminNonAdmin(t *testing.T) {
	ctx := WithCaller(context.Background(), Caller{PrincipalID: "p1", SystemAdmin: false})
	err := RequireSystemAdmin(ctx)
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
}

func TestRequireSystemAdminAdmin(t *testing.T) {
	ctx := WithCaller(context.Background(), Caller{PrincipalID: "root", SystemAdmin: true})
	if err := RequireSystemAdmin(ctx); err != nil {
		t.Fatalf("want nil, got %v", err)
	}
}

func TestRequireMemberNoCaller(t *testing.T) {
	_, err := RequireMember(context.Background(), fakeMemberChecker{}, "org-1")
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("want Unauthenticated, got %v", err)
	}
}

func TestRequireMemberSystemAdminBypasses(t *testing.T) {
	ctx := WithCaller(context.Background(), Caller{PrincipalID: "root", SystemAdmin: true})
	c, err := RequireMember(ctx, fakeMemberChecker{member: false}, "org-1")
	if err != nil {
		t.Fatalf("want nil, got %v", err)
	}
	if !c.SystemAdmin {
		t.Fatalf("want caller returned, got %+v", c)
	}
}

func TestRequireMemberIsMember(t *testing.T) {
	ctx := WithCaller(context.Background(), Caller{PrincipalID: "p1", SystemAdmin: false})
	c, err := RequireMember(ctx, fakeMemberChecker{member: true}, "org-1")
	if err != nil {
		t.Fatalf("want nil, got %v", err)
	}
	if c.PrincipalID != "p1" {
		t.Fatalf("want caller p1, got %+v", c)
	}
}

func TestRequireMemberNotMember(t *testing.T) {
	ctx := WithCaller(context.Background(), Caller{PrincipalID: "p1", SystemAdmin: false})
	_, err := RequireMember(ctx, fakeMemberChecker{member: false}, "org-1")
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
}

func TestRequireMemberCheckerError(t *testing.T) {
	ctx := WithCaller(context.Background(), Caller{PrincipalID: "p1", SystemAdmin: false})
	_, err := RequireMember(ctx, fakeMemberChecker{err: errors.New("db down")}, "org-1")
	if connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("want Internal, got %v", err)
	}
}
