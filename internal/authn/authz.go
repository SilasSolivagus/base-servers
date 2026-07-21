package authn

import (
	"context"

	"connectrpc.com/connect"
)

type MemberChecker interface {
	IsMember(ctx context.Context, principalID, orgID string) (bool, error)
}

// RequireSystemAdmin: only the root-token bootstrap principal may pass.
func RequireSystemAdmin(ctx context.Context) error {
	c, ok := CallerFromContext(ctx)
	if !ok {
		return connect.NewError(connect.CodeUnauthenticated, nil)
	}
	if !c.SystemAdmin {
		return connect.NewError(connect.CodePermissionDenied, errNotSystemAdmin)
	}
	return nil
}

// RequireMember: SystemAdmin bypasses; otherwise caller must be a member of orgID.
func RequireMember(ctx context.Context, m MemberChecker, orgID string) (Caller, error) {
	c, ok := CallerFromContext(ctx)
	if !ok {
		return Caller{}, connect.NewError(connect.CodeUnauthenticated, nil)
	}
	if c.SystemAdmin {
		return c, nil
	}
	ok, err := m.IsMember(ctx, c.PrincipalID, orgID)
	if err != nil {
		return Caller{}, connect.NewError(connect.CodeInternal, err)
	}
	if !ok {
		return Caller{}, connect.NewError(connect.CodePermissionDenied, errNotMember)
	}
	return c, nil
}

var (
	errNotSystemAdmin = errText("system-admin capability required")
	errNotMember      = errText("caller is not a member of the target org")
)

type errText string

func (e errText) Error() string { return string(e) }
