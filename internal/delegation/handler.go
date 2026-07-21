package delegation

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"connectrpc.com/connect"

	v1 "github.com/SilasSolivagus/base-servers/gen/baseservers/v1"
	"github.com/SilasSolivagus/base-servers/gen/baseservers/v1/baseserversv1connect"
	"github.com/SilasSolivagus/base-servers/internal/authn"
	"github.com/SilasSolivagus/base-servers/internal/authz"
)

type Handler struct {
	svc     *Service
	checker *Checker
}

func NewHandler(svc *Service, checker *Checker) *Handler { return &Handler{svc: svc, checker: checker} }

func (h *Handler) Register(mux *http.ServeMux, opts ...connect.HandlerOption) {
	path, hdl := baseserversv1connect.NewDelegationServiceHandler(h, opts...)
	mux.Handle(path, hdl)
}

func code(err error) error {
	if errors.Is(err, ErrInvalidInput) {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	if errors.Is(err, ErrNotFound) {
		return connect.NewError(connect.CodeNotFound, err)
	}
	return connect.NewError(connect.CodeInternal, err)
}

func (h *Handler) Issue(ctx context.Context, req *connect.Request[v1.IssueRequest]) (*connect.Response[v1.IssueResponse], error) {
	c, ok := authn.CallerFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, nil)
	}
	// SystemAdmin is retained as an operational escape hatch; otherwise the
	// caller may only delegate its own authority (confused-deputy guard).
	if !c.SystemAdmin && c.PrincipalID != req.Msg.DelegatorId {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("caller may only delegate its own authority"))
	}
	tok, id, err := h.svc.Issue(ctx, IssueInput{
		AgentID: req.Msg.AgentId, DelegatorID: req.Msg.DelegatorId, OrgID: req.Msg.OrgId,
		Scope: req.Msg.Scope, TTLSeconds: req.Msg.TtlSeconds, CnfJkt: req.Msg.CnfJkt,
	})
	if err != nil {
		return nil, code(err)
	}
	return connect.NewResponse(&v1.IssueResponse{Token: tok, DelegationId: id}), nil
}

func (h *Handler) Revoke(ctx context.Context, req *connect.Request[v1.RevokeRequest]) (*connect.Response[v1.RevokeResponse], error) {
	c, ok := authn.CallerFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, nil)
	}
	d, err := h.svc.Get(ctx, req.Msg.DelegationId)
	if err != nil {
		return nil, code(err)
	}
	// SystemAdmin is retained as an operational escape hatch; otherwise only
	// the delegation's own delegator may revoke it.
	if !c.SystemAdmin && c.PrincipalID != d.DelegatorID {
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("only the delegator or a system-admin may revoke"))
	}
	if err := h.svc.Revoke(ctx, req.Msg.DelegationId); err != nil {
		return nil, code(err)
	}
	return connect.NewResponse(&v1.RevokeResponse{}), nil
}

// CheckDelegated: when the caller (an RS) forwards dpop_proof/http_method/
// http_uri, CheckDelegatedDPoP additionally verifies DPoP proof-of-possession
// against the token's cnf.jkt; when they're empty it degrades to the 3b
// behavior (DPoP enforcement is otherwise the resource server's job).
func (h *Handler) CheckDelegated(ctx context.Context, req *connect.Request[v1.CheckDelegatedRequest]) (*connect.Response[v1.CheckDelegatedResponse], error) {
	allowed, err := h.checker.CheckDelegatedDPoP(ctx, req.Msg.Token, req.Msg.Action, authz.Resource{
		Type: req.Msg.ResourceType, ID: req.Msg.ResourceId, OrgID: req.Msg.OrgId, TeamID: req.Msg.TeamId,
	}, req.Msg.DpopProof, req.Msg.HttpMethod, req.Msg.HttpUri)
	if err != nil {
		return nil, code(err)
	}
	return connect.NewResponse(&v1.CheckDelegatedResponse{Allowed: allowed}), nil
}
