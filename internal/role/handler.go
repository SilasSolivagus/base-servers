package role

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"connectrpc.com/connect"

	v1 "github.com/SilasSolivagus/base-servers/gen/baseservers/v1"
	"github.com/SilasSolivagus/base-servers/gen/baseservers/v1/baseserversv1connect"
	"github.com/SilasSolivagus/base-servers/internal/authn"
)

type Handler struct {
	svc     *Service
	members authn.MemberChecker
}

func NewHandler(svc *Service, members authn.MemberChecker) *Handler {
	return &Handler{svc: svc, members: members}
}

func (h *Handler) Register(mux *http.ServeMux, opts ...connect.HandlerOption) {
	path, hdl := baseserversv1connect.NewRoleServiceHandler(h, opts...)
	mux.Handle(path, hdl)
}

func code(err error) error {
	if errors.Is(err, ErrInvalidInput) {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	return connect.NewError(connect.CodeInternal, err)
}

func (h *Handler) CreateRole(ctx context.Context, req *connect.Request[v1.CreateRoleRequest]) (*connect.Response[v1.CreateRoleResponse], error) {
	if _, err := authn.RequireMember(ctx, h.members, req.Msg.OrgId); err != nil {
		return nil, err
	}
	r, err := h.svc.CreateRole(ctx, req.Msg.OrgId, req.Msg.Name, req.Msg.Permissions)
	if err != nil {
		return nil, code(err)
	}
	return connect.NewResponse(&v1.CreateRoleResponse{
		Role: &v1.Role{Id: r.ID, OrgId: r.OrgID, Name: r.Name, Permissions: r.Permissions},
	}), nil
}

func (h *Handler) AssignRole(ctx context.Context, req *connect.Request[v1.AssignRoleRequest]) (*connect.Response[v1.AssignRoleResponse], error) {
	// AssignRoleRequest carries no org_id directly; resolve the role's owning
	// org first, then gate on membership in that org. A role lookup failure
	// is folded into the same ErrInvalidInput the business logic below would
	// otherwise return for a bad/missing role_id, so callers see one
	// consistent error rather than leaking the authz-vs-validation ordering.
	orgID, err := h.svc.RoleOrg(ctx, req.Msg.RoleId)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, code(fmt.Errorf("%w: role not found", ErrInvalidInput))
		}
		return nil, code(err)
	}
	if _, err := authn.RequireMember(ctx, h.members, orgID); err != nil {
		return nil, err
	}
	if err := h.svc.AssignRole(ctx, req.Msg.PrincipalId, req.Msg.RoleId, req.Msg.ScopeType, req.Msg.ScopeId); err != nil {
		return nil, code(err)
	}
	return connect.NewResponse(&v1.AssignRoleResponse{}), nil
}
