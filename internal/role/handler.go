package role

import (
	"context"
	"errors"
	"net/http"

	"connectrpc.com/connect"

	v1 "github.com/SilasSolivagus/base-servers/gen/baseservers/v1"
	"github.com/SilasSolivagus/base-servers/gen/baseservers/v1/baseserversv1connect"
)

type Handler struct{ svc *Service }

func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

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
	r, err := h.svc.CreateRole(ctx, req.Msg.OrgId, req.Msg.Name, req.Msg.Permissions)
	if err != nil {
		return nil, code(err)
	}
	return connect.NewResponse(&v1.CreateRoleResponse{
		Role: &v1.Role{Id: r.ID, OrgId: r.OrgID, Name: r.Name, Permissions: r.Permissions},
	}), nil
}

func (h *Handler) AssignRole(ctx context.Context, req *connect.Request[v1.AssignRoleRequest]) (*connect.Response[v1.AssignRoleResponse], error) {
	if err := h.svc.AssignRole(ctx, req.Msg.PrincipalId, req.Msg.RoleId, req.Msg.ScopeType, req.Msg.ScopeId); err != nil {
		return nil, code(err)
	}
	return connect.NewResponse(&v1.AssignRoleResponse{}), nil
}
