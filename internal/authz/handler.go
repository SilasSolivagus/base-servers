package authz

import (
	"context"
	"net/http"

	"connectrpc.com/connect"

	v1 "github.com/SilasSolivagus/base-servers/gen/baseservers/v1"
	"github.com/SilasSolivagus/base-servers/gen/baseservers/v1/baseserversv1connect"
)

type Handler struct {
	svc   *Service
	store *Store
}

func NewHandler(svc *Service, store *Store) *Handler { return &Handler{svc: svc, store: store} }

func (h *Handler) Register(mux *http.ServeMux) {
	path, hdl := baseserversv1connect.NewAuthzServiceHandler(h)
	mux.Handle(path, hdl)
}

func (h *Handler) Check(ctx context.Context, req *connect.Request[v1.CheckRequest]) (*connect.Response[v1.CheckResponse], error) {
	allowed, err := h.svc.Check(ctx, req.Msg.Subject, req.Msg.Action, Resource{
		Type: req.Msg.ResourceType, ID: req.Msg.ResourceId, OrgID: req.Msg.OrgId, TeamID: req.Msg.TeamId,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return connect.NewResponse(&v1.CheckResponse{Allowed: allowed}), nil
}

func (h *Handler) RegisterOwnership(ctx context.Context, req *connect.Request[v1.RegisterOwnershipRequest]) (*connect.Response[v1.RegisterOwnershipResponse], error) {
	if err := h.store.RegisterOwnership(ctx, req.Msg.ResourceType, req.Msg.ResourceId, req.Msg.OwnerPrincipalId, req.Msg.OrgId); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return connect.NewResponse(&v1.RegisterOwnershipResponse{}), nil
}
