package delegation

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

func (h *Handler) Register(mux *http.ServeMux) {
	path, hdl := baseserversv1connect.NewDelegationServiceHandler(h)
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
	tok, id, err := h.svc.Issue(ctx, IssueInput{
		AgentID: req.Msg.AgentId, DelegatorID: req.Msg.DelegatorId, OrgID: req.Msg.OrgId,
		Scope: req.Msg.Scope, TTLSeconds: req.Msg.TtlSeconds,
	})
	if err != nil {
		return nil, code(err)
	}
	return connect.NewResponse(&v1.IssueResponse{Token: tok, DelegationId: id}), nil
}

func (h *Handler) Revoke(ctx context.Context, req *connect.Request[v1.RevokeRequest]) (*connect.Response[v1.RevokeResponse], error) {
	if err := h.svc.Revoke(ctx, req.Msg.DelegationId); err != nil {
		return nil, code(err)
	}
	return connect.NewResponse(&v1.RevokeResponse{}), nil
}
