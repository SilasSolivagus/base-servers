package principal

import (
	"context"
	"errors"
	"net/http"

	"connectrpc.com/connect"

	v1 "github.com/SilasSolivagus/base-servers/gen/baseservers/v1"
	"github.com/SilasSolivagus/base-servers/gen/baseservers/v1/baseserversv1connect"
	"github.com/SilasSolivagus/base-servers/internal/audit"
	"github.com/SilasSolivagus/base-servers/internal/authn"
	"github.com/SilasSolivagus/base-servers/internal/engine"
)

type Handler struct {
	svc *Service
	rec audit.Recorder
}

func NewHandler(svc *Service, rec audit.Recorder) *Handler { return &Handler{svc: svc, rec: rec} }

func (h *Handler) Register(mux *http.ServeMux, opts ...connect.HandlerOption) {
	path, hdl := baseserversv1connect.NewPrincipalServiceHandler(h, opts...)
	mux.Handle(path, hdl)
}

var typeToProto = map[engine.PrincipalType]v1.PrincipalType{
	engine.Human:   v1.PrincipalType_PRINCIPAL_TYPE_HUMAN,
	engine.Service: v1.PrincipalType_PRINCIPAL_TYPE_SERVICE,
	engine.Agent:   v1.PrincipalType_PRINCIPAL_TYPE_AGENT,
}
var protoToType = map[v1.PrincipalType]engine.PrincipalType{
	v1.PrincipalType_PRINCIPAL_TYPE_HUMAN:   engine.Human,
	v1.PrincipalType_PRINCIPAL_TYPE_SERVICE: engine.Service,
	v1.PrincipalType_PRINCIPAL_TYPE_AGENT:   engine.Agent,
}

func toProto(p Principal) *v1.Principal {
	return &v1.Principal{
		Id: p.ID, Type: typeToProto[p.Type], DisplayName: p.DisplayName,
		OwnerPrincipalId: p.OwnerPrincipalID, Capabilities: p.Capabilities,
		Purpose: p.Purpose, OnBehalfOf: p.OnBehalfOf,
	}
}

func (h *Handler) CreatePrincipal(ctx context.Context, req *connect.Request[v1.CreatePrincipalRequest]) (*connect.Response[v1.CreatePrincipalResponse], error) {
	if err := authn.RequireSystemAdmin(ctx); err != nil {
		return nil, err
	}
	p, err := h.svc.Create(ctx, NewInput{
		Type:             protoToType[req.Msg.Type],
		DisplayName:      req.Msg.DisplayName,
		OwnerPrincipalID: req.Msg.OwnerPrincipalId,
		Capabilities:     req.Msg.Capabilities,
		Purpose:          req.Msg.Purpose,
	})
	if err != nil {
		if errors.Is(err, ErrInvalidInput) {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	aid, at, sa := audit.Actor(ctx)
	h.rec.Record(ctx, audit.Event{ActorID: aid, ActorType: at, SystemAdmin: sa,
		Action: "principal.create", TargetType: "principal", TargetID: p.ID, OrgID: "",
		Outcome: audit.OutcomeSuccess, Detail: map[string]string{"display_name": p.DisplayName}})
	return connect.NewResponse(&v1.CreatePrincipalResponse{Principal: toProto(p)}), nil
}

func (h *Handler) GetPrincipal(ctx context.Context, req *connect.Request[v1.GetPrincipalRequest]) (*connect.Response[v1.GetPrincipalResponse], error) {
	p, err := h.svc.Get(ctx, req.Msg.Id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, err)
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&v1.GetPrincipalResponse{Principal: toProto(p)}), nil
}
