package org

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
	path, hdl := baseserversv1connect.NewOrgServiceHandler(h, opts...)
	mux.Handle(path, hdl)
}

func errCode(err error) error {
	switch {
	case errors.Is(err, ErrInvalidInput):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}

func (h *Handler) CreateOrganization(ctx context.Context, req *connect.Request[v1.CreateOrganizationRequest]) (*connect.Response[v1.CreateOrganizationResponse], error) {
	o, err := h.svc.CreateOrg(ctx, req.Msg.Name)
	if err != nil {
		return nil, errCode(err)
	}
	return connect.NewResponse(&v1.CreateOrganizationResponse{
		Organization: &v1.Organization{Id: o.ID, Name: o.Name, ParentId: o.ParentID},
	}), nil
}

func (h *Handler) CreateTeam(ctx context.Context, req *connect.Request[v1.CreateTeamRequest]) (*connect.Response[v1.CreateTeamResponse], error) {
	tm, err := h.svc.CreateTeam(ctx, req.Msg.OrgId, req.Msg.Name)
	if err != nil {
		return nil, errCode(err)
	}
	return connect.NewResponse(&v1.CreateTeamResponse{Team: &v1.Team{Id: tm.ID, OrgId: tm.OrgID, Name: tm.Name}}), nil
}

func (h *Handler) AddMember(ctx context.Context, req *connect.Request[v1.AddMemberRequest]) (*connect.Response[v1.AddMemberResponse], error) {
	if err := h.svc.AddMember(ctx, req.Msg.PrincipalId, req.Msg.OrgId); err != nil {
		return nil, errCode(err)
	}
	return connect.NewResponse(&v1.AddMemberResponse{}), nil
}

func (h *Handler) AddTeamMember(ctx context.Context, req *connect.Request[v1.AddTeamMemberRequest]) (*connect.Response[v1.AddTeamMemberResponse], error) {
	if err := h.svc.AddTeamMember(ctx, req.Msg.PrincipalId, req.Msg.TeamId); err != nil {
		return nil, errCode(err)
	}
	return connect.NewResponse(&v1.AddTeamMemberResponse{}), nil
}
