package audit

import (
	"context"
	"net/http"
	"time"

	"connectrpc.com/connect"

	v1 "github.com/SilasSolivagus/base-servers/gen/baseservers/v1"
	"github.com/SilasSolivagus/base-servers/gen/baseservers/v1/baseserversv1connect"
	"github.com/SilasSolivagus/base-servers/internal/authn"
)

type Handler struct {
	store   *Store
	members authn.MemberChecker
}

func NewHandler(store *Store, members authn.MemberChecker) *Handler {
	return &Handler{store: store, members: members}
}

func (h *Handler) Register(mux *http.ServeMux, opts ...connect.HandlerOption) {
	path, hdl := baseserversv1connect.NewAuditServiceHandler(h, opts...)
	mux.Handle(path, hdl)
}

// authorize:system chain 仅 system-admin;org chain 需成员(system-admin 放行)。
func (h *Handler) authorize(ctx context.Context, orgID string) error {
	if orgID == "" || orgID == "system" {
		return authn.RequireSystemAdmin(ctx)
	}
	_, err := authn.RequireMember(ctx, h.members, orgID)
	return err
}

func rfc(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func (h *Handler) List(ctx context.Context, req *connect.Request[v1.ListRequest]) (*connect.Response[v1.ListResponse], error) {
	if err := h.authorize(ctx, req.Msg.OrgId); err != nil {
		return nil, err
	}
	f := ListFilter{
		Chain: ChainOf(req.Msg.OrgId), ActorID: req.Msg.ActorId, Action: req.Msg.Action, Outcome: req.Msg.Outcome,
		Limit: req.Msg.PageSize, AfterSeq: req.Msg.AfterSeq,
	}
	if req.Msg.From != "" {
		f.From, _ = time.Parse(time.RFC3339, req.Msg.From)
	}
	if req.Msg.To != "" {
		f.To, _ = time.Parse(time.RFC3339, req.Msg.To)
	}
	evs, err := h.store.List(ctx, f)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &v1.ListResponse{}
	for _, e := range evs {
		out.Events = append(out.Events, &v1.AuditEvent{
			Seq: e.Seq, Ts: rfc(e.Ts), ActorId: e.ActorID, ActorType: e.ActorType, SystemAdmin: e.SystemAdmin,
			Action: e.Action, TargetType: e.TargetType, TargetId: e.TargetID, OrgId: e.OrgID, Outcome: e.Outcome, Detail: e.Detail,
		})
		out.NextAfterSeq = e.Seq
	}
	return connect.NewResponse(out), nil
}

func (h *Handler) Verify(ctx context.Context, req *connect.Request[v1.VerifyRequest]) (*connect.Response[v1.VerifyResponse], error) {
	chain := ChainOf(req.Msg.OrgId)
	if err := h.authorize(ctx, req.Msg.OrgId); err != nil {
		return nil, err
	}
	ok, broken, err := h.store.Verify(ctx, chain)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&v1.VerifyResponse{Ok: ok, BrokenAtSeq: broken}), nil
}
