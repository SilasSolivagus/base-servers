package apikey

import (
	"context"
	"errors"
	"net/http"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/SilasSolivagus/base-servers/gen/baseservers/v1"
	"github.com/SilasSolivagus/base-servers/gen/baseservers/v1/baseserversv1connect"
	"github.com/SilasSolivagus/base-servers/internal/audit"
	"github.com/SilasSolivagus/base-servers/internal/authn"
	"github.com/jackc/pgx/v5"
)

type Handler struct {
	store            *Store
	h                *Hasher
	members          authn.MemberChecker
	maxTTL           time.Duration
	allowNeverExpire bool
	keyCap           int
	rec              audit.Recorder
}

func NewHandler(store *Store, h *Hasher, members authn.MemberChecker, maxTTL time.Duration, allowNeverExpire bool, keyCap int, rec audit.Recorder) *Handler {
	return &Handler{store, h, members, maxTTL, allowNeverExpire, keyCap, rec}
}

func (h *Handler) Register(mux *http.ServeMux, opts ...connect.HandlerOption) {
	path, hdl := baseserversv1connect.NewApiKeyServiceHandler(h, opts...)
	mux.Handle(path, hdl)
}

func denied(msg string) error  { return connect.NewError(connect.CodePermissionDenied, errors.New(msg)) }
func invalid(msg string) error { return connect.NewError(connect.CodeInvalidArgument, errors.New(msg)) }

func (h *Handler) Issue(ctx context.Context, req *connect.Request[v1.IssueApiKeyRequest]) (*connect.Response[v1.IssueApiKeyResponse], error) {
	caller, ok := authn.CallerFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("no caller"))
	}
	// C2/K5c: an API key must not mint keys.
	if caller.AuthMethod == "apikey" {
		return nil, denied("api key credentials may not issue keys")
	}
	m := req.Msg
	if m.PrincipalId == "" || m.OrgId == "" {
		return nil, invalid("principal_id and org_id required")
	}
	// K8 + I4: self-sign, or system-admin for anyone (admin bypasses membership).
	if !caller.SystemAdmin {
		if caller.PrincipalID != m.PrincipalId {
			return nil, denied("may only issue keys for yourself")
		}
		member, err := h.members.IsMember(ctx, caller.PrincipalID, m.OrgId)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		if !member {
			return nil, denied("not a member of org")
		}
	}
	// per-principal active key cap (defense-in-depth).
	if n, err := h.store.CountActive(ctx, m.PrincipalId); err == nil && n >= h.keyCap {
		return nil, denied("active key limit reached")
	}
	// I9: max-TTL policy.
	var expPtr *time.Time
	switch {
	case m.TtlSeconds > 0:
		ttl := time.Duration(m.TtlSeconds) * time.Second
		if ttl > h.maxTTL {
			return nil, invalid("ttl_seconds exceeds policy maximum")
		}
		e := time.Now().Add(ttl)
		expPtr = &e
	default: // 0
		if !h.allowNeverExpire {
			e := time.Now().Add(h.maxTTL)
			expPtr = &e
		} // else never expires (expPtr stays nil)
	}

	plaintext, keyID, secret, err := Generate()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := h.store.Insert(ctx, NewKey{
		KeyID: keyID, PrincipalID: m.PrincipalId, OrgID: m.OrgId, Name: m.Name,
		Hash: h.h.Hash(secret), ReadOnly: m.ReadOnly, ExpiresAt: expPtr,
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	aid, at, sa := audit.Actor(ctx)
	h.rec.Record(ctx, audit.Event{ActorID: aid, ActorType: at, SystemAdmin: sa,
		Action: "apikey.issue", TargetType: "apikey", TargetID: keyID, OrgID: m.OrgId,
		Outcome: audit.OutcomeSuccess,
		Detail:  map[string]string{"principal": m.PrincipalId, "name": m.Name, "read_only": boolStr(m.ReadOnly)}})

	var expUnix int64
	if expPtr != nil {
		expUnix = expPtr.Unix()
	}
	return connect.NewResponse(&v1.IssueApiKeyResponse{KeyId: keyID, Secret: plaintext, ExpiresAtUnix: expUnix}), nil
}

func (h *Handler) Revoke(ctx context.Context, req *connect.Request[v1.RevokeApiKeyRequest]) (*connect.Response[v1.RevokeApiKeyResponse], error) {
	caller, ok := authn.CallerFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("no caller"))
	}
	rec, err := h.store.GetByKeyID(ctx, req.Msg.KeyId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("no such key"))
		}
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if !caller.SystemAdmin && caller.PrincipalID != rec.PrincipalID {
		return nil, denied("may only revoke your own keys")
	}
	if _, err := h.store.Revoke(ctx, req.Msg.KeyId); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	aid, at, sa := audit.Actor(ctx)
	h.rec.Record(ctx, audit.Event{ActorID: aid, ActorType: at, SystemAdmin: sa,
		Action: "apikey.revoke", TargetType: "apikey", TargetID: req.Msg.KeyId, OrgID: rec.OrgID,
		Outcome: audit.OutcomeSuccess, Detail: map[string]string{"principal": rec.PrincipalID}})
	return connect.NewResponse(&v1.RevokeApiKeyResponse{}), nil
}

func (h *Handler) List(ctx context.Context, req *connect.Request[v1.ListApiKeysRequest]) (*connect.Response[v1.ListApiKeysResponse], error) {
	caller, ok := authn.CallerFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("no caller"))
	}
	if !caller.SystemAdmin && caller.PrincipalID != req.Msg.PrincipalId {
		return nil, denied("may only list your own keys")
	}
	var after *time.Time
	if req.Msg.PageToken != "" {
		if t, err := time.Parse(time.RFC3339Nano, req.Msg.PageToken); err == nil {
			after = &t
		}
	}
	rows, err := h.store.ListByPrincipal(ctx, req.Msg.PrincipalId, after, req.Msg.PageSize)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &v1.ListApiKeysResponse{}
	for _, r := range rows {
		out.Keys = append(out.Keys, &v1.ApiKeyMeta{
			KeyId: r.KeyID, Name: r.Name, ReadOnly: r.ReadOnly, Revoked: r.Revoked,
			CreatedAtUnix: r.CreatedAt.Unix(), ExpiresAtUnix: unixPtr(r.ExpiresAt), LastUsedAtUnix: unixPtr(r.LastUsedAt),
		})
	}
	if n := len(rows); n > 0 && int32(n) == clampLimit(req.Msg.PageSize) {
		out.NextPageToken = rows[n-1].CreatedAt.Format(time.RFC3339Nano)
	}
	return connect.NewResponse(out), nil
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
func unixPtr(t *time.Time) int64 {
	if t == nil {
		return 0
	}
	return t.Unix()
}
func clampLimit(l int32) int32 {
	if l <= 0 || l > 200 {
		return 100
	}
	return l
}
