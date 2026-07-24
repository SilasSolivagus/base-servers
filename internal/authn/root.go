package authn

import (
	"context"
	"crypto/subtle"
	"net/http"
)

// CheckRoot reports whether the request carries the break-glass root token (present)
// and whether it is valid. valid requires a configured non-empty rootToken AND a
// non-empty header — this guards against the ConstantTimeCompare("","")==1 trap when
// BS_ROOT_TOKEN is unset.
func CheckRoot(h http.Header, rootToken []byte) (present, valid bool) {
	rt := h.Get("X-BS-Root-Token")
	present = rt != ""
	valid = len(rootToken) > 0 && present && subtle.ConstantTimeCompare([]byte(rt), rootToken) == 1
	return present, valid
}

// ThrottleEvent describes a rate-limit denial (or a failed root-token attempt) for audit.
// Pre-auth events (Gate A / root.auth) carry no PrincipalID and use IPPrefix.
type ThrottleEvent struct {
	Gate        string // "global" | "ip" | "principal" | "root.auth"
	IPPrefix    string // v6 /64 or v4 /24 prefix (never a full address); empty for principal gate
	PrincipalID string // set only for Gate B
	AuthMethod  string
	Reason      string
}

// ThrottleHook receives throttle/auth-failure events. Defined here (consumer side) so
// authn/server never import audit; main supplies an adapter over audit.Recorder.
type ThrottleHook func(ctx context.Context, ev ThrottleEvent)
