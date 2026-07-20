package engine

import "context"

type PrincipalType string

const (
	Human   PrincipalType = "human"
	Service PrincipalType = "service"
	Agent   PrincipalType = "agent"
)

type Capabilities struct {
	TokenExchange bool
	DPoP          bool
	CAEP          bool
}

type EnginePrincipal struct {
	ID          string
	Type        PrincipalType
	DisplayName string
	Metadata    map[string]string // agent 的 owner/purpose 等作为 metadata 透传
}

type IdentityEngine interface {
	Capabilities() Capabilities
	CreatePrincipal(ctx context.Context, p EnginePrincipal) (string, error)
	GetPrincipal(ctx context.Context, id string) (EnginePrincipal, error)
}
