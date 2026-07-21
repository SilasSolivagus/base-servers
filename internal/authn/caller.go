package authn

import "context"

// Caller 是一次已认证请求的主体身份。
type Caller struct {
	PrincipalID string // = 令牌 sub(= base-servers principal id)
	SystemAdmin bool   // 经 root-token bootstrap 路径
}

type ctxKey struct{}

func WithCaller(ctx context.Context, c Caller) context.Context {
	return context.WithValue(ctx, ctxKey{}, c)
}

func CallerFromContext(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(ctxKey{}).(Caller)
	return c, ok
}
