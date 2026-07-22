package audit

import (
	"context"

	"github.com/SilasSolivagus/base-servers/internal/authn"
)

// Actor 从 ctx 取 caller,组装写操作埋点用的 actor 三元组。
// 调用点在真正执行了变更、拿到 target id 之后使用。
func Actor(ctx context.Context) (id, typ string, sysAdmin bool) {
	if c, ok := authn.CallerFromContext(ctx); ok {
		if c.SystemAdmin {
			return c.PrincipalID, ActorSystem, true
		}
		return c.PrincipalID, "", false // 类型未知时留空,查询仍可用 actor_id
	}
	return "", ActorSystem, false
}
