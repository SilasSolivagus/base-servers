package delegation

import (
	"context"
	"time"

	"github.com/SilasSolivagus/base-servers/internal/authz"
)

type Checker struct {
	store  *Store
	signer *Signer
	authz  authz.Checker
}

func NewChecker(store *Store, signer *Signer, az authz.Checker) *Checker {
	return &Checker{store: store, signer: signer, authz: az}
}

// CheckDelegated: 验签 → 查委托记录(黑名单/过期)→ delegator ∩ scope。
// 忽略 agent 自身角色(防混淆代理)。用授权人当前权限。
func (c *Checker) CheckDelegated(ctx context.Context, token, action string, res authz.Resource) (bool, error) {
	claims, err := c.signer.Verify(token) // 验签 + exp
	if err != nil {
		return false, nil // 无效令牌 → 拒(fail closed)
	}
	d, err := c.store.Get(ctx, claims.DelegationID)
	if err != nil {
		return false, nil // 找不到记录 → 拒
	}
	if d.Revoked || time.Now().After(d.ExpiresAt) {
		return false, nil // 黑名单/过期 → 拒
	}
	if res.OrgID != d.OrgID {
		return false, nil // delegation is scoped to its org
	}
	if !contains(d.Scope, action) {
		return false, nil // 范围外 → 拒
	}
	// 上限:授权人当前是否有此权限。忽略 agent 自身角色。
	return c.authz.Check(ctx, d.DelegatorID, action, res)
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
