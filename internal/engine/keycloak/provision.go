package keycloak

import (
	"context"
	"fmt"

	"github.com/Nerzal/gocloak/v13"
)

func p[T any](v T) *T { return &v }

// EnsureProvisioned 幂等确保 base-servers realm + 登录/服务两 client 存在且配置正确。
func (a *Adapter) EnsureProvisioned(ctx context.Context) error {
	jwt, err := a.login(ctx)
	if err != nil {
		return fmt.Errorf("admin login: %w", err)
	}
	if err := a.ensureRealm(ctx, jwt.AccessToken); err != nil {
		return err
	}
	return a.ensureClients(ctx, jwt.AccessToken)
}

func (a *Adapter) ensureRealm(ctx context.Context, token string) error {
	if _, err := a.cli.GetRealm(ctx, token, a.cfg.Realm); err == nil {
		return nil // 已存在
	}
	_, err := a.cli.CreateRealm(ctx, token, gocloak.RealmRepresentation{
		Realm:       p(a.cfg.Realm),
		Enabled:     p(true),
		SslRequired: p("none"), // alpha/自托管:HTTP 前门经网关;生产在网关侧终止 TLS
	})
	if err != nil {
		return fmt.Errorf("create realm %s: %w", a.cfg.Realm, err)
	}
	return nil
}

func (a *Adapter) ensureClients(ctx context.Context, token string) error {
	// 登录 client:public + auth-code + PKCE(S256)
	login := gocloak.Client{
		ClientID:                  p(a.cfg.LoginClientID),
		PublicClient:              p(true),
		StandardFlowEnabled:       p(true),
		DirectAccessGrantsEnabled: p(false),
		RedirectURIs:              p(a.cfg.LoginRedirectURIs),
		Attributes:                p(map[string]string{"pkce.code.challenge.method": "S256"}),
	}
	if err := a.upsertClient(ctx, token, login); err != nil {
		return err
	}
	// 服务 client:confidential + client-credentials(service accounts)
	service := gocloak.Client{
		ClientID:                  p(a.cfg.ServiceClientID),
		PublicClient:              p(false),
		StandardFlowEnabled:       p(false),
		DirectAccessGrantsEnabled: p(false), // 仅 client-credentials,禁 ROPC 密码授权
		ServiceAccountsEnabled:    p(true),
		FullScopeAllowed:          p(false), // 最小权限:token 不携带全部 realm 角色,授权由 base-servers 自行处理
		Secret:                    p(a.cfg.ServiceClientSecret),
	}
	return a.upsertClient(ctx, token, service)
}

// upsertClient 幂等:不存在则建;存在则用 UpdateClient 收敛回期望态(drift 修正)。
func (a *Adapter) upsertClient(ctx context.Context, token string, want gocloak.Client) error {
	existing, err := a.cli.GetClients(ctx, token, a.cfg.Realm, gocloak.GetClientsParams{ClientID: want.ClientID})
	if err != nil {
		return fmt.Errorf("get clients: %w", err)
	}
	if len(existing) == 0 {
		if _, err := a.cli.CreateClient(ctx, token, a.cfg.Realm, want); err != nil {
			return fmt.Errorf("create client %s: %w", *want.ClientID, err)
		}
		return nil
	}
	want.ID = existing[0].ID // 更新需带 internal id
	if err := a.cli.UpdateClient(ctx, token, a.cfg.Realm, want); err != nil {
		return fmt.Errorf("update client %s: %w", *want.ClientID, err)
	}
	return nil
}

type ClientStatus struct {
	Public, StandardFlow, ServiceAccounts bool
	DirectAccessGrants                    bool
	PKCE                                  string
	RedirectURIs                          []string
}
type ProvisionState struct {
	RealmExists   bool
	LoginClient   ClientStatus
	ServiceClient ClientStatus
}

func (a *Adapter) ProvisionStatus(ctx context.Context) (ProvisionState, error) {
	jwt, err := a.login(ctx)
	if err != nil {
		return ProvisionState{}, err
	}
	var st ProvisionState
	if _, err := a.cli.GetRealm(ctx, jwt.AccessToken, a.cfg.Realm); err == nil {
		st.RealmExists = true
	}
	st.LoginClient, _ = a.clientStatus(ctx, jwt.AccessToken, a.cfg.LoginClientID)
	st.ServiceClient, _ = a.clientStatus(ctx, jwt.AccessToken, a.cfg.ServiceClientID)
	return st, nil
}

func (a *Adapter) clientStatus(ctx context.Context, token, clientID string) (ClientStatus, error) {
	cs, err := a.cli.GetClients(ctx, token, a.cfg.Realm, gocloak.GetClientsParams{ClientID: &clientID})
	if err != nil || len(cs) == 0 {
		return ClientStatus{}, err
	}
	c := cs[0]
	out := ClientStatus{}
	if c.PublicClient != nil {
		out.Public = *c.PublicClient
	}
	if c.StandardFlowEnabled != nil {
		out.StandardFlow = *c.StandardFlowEnabled
	}
	if c.ServiceAccountsEnabled != nil {
		out.ServiceAccounts = *c.ServiceAccountsEnabled
	}
	if c.DirectAccessGrantsEnabled != nil {
		out.DirectAccessGrants = *c.DirectAccessGrantsEnabled
	}
	if c.RedirectURIs != nil {
		out.RedirectURIs = *c.RedirectURIs
	}
	if c.Attributes != nil {
		out.PKCE = (*c.Attributes)["pkce.code.challenge.method"]
	}
	return out, nil
}
