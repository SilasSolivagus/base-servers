package keycloak

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/Nerzal/gocloak/v13"

	"github.com/SilasSolivagus/base-servers/internal/engine"
)

type Config struct {
	BaseURL, Realm, AdminUser, AdminPass string
}

type Adapter struct {
	cli *gocloak.GoCloak
	cfg Config
	// unmanagedAttrsEnsured is set true after ensureUnmanagedUserAttributes
	// succeeds once, so subsequent CreatePrincipal(Human) calls skip the
	// extra GET/PUT round trip. Left false on failure so it retries.
	unmanagedAttrsEnsured bool
}

func New(cfg Config) (*Adapter, error) {
	return &Adapter{cli: gocloak.NewClient(cfg.BaseURL), cfg: cfg}, nil
}

// Keycloak 26.4：token-exchange 与 DPoP 均 GA;CAEP 未纳入 v1。
func (a *Adapter) Capabilities() engine.Capabilities {
	return engine.Capabilities{TokenExchange: true, DPoP: true, CAEP: false}
}

func (a *Adapter) login(ctx context.Context) (*gocloak.JWT, error) {
	return a.cli.LoginAdmin(ctx, a.cfg.AdminUser, a.cfg.AdminPass, "master")
}

// ensureUnmanagedUserAttributes 确保 realm 的 user-profile 配置允许 unmanaged
// attributes,否则 CreateUser 传入的 bs_* 自定义属性会被 Keycloak 静默丢弃。
// gocloak/v13.9.0 未封装 users/profile 接口,这里直接复用其已导出的
// GetRequestWithBearerAuth 发原始请求。
func (a *Adapter) ensureUnmanagedUserAttributes(ctx context.Context, token string) error {
	if a.unmanagedAttrsEnsured {
		return nil
	}
	url := a.cfg.BaseURL + "/admin/realms/" + a.cfg.Realm + "/users/profile"
	var profile map[string]interface{}
	getResp, err := a.cli.GetRequestWithBearerAuth(ctx, token).SetResult(&profile).Get(url)
	if err != nil {
		return fmt.Errorf("get user profile config: %w", err)
	}
	if getResp.IsError() {
		return fmt.Errorf("get user profile config: status %d: %s", getResp.StatusCode(), getResp.String())
	}
	if profile == nil {
		profile = map[string]interface{}{}
	}
	if profile["unmanagedAttributePolicy"] == "ENABLED" {
		a.unmanagedAttrsEnsured = true
		return nil
	}
	profile["unmanagedAttributePolicy"] = "ENABLED"
	putResp, err := a.cli.GetRequestWithBearerAuth(ctx, token).SetBody(profile).Put(url)
	if err != nil {
		return fmt.Errorf("update user profile config: %w", err)
	}
	if putResp.IsError() {
		return fmt.Errorf("update user profile config: status %d: %s", putResp.StatusCode(), putResp.String())
	}
	a.unmanagedAttrsEnsured = true
	return nil
}

func (a *Adapter) CreatePrincipal(ctx context.Context, p engine.EnginePrincipal) (string, error) {
	tok, err := a.login(ctx)
	if err != nil {
		return "", fmt.Errorf("admin login: %w", err)
	}
	switch p.Type {
	case engine.Human:
		// Keycloak 26 默认启用 declarative user profile,未在 realm user-profile 中
		// 声明的自定义属性(如 bs_type/bs_*)会被静默丢弃,必须先放开 unmanaged attributes。
		if err := a.ensureUnmanagedUserAttributes(ctx, tok.AccessToken); err != nil {
			return "", fmt.Errorf("configure user profile: %w", err)
		}
		attrs := map[string][]string{"bs_type": {string(p.Type)}}
		for k, v := range p.Metadata {
			attrs["bs_"+k] = []string{v}
		}
		id, err := a.cli.CreateUser(ctx, tok.AccessToken, a.cfg.Realm, gocloak.User{
			Username:   gocloak.StringP(p.DisplayName),
			Enabled:    gocloak.BoolP(true),
			Attributes: &attrs,
		})
		return id, err
	case engine.Service, engine.Agent:
		// gocloak.Client.Attributes 是 map[string]string(非 []string),与 User 不同。
		attrs := map[string]string{"bs_type": string(p.Type)}
		for k, v := range p.Metadata {
			attrs["bs_"+k] = v
		}
		id, err := a.cli.CreateClient(ctx, tok.AccessToken, a.cfg.Realm, gocloak.Client{
			ClientID:               gocloak.StringP("bs-" + p.DisplayName),
			ServiceAccountsEnabled: gocloak.BoolP(true),
			StandardFlowEnabled:    gocloak.BoolP(false),
			Attributes:             &attrs,
		})
		return id, err
	default:
		return "", fmt.Errorf("unsupported principal type %q", p.Type)
	}
}

func (a *Adapter) GetPrincipal(ctx context.Context, id string) (engine.EnginePrincipal, error) {
	tok, err := a.login(ctx)
	if err != nil {
		return engine.EnginePrincipal{}, err
	}
	// 先按 user 查,查不到(404)再按 client 查;其他错误(网络/鉴权等)直接向上传播。
	u, err := a.cli.GetUserByID(ctx, tok.AccessToken, a.cfg.Realm, id)
	if err == nil && u != nil {
		return fromAttrs(id, gocloak.PString(u.Username), attrsOf(u.Attributes)), nil
	}
	if err != nil {
		var apiErr *gocloak.APIError
		if !errors.As(err, &apiErr) || apiErr.Code != http.StatusNotFound {
			return engine.EnginePrincipal{}, fmt.Errorf("get user %q: %w", id, err)
		}
	}
	c, err := a.cli.GetClient(ctx, tok.AccessToken, a.cfg.Realm, id)
	if err != nil {
		return engine.EnginePrincipal{}, fmt.Errorf("principal %q not found: %w", id, err)
	}
	return fromAttrs(id, gocloak.PString(c.ClientID), attrsOfSingle(c.Attributes)), nil
}

func attrsOf(m *map[string][]string) map[string][]string {
	if m == nil {
		return map[string][]string{}
	}
	return *m
}

// attrsOfSingle 把 Client.Attributes(map[string]string)归一化成 map[string][]string,
// 以便复用 fromAttrs。
func attrsOfSingle(m *map[string]string) map[string][]string {
	out := map[string][]string{}
	if m == nil {
		return out
	}
	for k, v := range *m {
		out[k] = []string{v}
	}
	return out
}

func fromAttrs(id, name string, attrs map[string][]string) engine.EnginePrincipal {
	meta := map[string]string{}
	var typ engine.PrincipalType
	for k, v := range attrs {
		if len(v) == 0 {
			continue
		}
		if k == "bs_type" {
			typ = engine.PrincipalType(v[0])
			continue
		}
		if len(k) > 3 && k[:3] == "bs_" {
			meta[k[3:]] = v[0]
		}
	}
	return engine.EnginePrincipal{ID: id, Type: typ, DisplayName: name, Metadata: meta}
}
