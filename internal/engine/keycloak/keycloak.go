package keycloak

import (
	"context"
	"fmt"

	"github.com/Nerzal/gocloak/v13"

	"github.com/SilasSolivagus/base-servers/internal/engine"
)

type Config struct {
	BaseURL, Realm, AdminUser, AdminPass string
}

type Adapter struct {
	cli *gocloak.GoCloak
	cfg Config
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

func (a *Adapter) CreatePrincipal(ctx context.Context, p engine.EnginePrincipal) (string, error) {
	tok, err := a.login(ctx)
	if err != nil {
		return "", fmt.Errorf("admin login: %w", err)
	}
	switch p.Type {
	case engine.Human:
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
	// 先按 user 查,查不到再按 client 查。
	if u, err := a.cli.GetUserByID(ctx, tok.AccessToken, a.cfg.Realm, id); err == nil && u != nil {
		return fromAttrs(id, gocloak.PString(u.Username), attrsOf(u.Attributes)), nil
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
