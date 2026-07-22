<div align="center">

# base-servers

### The identity & permission layer for the agentic era.

**Accounts, organizations, and authorization — for humans, services, and AI agents alike.**
Self-hosted. Multi-tenant. Standards-based. Stop rebuilding this layer in every system — just call it.

![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)
![Status](https://img.shields.io/badge/status-alpha-orange)
![Ring 0](https://img.shields.io/badge/Ring%200-all%204%20phases%20shipped-brightgreen)
![Tests](https://img.shields.io/badge/tests-green%20(real%20containers)-brightgreen)
![PRs](https://img.shields.io/badge/PRs-welcome-blueviolet)

</div>

---

> **Status: early / alpha.** All four Ring 0 phases are built and tested end-to-end against real Keycloak + Postgres: identity (human / service / agent principals), organizations & RBAC/ownership, **agent delegation** (the headline), and the front-door & delivery layer — OIDC login front-door, one-command deploy, and an **authenticated** control plane (Keycloak bearer tokens + org-membership + delegation-authority enforcement). Outer rings are next on the [roadmap](#-roadmap). Not production-ready yet.
>
> **⚠️ Operational constraints (alpha) — read before deploying:**
> - **Control-plane RPCs are now authenticated.** Every Connect RPC requires a valid Keycloak access token (`Authorization: Bearer …`), obtained via the [OIDC front-door](#-oidc-front-door); an anonymous caller gets `Unauthenticated`. Org-scoped RPCs additionally enforce that the caller is a member of the target org, and delegation `Issue` requires the caller to *be* the delegator — so a caller can only delegate its own authority (a caller can never mint a delegation naming someone else as the delegator). `X-BS-Root-Token` (`BS_ROOT_TOKEN`) is a break-glass bootstrap credential for the initial cross-tenant setup (registering the first principals, creating the first org + owner) — treat it like the signing KEK: env-injected, never committed, used only to bootstrap before any org/membership exists.
> - **Multi-replica ready.** Delegation signing keys are persisted in Postgres (envelope-encrypted with an env `BS_SIGNING_KEK`) and shared across replicas, with rotation via the `rotate-signing-key` command. Set `BS_SIGNING_KEK` to the base64 of 32 random bytes; the service refuses to start without it.
> - **Key rotation is break-glass, with a bounded window.** `rotate-signing-key` opens a **fail-closed** window (~90s = 30s internal keyset cache + 60s JWKS `max-age`) where freshly minted tokens under the new key may be *rejected* by not-yet-refreshed replicas and external verifiers until JWKS caches converge — no wrongful accepts, self-healing. Rotate during low traffic, treat rotation as complete only after ≥90s, and don't rotate twice within that window. Previously-issued tokens stay valid (old keys are retained ~25h ≥ max token TTL). True two-phase (publish-then-promote) rotation is planned and additive.

## Why base-servers

Every new system rebuilds the same plumbing: accounts, login, sessions, orgs, roles, permissions. It's weeks of undifferentiated work, re-implemented (and re-broken) everywhere, and it's exactly the layer where a subtle bug becomes a breach.

Worse, a new kind of user just arrived that traditional IAM was never designed for: **AI agents**. Agents cross trust boundaries, act *on behalf of* people, and move at machine speed. Hand one your API key and you've given away a permanent, over-privileged, unrevocable, unauditable credential.

**base-servers is that layer, done once, done right — and built agent-native from day one.**

## ✨ What makes it different

- **Three first-class principals — human · service · AI agent.** Not "users, plus a bolted-on token." Agents are modeled as their own principal type, with an owner, a purpose, and a delegation chain.
- **Agent-native delegation** *(Phase 3)* — an agent gets a **scoped, time-boxed, revocable** credential whose authority **can never exceed the person who granted it**, via OAuth2 Token Exchange / On-Behalf-Of. Every action stays attributable; a kill-switch revokes in seconds.
- **Pluggable identity engine behind a clean adapter.** We don't reinvent OAuth crypto — we compose a proven engine behind a capability-flagged interface, so you're never locked to one vendor.
- **Self-hosted & multi-tenant from day one.** One shared deployment serves all your systems and tenants; your data stays yours.
- **Speak the lingua franca.** OAuth2 / OIDC for auth; a single [Connect](https://connectrpc.com) handler serves gRPC, gRPC-Web, and plain HTTP/JSON — callable from any language in a few lines.
- **Modular onion.** A tiny mandatory core plus optional, independently-adoptable modules. Enable only what your product shape actually needs — no swallowing the whole platform.

## 🏗 Architecture

<div align="center">
  <img src="docs/diagrams/ring0-architecture.png" alt="base-servers Ring 0 architecture" width="820">
</div>

Consumers (any system, or an AI agent) talk to the **base-servers API layer** over OIDC / gRPC / REST. That layer owns the net-new value — the unified API, the agent delegation logic, and permission checks — and sits on a swappable **identity engine** + PostgreSQL behind an adapter. The engine is an implementation detail; you program against base-servers' own API.

## 🚀 Quick start

> Phase 1 lets you create and fetch principals (human / service / agent) end-to-end.

```bash
# 1. Bring up the stack (identity engine + Postgres)
docker compose -f deploy/docker-compose.yml up -d

# 2. Apply the schema
export DATABASE_URL="postgres://base:base@localhost:5432/baseservers?sslmode=disable"
goose -dir db/migrations postgres "$DATABASE_URL" up

# 3. Run base-servers
KEYCLOAK_URL=http://localhost:8080 go run ./cmd/base-servers
```

```bash
# Health
curl -s localhost:8081/healthz            # -> ok

# Register an AI agent as a first-class principal (Connect JSON over HTTP)
curl -X POST localhost:8081/baseservers.v1.PrincipalService/CreatePrincipal \
  -H 'Content-Type: application/json' \
  -d '{"type":"PRINCIPAL_TYPE_AGENT","displayName":"planner","ownerPrincipalId":"u1","purpose":"triage"}'
```

Everything above is covered by tests that spin up **real** Keycloak + Postgres containers — no mocks.

## 🔐 OIDC front-door

`deploy/docker-compose.yml` ships a thin [Caddy](https://caddyserver.com) gateway (`caddy` service, public port `8088`) so the public **issuer, discovery, and `jwks_uri` URLs** are pinned to one public domain rather than Keycloak's own hostname:

- `${BS_PUBLIC_URL}/oidc/*` → proxied (prefix stripped) to Keycloak. `KC_HOSTNAME` is set to `${BS_PUBLIC_URL}/oidc`, so Keycloak itself emits `iss`, discovery, and `jwks_uri` under that public, neutral `/oidc` path — not `keycloak:8080`. The public issuer is `<BS_PUBLIC_URL>/oidc/realms/base-servers`. Note `BS_PUBLIC_URL` must have **no trailing slash** — it's concatenated directly with `/oidc`.
- Everything else → proxied to `base-servers`.

This means base-servers never re-signs or proxies login tokens — the gateway is a compose-layer routing concern, not something the Go process does. If the identity engine is ever swapped out, the issuer stays pinned to the base-servers domain.

**Dev-vs-prod note:** the compose file also publishes Keycloak's own port `8080:8080` directly on the host, and the realm is created with `sslRequired: none` — both are dev conveniences so you can hit Keycloak's admin console without the gateway. For a real deployment, drop the `8080:8080` port mapping (Keycloak should only be reachable via the Caddy gateway) and raise `sslRequired` once TLS is terminated at the gateway.

Two OIDC clients are provisioned at startup (`EnsureProvisioned`, idempotent):

- **`base-servers-login`** — public client, PKCE (S256), authorization-code flow, for humans/UIs. Redirect URIs come from `OIDC_LOGIN_REDIRECT_URIS` (comma-separated; defaults to `http://localhost:8088/callback`). This env list is the source of truth: `EnsureProvisioned` re-asserts it on every restart, so any redirect URI added by hand in the Keycloak console is non-durable and will be overwritten. Dynamic, per-app redirect-URI registration (an API instead of a static env list) is deferred to a later phase.
- **`base-servers-service`** — confidential client, client-credentials flow only (`directAccessGrantsEnabled: false`, no ROPC password grant), least-privilege scope (`fullScopeAllowed: false`), for service-to-service calls. Its secret is supplied via `BS_SERVICE_CLIENT_SECRET` (required; the process fails closed at startup if unset).

## 🗺 Roadmap

base-servers is scoped as an onion — a small mandatory core, then optional rings. **Ring 0** (identity + org + authz) is the first sub-project, delivered in four phases:

| Phase | Scope | Status |
|-------|-------|--------|
| **1 · Foundation** | Go service, pluggable identity-engine adapter, three-type principals, Postgres store, Connect RPC API | ✅ **Shipped** |
| **2 · Org & Permissions** | Organizations, teams, membership, RBAC roles, `check(subject, action, resource)`, resource ownership | ✅ **Shipped** |
| **3 · Agent Delegation** *(the headline)* | Token-exchange narrow tokens, effective-perms ≤ delegator, short-TTL + denylist revocation, DPoP sender-binding | ✅ **Shipped** |
| **4 · Front-door & Delivery** | OIDC-fronted login + SSO, headless admin API, multi-tenant isolation, one-command deploy | ✅ **Shipped** — OIDC login front-door (public issuer + Caddy gateway), authenticated Connect admin API (Keycloak bearer + org-membership + delegation-authority enforcement), one-command docker-compose deploy |

Outer rings (notifications, audit, billing, webhooks, agent-to-agent messaging …) come later, each as its own module.

<details>
<summary>See the Phase 1 implementation status on the architecture map</summary>

<div align="center">
  <img src="docs/diagrams/ring0-architecture-phase1-status.png" alt="Phase 1 implementation status" width="820">
</div>
</details>

## 🧱 Tech

Go · [Connect](https://connectrpc.com) (gRPC + HTTP/JSON) · pgx + sqlc · testcontainers · a pluggable OAuth2/OIDC identity engine (Keycloak by default, swappable behind the adapter).

## 🤝 Contributing

Early days — issues, ideas, and PRs are welcome. Tests run against real containers (`go test ./...` needs Docker). Please keep changes focused and covered.

## 📄 License

TBD. Intended to be permissive so any team can self-host and build on it.

---

<div align="center">
<sub>base-servers — build the app, not the auth layer.</sub>
</div>
