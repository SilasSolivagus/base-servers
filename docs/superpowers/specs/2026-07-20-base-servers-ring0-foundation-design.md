# base-servers · Ring 0 内核地基 · 设计文档

- 日期:2026-07-20
- 状态:设计已定稿,待写实现计划
- 范围:base-servers 的第一个子项目 —— Ring 0 内核(Identity + Tenancy + AuthZ)
- 仓库:https://github.com/SilasSolivagus/base-servers

---

## 1. 背景与目标

构建各种业务系统时,总有一层基础设施级的必要服务需要反复搭建:账号、组织架构、权限。
`base-servers` 的目标是把这一层**做一次、做对**,让任何系统不必再自建,直接调用即可。

一句话定位:

> 一个**自托管、多租户、模块化**的服务,把「人 / 服务 / AI agent」三态主体的**身份、组织、权限**,
> 按 2026 年的 agent 身份标准打包成任何系统用 OAuth2/OIDC 几行代码就能直接调用的一层。
> 发动机复用成熟开源,我们只造别人没造好的:**agent 原生的委托层 + 统一 API + 模块化打包**。

### 北极星
- **B2B SaaS 优先**(多租户、有组织和团队)。
- **AI agent 是一等主体**:agent 的身份、属性、权限、以及受托代理关系,从第一天就进内核。
  这是 base-servers 的差异化空位 —— 2026 年没人把"agent 当一等主体"这层打包好。

### 调用方
内部(自己未来的一堆项目)与外部团队**都要**支持。因此:license 需可外发、部署需可交付。

---

## 2. 形态与交付(已定)

- **形态**:自托管服务,不是 SaaS、也不是嵌入式 SDK。
- **协议对外**:以 **OAuth2 / OIDC Provider** 为主轴(方案 A),外加**少量无头(headless)服务端 API** 作补充。
- **部署模型**:**一份共享的多租户实例**,喂一个组织下的所有系统与租户。
  无状态设计,成本被所有调用方摊薄。**不是** instance-per-tenant。
- **打包**:docker-compose 一键起;架构从第一天就多租户 + 无状态,为将来开托管版留口子。

---

## 3. 模块化原则(已定)

不是所有业务都需要每一环,甚至同一环内部也要能降级。因此:

> base-servers = **一个强制的极小内核 + 一圈各自独立、可选启用、可分档的模块**。

- 唯一近乎"人人都要"的是 Identity;组织、计费、文件等**看业务形态才启用**。
- 每个模块自己也要能"从简单档位起步、按需升配"(如权限:归属级 → RBAC → ReBAC)。

### 洋葱路线图(依赖顺序,非必装清单)

```
Ring 0  内核地基     Identity · Tenancy 组织 · AuthZ 权限   ← 本 spec
Ring 1  信任与安全   API Key/M2M · 审计 · 会话/设备 · 限流
Ring 2  触达         通知 · 模板/i18n · Webhook/事件 · (agent 通信网 = 未来)
Ring 3  商业化       计费/订阅 · Entitlement/FeatureFlag · Config
Ring 4  数据与内容   文件存储 · 用户资料/偏好
横切     多租户隔离 · Admin 控制台 · SDK / API 网关
```

Ring 1~4 各自后续单独一轮 spec → plan → 实现。本文档只覆盖 Ring 0。

---

## 4. Ring 0 核心设计决策(含理由)

| # | 决策 | 选择 | 理由 |
|---|---|---|---|
| D1 | 身份归属 | **全局身份 + 多组织成员**(Slack/GitHub 模型) | 现代 B2B SaaS 事实标准;agent 可受托跨多租户;可向下兼容"单组织"模型 |
| D2 | 主体类型 | `Principal = Human \| Service \| Agent` | agent 是夹在人和机器之间的第三类主体,需一等建模 |
| D3 | 组织层级 | v1 = `组织(Org) + 一层团队(Team)`;深层部门树用 `parent_id` 预留不做 | YAGNI,留迭代空间 |
| D4 | 权限模型 | v1 = **RBAC(组织/团队级角色)+ 资源归属(ownership)**;数据模型按 ReBAC 形状铺 | 务实变体:先能用,ReBAC 引擎后续无痛接入 |
| D5 | agent 委托 | **OAuth2 Token Exchange(RFC 8693)/ On-Behalf-Of**,约束用 caveat/条件表达 | 踩 2026 行业共识与 IETF 草案;有效权限 = min(自身授予, 授权人权限),可限时/限任务/可撤销 |
| D6 | 对外接入 | **A:OIDC Provider 为主 + 无头 API 补充** | OIDC 是任何语言可调的普通话,一套协议接住人/服务/agent,并白送组织内多系统 SSO |
| D7 | 造 vs 组合 | **组合:站在成熟身份引擎之上 + 适配器层** | 自研 OAuth2/OIDC 是安全雷区且重复造轮;适配器避免被单一开源绑架 |
| D8 | 默认引擎 | **Keycloak**(Apache-2.0);适配器保留 Zitadel/Logto 可换 | 唯一今天就同时 ship token-exchange + DPoP + CAEP,且原生多组织,license 干净 |

### D8 详解:为什么默认 Keycloak
由独立专家评审横评 Logto / Ory / Zitadel / Keycloak / SuperTokens / Casdoor / Authentik 后得出。
Keycloak 同时压中三个最高权重项:
- **license**:Apache-2.0,可嵌入并交付外部团队,零 copyleft 摩擦(Zitadel 自 2025 v3 起为 AGPL-3.0)。
- **agent 委托原语现成**:RFC 8693 token exchange + **DPoP**(26.4 GA)+ **CAEP/SSF** 撤销(26.7,实验开关)——
  这正是最难、最安全敏感、本来要自己造的部分。
- **全局身份 + 多组织**:原生 Organizations + 团队级 Groups。

代价:JVM 服务,自托管足迹最重(小规模每月约多 $10–15,一台机器档位差)。
但它躲在适配器后,调用方只调 base-servers 的 OIDC/API,这份"重"只压在运维侧、不外泄到调用体验;
规模一大,成本由 Postgres 和流量主导,引擎内存是噪声。

备选:**Zitadel**(能接受 AGPL、要轻、要最 API 原生时;但无 DPoP/CAEP);
**Logto**(要极致 DX/轻量、且愿意自造整个委托层时)。

---

## 5. 架构

```
                    调用方系统(任意语言) / AI agents
                                │  OIDC / OAuth2 · gRPC/REST
                                ▼
        ┌───────────────────────────────────────────────┐
        │                 base-servers API                │
        │  统一领域模型 · 委托层 · 权限 check · 管理 API   │  ← 我们造的净增值
        │                                                 │
        │   ┌─────────────┐        ┌──────────────────┐   │
        │   │ Identity     │        │ AuthZ Port        │   │
        │   │ Adapter      │        │ (RBAC+ownership   │   │
        │   │ (Keycloak)   │        │  v1;ReBAC 后续)   │   │
        │   └─────┬────────┘        └──────────────────┘   │
        └─────────┼───────────────────────────────────────┘
                  ▼
        ┌──────────────────┐   ┌────────────┐
        │ Keycloak(引擎)   │   │ Postgres    │
        │ OIDC/OAuth2/orgs  │   │             │
        │ token-exchange    │   └────────────┘
        │ DPoP · CAEP       │
        └──────────────────┘
```

- **base-servers API 层**(我们写):定义自己的领域模型与 API,是调用方唯一接触面。
- **Identity Adapter**:把领域模型映射到具体引擎(默认 Keycloak)。引擎可换。
- **AuthZ Port**:授权判定独立成端口,v1 内建 RBAC+ownership,后续可接 OpenFGA/SpiceDB,不动上层 API。
- **Keycloak**:身份发动机,提供 OIDC/OAuth2、组织、token-exchange、DPoP、CAEP。
- **Postgres**:引擎与 base-servers 的持久化。

---

## 6. 领域模型(草案)

> 按 ReBAC 的形状铺:关系用可演进的边表达,便于后续接入关系图引擎。

- **Principal**:`id`、`type`(human/service/agent)、`status`。全局唯一。
  - Agent 扩展:`owner_principal_id`、`capabilities`、`purpose`、`on_behalf_of`。
- **Organization**:`id`、`name`、`parent_id`(预留层级,v1 不用)。
- **Team**:`id`、`org_id`。v1 单层。
- **Membership**:`principal_id` × `org_id`(全局用户 join 组织)。
- **Role / RoleAssignment**:角色可挂 `org` 或 `team` 作用域;分配 = principal × role × scope。
- **Ownership**:`resource_ref` × `owner_principal_id`(资源归属,v1 授权基石)。
- **Delegation(委托)**:`agent_principal_id`、`delegator_principal_id`、`scope/task`、`expires_at`、`revoked`。
  有效权限 = `min(agent 自身授予, delegator 权限)`,受 caveat 约束。

---

## 7. 对外接口

### 7.1 OIDC / OAuth2(主轴)
- 用户登录:authorization-code + PKCE。
- 服务/agent:client-credentials。
- **agent 委托:token-exchange(RFC 8693)/ OBO** —— 用宽令牌换取限时、限任务的窄令牌。
- 令牌:短命 JWT access + refresh,JWKS 轮换。
- 安全增强:**DPoP** 绑令牌防盗;**CAEP/撤销** 做实时 kill-switch。

### 7.2 无头服务端 API(补充)
- `check(subject, action, resource)` —— 权限判定,后端直连。
- 组织 / 成员 / 团队 / 角色管理。
- **agent 注册与委托签发 / 撤销**。

### 7.3 认证方式(引擎白得)
邮箱密码、magic link、社交登录、TOTP MFA、Passkey 开箱;企业 SAML/SCIM 列为"可用",非 v1 重点。

---

## 8. 适配器接口(关键抽象)

引擎能力差异大,适配器必须以**能力标志**建模,不能假设:

- `supportsTokenExchange` / `supportsDPoP` / `supportsCAEP`
  —— Keycloak 全支持;若换 Logto 等不支持的引擎,委托需我们在 API 层自造(`act`/`may_act` claim 或 token-exchange shim)。
- 组织成员形态:统一"全局用户 + 成员层"(Keycloak/Logto)与"用户绑单组织 + 跨组织授权"(Zitadel)两种模型。
  暴露 `attachUserToOrg` / `grantCrossOrgRole`,各引擎实现不同。
- 主体元数据:agent 属性映射到 Keycloak user/client attributes + protocol mappers(Zitadel metadata / Logto custom data)。
  抽象为 `principal.metadata` map + `enrichClaims(principal, ctx)` 钩子。
- M2M 供给:统一 `createServicePrincipal`(各引擎机制不同)。
- **ReBAC 放在 identity adapter 之外**,单独授权端口,避免与引擎耦合。

---

## 9. 明确不做 / 推后

- Ring 1~4 全部。审计 v1 只做"引擎发事件、我们透出",不建独立审计子系统。
- ReBAC 引擎(OpenFGA/SpiceDB)—— 数据模型预留,v1 不接。
- agent 之间的消息通信网(Ring 2 的未来项)。
- Admin 控制台做厚;深层组织部门树。
- 企业 SAML/SCIM 深度打磨(引擎现成,列可用即可)。

---

## 10. 测试与验收标准

- **身份**:三态主体注册/登录;全局用户加入多组织并切换;JWKS 轮换后旧令牌校验。
- **组织**:创建组织 + 团队;成员挂载;组织/团队级角色分配。
- **权限**:`check()` 对 RBAC 角色与资源归属两条路径均正确;越权被拒。
- **agent 委托(核心验收)**:
  - 用 token-exchange 为 agent 签发"限时 + 限任务"窄令牌;
  - 有效权限不超过授权人;
  - 到期 / 撤销(CAEP)后令牌立即失效;
  - DPoP 绑定令牌,盗用(换客户端)被拒。
- **多租户隔离**:A 租户主体无法读写 B 租户资源。
- **部署**:docker-compose 一键起,冷启动到可服务的健康检查通过。

---

## 11. 风险与开放问题

- **Keycloak 运维重量**:JVM,交付外部自托管者足迹最大。缓解:躲在适配器后、提供调优过的 compose。
- **CAEP/SSF 实验状态**:Keycloak 26.7 的 SSF 目前为实验开关,需验证是否满足我们的 agent 撤销流。
- **token-exchange + DPoP 组合边界**:需核实"客户端换取自身令牌"这条窄路径覆盖我们的 agent 流,再最终敲定。
- **引擎可换性**:适配器抽象需在实现早期用第二引擎(Zitadel 或 Logto)做一次冒烟,验证抽象没漏。

---

## 附:决策依据来源

- Zitadel AGPL relicense:https://zitadel.com/blog/apache-to-agpl
- Keycloak DPoP(26.4):https://www.keycloak.org/2025/10/dpop-support-26-4
- Keycloak Token Exchange:https://www.keycloak.org/securing-apps/token-exchange
- Keycloak CAEP/SSF(26.7):https://www.keycloak.org/2026/07/keycloak-2670-released
- Keycloak Organizations:https://www.keycloak.org/2024/06/announcement-keycloak-organizations
- IETF 草案 OAuth 2.0 On-Behalf-Of for AI Agents:https://www.ietf.org/archive/id/draft-oauth-ai-agents-on-behalf-of-user-00.html
- CNCF 服务间鉴权(SPIFFE + OAuth2 + OPA)、agentic identity 六原语:https://www.strata.io/blog/agentic-identity/why-agentic-ai-demands-more-from-oauth-6a/
