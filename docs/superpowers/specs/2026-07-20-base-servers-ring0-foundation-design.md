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

> base-servers 是一层 **agent 原生**的身份与权限底座:在成熟的人/服务身份之上,
> 把 **AI agent 当一等主体** —— 它的身份、属性、受托权限、可归因与可撤销 —— 按 2026 的 agent 标准打包好,
> 让任何系统用 OAuth2/OIDC 几行代码直接调用。自托管、多租户、模块化;发动机复用成熟开源,
> 我们只造别人没造好的:**agent 原生的委托层 + 统一 API + 模块化打包**。

### 北极星
- **头号定位:agent 原生的身份 / 权限底座。** agent 的身份、属性、权限、受托代理关系从第一天进内核。
  这是 base-servers 的差异化空位与抢位赌注 —— 2026 年没人把"agent 当一等主体"打包好。
  **对外话术与验收权重都以 agent 为主角;人 / 服务是成熟基座,不是头条。**
- **承载环境:B2B SaaS 多租户**(全局身份 + 组织 + 团队)是它运行的基底,而非卖点主角。

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
| D5 | agent 委托 | **v1 由 base-servers 自签委托 JWT**(go-jose,含 `act`/`delegation_id`/`cnf.jkt`/`scope`/短TTL + 自有 JWKS 轮换);引擎原生 token-exchange 留作适配器能力(Zitadel 可切)| Keycloak 不原生出 `act`/动态 `delegation_id`,自签避开其最大集成雷、仍合 RFC 8693 形状;有效权限 = **delegator ∩ scope**(用授权人**当前**权限,忽略 agent 自身角色以防混淆代理;"agent 自身上限"改每条委托可选、默认关);限时/限任务/可撤销 |
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
- **agent 委托:base-servers 自签委托 JWT(v1)** —— 含 `act={delegator}` / `delegation_id` / `cnf.jkt` / `scope` / 短TTL,base-servers 自有 JWKS 轮换;合 RFC 8693 形状,引擎原生 token-exchange 作适配器能力保留。
- 令牌:短命 JWT access + refresh,JWKS 轮换(用户/服务令牌由引擎签;委托令牌由 base-servers 签)。
- 安全增强:**DPoP** 绑令牌防盗 —— **权威校验归资源服务器**;base-servers 提供可复用验证器,PDP 侧仅在 RS 转发 `{proof, htm, htu}` 时做完整校验(签名 + `cnf.jkt` + `ath` + `htu/htm`)。
- 撤销机制:v1 用**短 TTL + introspection / 黑名单**,按"撤销后有界秒级失效"的**行为**验收;
  **不押 CAEP**。完整 CAEP/SSF 实时推送撤销为 v1.1,适配器留同一接口可无重构升级。

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
  —— **v1 委托令牌一律 base-servers 自签**(不依赖引擎的 token-exchange,避开 Keycloak 不出 `act`/动态 `delegation_id` 的雷);此标志预留,将来对 Zitadel 等原生支持的引擎可切换为引擎签发。
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

> **不可退让的验收闸门:agent 委托流(精确版)。** 它是 base-servers 的头号定位所在。
> v1 若 scope 吃紧,先砍其他项 —— 下面这四条不全通过,v1 不算完成。
> 设计原则:把**委托语义**(我们的代码、完全可控)与**传输加固**(标准不成熟的引擎特性)解耦,
> 关键路径上只放前者与已 GA 的部分,标准不成熟的依赖下放 v1.1。

- **身份**:三态主体注册/登录;全局用户加入多组织并切换;JWKS 轮换后旧令牌校验。
- **组织**:创建组织 + 团队;成员挂载;组织/团队级角色分配。
- **权限**:`check()` 对 RBAC 角色与资源归属两条路径均正确;越权被拒。
- **agent 委托(不可退让的四条门,按 3a→3b→3c 顺序落地)**:
  1. **签发窄令牌(3a)** —— base-servers 自签委托 JWT,带 `act={delegator}` / `delegation_id` / `cnf.jkt` / `scope` / 短TTL;写 `delegations` 记录;`Revoke` 可用。
  2. **有效权限 = delegator ∩ scope(3b,核心不变量)** —— `allow = action∈scope ∧ Check(delegator, 当前)`,**忽略 agent 自身角色**(防混淆代理);须有**对抗性测试**:授权人没有的权限拒、范围外拒、用授权人**当前**权限(撤授权人角色即时收窄)。**Issue 时禁止"授权人是 agent"**(v1)。"agent 自身上限"为每条委托可选、默认关。
  3. **撤销真的生效** —— 短 TTL + `delegations.revoked` 黑名单,`CheckDelegated` 每次查库;发→通→撤→**有界秒级拒**(不押 CAEP)。
  4. **DPoP 防重放(3c)** —— 令牌 `cnf.jkt` 绑定;**权威校验在资源服务器**,base-servers 提供验证器,`CheckDelegated` 仅在 RS 转发 `{proof, htm, htu}` 时做完整校验(签名 + `cnf.jkt` + `ath` + `htu/htm`)。"盗令牌换 key 被拒"演示如实标为 RS 的活、base-servers 协助。
  - **下放 v1.1**:多跳委托(边表已容纳,加可空 `parent_delegation_id` 为非破坏迁移)、完整 CAEP/SSF 实时推送撤销、引擎原生 token-exchange。
- **多租户隔离**:A 租户主体无法读写 B 租户资源。
- **部署**:docker-compose 一键起,冷启动到可服务的健康检查通过。

---

## 11. 风险与开放问题

- **Keycloak 运维重量**:JVM,交付外部自托管者足迹最大。缓解:躲在适配器后、提供调优过的 compose。
- **CAEP/SSF 实验状态(已从关键路径移除)**:Keycloak 26.7 的 SSF 仍为实验开关。
  v1 撤销改用短 TTL + 黑名单,不依赖它;CAEP 作为 v1.1 的可插拔升级,风险已隔离。
- **委托签发已改自签(风险已隔离)**:Keycloak 不原生出 `act`/动态 `delegation_id`,且 token-exchange+DPoP 同出 `cnf.jkt` 未经证实——v1 改为 base-servers 用 go-jose 自签委托 JWT(自有 JWKS),彻底避开该雷;引擎原生签发留作 Zitadel 能力。
- **DPoP 架构归位**:DPoP 绑"客户端→资源服务器"的请求,PDP 带外收 token+proof 无法验 `htm/htu`。故权威校验归 RS,base-servers 只提供验证器 + 在 RS 转发请求上下文时协助。
- **base-servers 成为令牌签发方**:自签意味着 RS 要信任 base-servers 的 JWKS——需确定单一 issuer、承担 key 轮换与分发。
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
