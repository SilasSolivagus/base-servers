# base-servers · Ring 0 · Phase 4 前门与交付 · 设计文档

- 日期:2026-07-21
- 状态:设计已定稿,待写实现计划
- 范围:Ring 0 第四(收官)阶段 —— **Front-door & Delivery**
- 前置:Phase 1 基础 / Phase 2 组织与权限 / Phase 3 agent 委托,均已合入 main
- 仓库:https://github.com/SilasSolivagus/base-servers

---

## 1. 背景与目标

前三阶段把领域内核做齐了:三态主体、组织/团队/RBAC+ownership、agent 委托硬门。但服务今天仍是一层**裸露的无头 Connect RPC** —— 没有任何认证中间件,任何能连到端口的调用方都能调用任意 RPC 并传入**任意 `org_id`**。也就是说,Phase 2 的"多租户隔离"目前只在"调用方老实传对 `org_id`"时成立。

同时,原始设计(`2026-07-20-...-foundation-design.md`)§7.1 把 **OIDC / OAuth2 Provider 定为对外主轴**,而这条前门至今不存在;§10 的部署闸门(docker-compose 一键起、冷启动健康检查)也尚未交付;委托签名密钥是 per-process 生成的,把部署钉死在**单副本**(已在 README 记为 alpha 约束)。

Phase 4 收官,把这四件事一次做齐,让 Ring 0 完整可交付:

> **A** OIDC 登录前门 · **B** admin API 认证门 · **C** 调用方→租户绑定 · **D** 一键部署 + 签名密钥持久化

### 北极星对齐
- **§5"base-servers 是调用方唯一接触面"** → A 用代理型前门坐实。
- **§10"多租户隔离:A 租户主体无法读写 B 租户资源"** → B+C 把它从"靠调用方自律"变成**服务端强制**。
- **D6/D7"OIDC 为主轴、不重造 OAuth 加密、引擎可换"** → A 让 `iss` 归 base-servers,同时绝不自签登录令牌。
- **§10 部署闸门 + §11"承担 key 轮换与分发"** → D 解除单副本约束。

---

## 2. 核心设计决策(含理由)

| # | 决策 | 选择 | 理由 |
|---|---|---|---|
| P4-D1 | OIDC 前门形态 | **代理型**:薄网关做单一公共域名前门,`KC_HOSTNAME`=公共域名,Keycloak 自签但发**公共 `iss`**;base-servers 绝不重签登录令牌 | 唯一同时满足 §5"唯一接触面" + D7"不重造 OAuth 加密"的路径。`iss` 是外部 RP 会永久 pin 死的公共契约;谁拥有 `iss`,谁就把"选了 Keycloak"从锁定变成实现细节,坐实"引擎可换" |
| P4-D2 | OIDC 公共路径 | 网关暴露**中性 `/oidc/*`**,rewrite 到 Keycloak 的 `/realms/{realm}/...` | 公共 hostname 只治 host;`/realms/...` 路径仍"一眼 Keycloak",换引擎时路径 shape 变、pin 死的 RP 照断。中性路径是"可换引擎"的真正试金石,成本仅一条网关规则 |
| P4-D3 | admin API 认证 | Connect **interceptor** 验 Keycloak 令牌(拉 Keycloak JWKS,校验 `iss`=公共域名),取 `sub`+类型入 ctx,匿名拒 | 关掉"裸露 RPC"这个最大的洞。登录 JWKS 与委托 JWKS **严格分离**(不同 `kid` 命名空间),RP 绝不拿委托 key 验登录令牌 |
| P4-D4 | 调用方→租户绑定 | org 作用域 RPC 强制"调用方 ∈ 该 org 成员"(写操作叠 Phase 2 role);`org_id` 从自由参数变为**受校验** | 复用 Phase 2 membership + `authz.Check`,让 §10 隔离真正成立 |
| P4-D5 | Bootstrap 授权 | v1 = **配置型 root 主体**(env secret 认证),唯一持有内部 **`system-admin capability`**;break-glass 语义 | 共享多租户实例 + 外部调用方 → 租户创建是炸半径操作,运营方应掌控(手动开租户在 alpha 是特性)。root 用**自己的 secret** 认证 → 特权授权层与可换引擎解耦。realm-role/self-service 未来沿同一 capability 缝纯策略叠加,RPC 零改动 |
| P4-D6 | 委托签名密钥持久化 | **DB 存 + env KEK 信封加密(AES-GCM)**;首启自备、多副本共享、可轮换 | 唯一同时满足"一键部署零仪式" + "命门私钥不裸放"。纯 DB 外泄(备份/快照/副本/注入)不带 env → 信封加密对准最高概率威胁,非安慰剂。**KEK 未设 fail-closed** |
| P4-D7 | 部署形态 | base-servers 进 compose(Dockerfile + `depends_on` healthcheck + 冷启动等 pg/keycloak);`/readyz` 探 DB+Keycloak | 交付 §10 一键起 + 健康检查闸门 |

---

## 3. 架构(Phase 4 增量)

```
        调用方 app / AI agents            运营方(bootstrap)
              │  OIDC 登录 / RPC                │ root secret
              ▼                                  ▼
   ┌────────────────────────────────────────────────────┐
   │  薄网关 (Caddy/nginx) · 单一公共域名前门              │  ← A 新增
   │   /oidc/*  → Keycloak (中性路径 rewrite)             │
   │   /*       → base-servers                            │
   └───────┬───────────────────────────┬─────────────────┘
           ▼                            ▼
   ┌──────────────┐          ┌─────────────────────────────┐
   │ Keycloak      │          │ base-servers                 │
   │ KC_HOSTNAME=  │          │  authn interceptor (B)       │  ← 验 Keycloak 令牌
   │  公共域名     │◀── JWKS ─│  tenant-binding (C)          │  ← org 成员校验
   │  发公共 iss   │          │  system-admin capability     │  ← bootstrap 缝
   │               │          │  delegation signer (D)       │  ← DB+KEK 私钥
   └──────┬────────┘          └──────────────┬──────────────┘
          ▼                                   ▼
   ┌──────────────┐                  ┌────────────────┐
   │ Postgres      │◀─────────────────│ signing_keys 表 │
   └──────────────┘                  └────────────────┘
```

---

## 4. 分块设计

### A · OIDC 登录前门
- **薄网关**(Caddy 优先,配置最短)进 `deploy/docker-compose.yml`,持有单一公共域名,是唯一对外入口。
- Keycloak 配 `KC_HOSTNAME`(及 frontend URL)= 公共域名 → discovery、token `iss`、JWKS URL 全读作公共 URL,**由 Keycloak 自己签名**,base-servers 不介入令牌链路。
- 网关把公共 **中性 `/oidc/*`** rewrite 到 Keycloak 的 realm 路径;`X-Forwarded-Proto/Host` 忠实透传。
- base-servers 通过管理能力在 realm 里**供给两类 client**:用户登录(authorization-code + PKCE)、服务/agent(client-credentials)。
- base-servers 的 Go 进程**不**实现 OAuth 重定向/回调代理逻辑(交给网关),避免把 footgun 烤进核心。

### B · admin API 认证门
- Connect **interceptor** 包住所有既有 RPC handler:
  - 取 `Authorization: Bearer`,验签 = Keycloak JWKS(带缓存,按公共 `iss` 拉);校验 `iss`/`exp`/`aud`。
  - 提取 `sub`(principal id)、principal 类型,写入 request context。
  - 无令牌/验签失败 → `CodeUnauthenticated`。
- **JWKS 分离**:登录令牌验 Keycloak keys、委托令牌验 base-servers keys,`kid` 命名空间不串;两套端点、文档分明。
- `/healthz`、`/readyz`、`/.well-known/jwks.json`(委托)、`/oidc/*`(网关)为**公开路由**,豁免 interceptor。

### C · 调用方→租户绑定
- 从 ctx 取调用方 principal;org 作用域 RPC 校验"调用方 ∈ 目标 `org_id` 成员",写操作再叠 Phase 2 `authz.Check(principal, action, resource)`。
- 越权/非成员 → `CodePermissionDenied`。
- `org_id` 仍在请求里,但服务端以"调用方成员资格"为准绳裁决,不再无条件信任。
- **系统/跨租户操作**(注册全局主体、建组织、指定首任 owner)不走 org 成员校验,走 `system-admin capability`(见 Bootstrap)。

### Bootstrap（system-admin capability 缝）
- 授权判定定义为内部 **capability**("可注册全局主体 / 建组织 / 指定首任 owner"),RPC 只查 capability、绝不查机制。
- v1 唯一持有者 = **配置型 root 主体**,由 deploy-time secret 认证(独立于引擎令牌 → 授权层引擎中立)。
- **break-glass 纪律**:仅 bootstrap 用、非日常;每次 bootstrap 调用记日志、运营人带外归因;secret 当真 secret 存(**不**提交进 compose env 明文);第一个外部租户落地前备好轮换路径。
- 未来 realm-role(B')/self-service(C')沿同一 capability 缝纯策略叠加。

### D · 一键部署 + 签名密钥持久化
- **compose**:新增 base-servers 服务(Dockerfile 多阶段构建);`depends_on` 带 `condition: service_healthy` 等 Postgres + Keycloak;迁移在启动时跑。
- **探活**:`/healthz`(存活,已存在)+ `/readyz`(就绪:DB ping + Keycloak discovery 可达)。
- **签名密钥**:
  - 新增 `signing_keys` 表(单例活跃键 + 历史键),私钥列存 **AES-GCM 信封密文**(KEK 来自 env `BS_SIGNING_KEK`)。**KEK 未设 → 启动 fail-closed。**
  - `kid` 从公钥 thumbprint 派生 → 所有副本一致。
  - **首启竞态**:单例活跃键行 unique 约束 + `INSERT … ON CONFLICT DO NOTHING`(或 pg advisory lock),败者回读赢者行。
  - **多键 Verify + 多键 JWKS**:JWKS 供"当前 + 上一把";Verify 逐 `kid`/逐键试。
  - **轮换**:生成新键 → 先发公钥进 JWKS →**再**切签名到新 `kid`。
  - **退休窗口** = `max 委托 TTL + max 验证方 JWKS 缓存 TTL + 时钟偏移`(绑定约束是验证方缓存,不是 TTL)。
  - 解除单副本约束;更新 README alpha 约束。

---

## 5. 数据/接口增量

- **新表** `signing_keys`:`kid` PK、`alg`、`public_jwk`(明文,供 JWKS)、`private_key_enc`(AES-GCM 密文)、`state`(active/retiring/retired)、`created_at`、`retire_after`。
- **新配置**:`BS_SIGNING_KEK`(必填,fail-closed)、`BS_ROOT_PRINCIPAL_*`(root bootstrap 认证)、`BS_PUBLIC_ISSUER`(公共域名 issuer)、Keycloak JWKS/discovery URL。
- **无破坏性 RPC 变更**:既有 handler 签名不变,认证/租户绑定以 interceptor + 每 handler 的成员校验落地;bootstrap 相关操作复用既有 principal/org RPC,授权路径区分 capability。
- **公开路由**豁免 interceptor:`/healthz`、`/readyz`、委托 JWKS、`/oidc/*`。

---

## 6. 明确不做 / 推后

- B'/C':realm-role 门控、self-service signup(缝已留,v1 不实现)。
- KMS / Vault 托管 KEK 或私钥(env KEK 已够 alpha)。
- CAEP/SSF 实时撤销、多跳委托(沿用 Ring 0 既定下放)。
- 厚 Admin 控制台 UI、企业 SAML/SCIM 深度。
- 网关做聚合/鉴权(保持薄片;认证在 base-servers 内)。

---

## 7. 测试与验收

- **A**:`GET /oidc/.well-known/openid-configuration` 经网关返回,`issuer` = 公共域名中性路径;Keycloak 签发令牌 `iss` 与之一致;两类 client 可完成各自 flow。
- **B**:无令牌/伪造令牌 RPC → `Unauthenticated`;合法 Keycloak 令牌 → ctx 带正确 `sub`/类型;委托 key 验登录令牌被拒。
- **C**:A 租户成员令牌读写 B 租户 `org_id` → `PermissionDenied`;成员正常路径通过;写操作 role 不足被拒。
- **Bootstrap**:root 主体可建组织+指定 owner;非 root 调 bootstrap RPC → 拒;每次 bootstrap 有审计日志。
- **D**:`docker compose up` 冷启动到 `/readyz` 通过;**两副本**并发,委托令牌在任一副本签、另一副本 `CheckDelegated` 通过(共享密钥);轮换后旧 TTL 内令牌仍验、退休窗口后旧 `kid` 移除;`BS_SIGNING_KEK` 未设 → 启动失败。
- 全程对**真 Keycloak + Postgres 容器**跑;提交署名 Silas、无 Co-Authored-By/Claude trailer;精确 `git add` 路径。

---

## 8. 风险与开放问题

- **网关 footgun**:`KC_HOSTNAME` / 实际代理 host / TLS 终止三者不一致 → 登录页错乱、重定向环、open-redirect。缓解:TLS 一致终止、`X-Forwarded-*` 忠实透传、集成测试覆盖 discovery+一次完整 flow。
- **root secret 是常驻跨租户上帝凭证**:泄漏=全租户沦陷、单主体无天然按人归因。缓解:break-glass 语义 + 审计 + 带外归因 + 轮换路径。
- **KEK 分发**:与密文不同通道(env vs DB)才有意义;复用 compose 既有 env secret 注入通道,不从 DB secret 派生 KEK。整机沦陷不设防(此时进程内存可读明文,任何 at-rest 方案无解)。
- **多副本轮换时序**:JWKS 必须先于签名发布;退休窗口按验证方缓存而非 TTL。
- **引擎可换性未验**:A 的中性路径 + issuer 归属是可换性的关键;真正冒烟(切 Zitadel)仍属后续。
