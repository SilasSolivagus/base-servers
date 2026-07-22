# base-servers · Ring 1 · API Key / M2M 凭证 · 设计文档

- 日期:2026-07-22
- 状态:设计待评审(专家 + 爸爸)
- 范围:Ring 1(信任与安全)第二个子项目 —— **API Key / 机器对机器(M2M)凭证**
- 前置:Ring 0 全四阶段 + Ring 1·审计 已在 main(`b9027db`)
- 仓库:https://github.com/SilasSolivagus/base-servers

---

## 1. 背景与目标

Ring 0 造好了治理引擎(作用域委托、authz 强制、认证门),Ring 1·审计给了防篡改决策日志。但在真实自托管部署里,**机器/服务/CI/第三方几乎没有干净的、principal-native、可吊销的方式来"够到"控制面**:今天只有人能 OIDC 登录,机器调用只能借 Keycloak client-credentials —— 笨重、把 Keycloak 依赖漏穿抽象、不是一等 principal、不在 base-servers 自己的审计下按 key 吊销。

> 定位:给**已存在的 principal**(human/service/agent)签发一把**长期、可吊销、发一次即只存哈希**的静态凭证,让非交互调用方用它认证控制面。每把 key 的签发/吊销/失败进审计,吊销即断访问且可归因。API key 是**人管的服务/CI/第三方的引导与边缘凭证**——**不是 agent 的默认**。

### 北极星对齐与红线
- **补齐 principal 模型的认证对称性**:human→OIDC、service→key、agent→key 引导后走短 TTL OBO 委托。三类 principal 都有原生认证路径。
- **喂已建好的机器**:每次 key 认证的调用直接汇入现有 authz + 审计路径 —— 即时可归因、可吊销、有日志。
- **战略红线(专家)**:agent 的正确答案是短 TTL 工作负载身份(委托 token 已是),**不是长期静态密钥**。本模块刻意把 API key 定位成机器/CI/第三方边缘凭证;**agent 运行时仍走委托**。设计上不让长期静态 key 成为 agent 的默认,否则反噬"消灭静态密钥蔓延"的卖点。

---

## 2. 核心设计决策(含理由)

| # | 决策 | 选择 | 理由 |
|---|---|---|---|
| K1 | 凭证形态 | **静态不透明密钥**,发一次即只存哈希;独立 `api_keys` 表;绑定既有 principal id + org。**非 JWT**(委托的 ES256/JWKS 机器全不复用) | 静态密钥认证 = 存储查找 + 常量时间哈希比对,与 root-token/Verifier 同构,非签名验证。principal 一律 Keycloak 签发,本模块不铸身份,只为已建 principal 发凭证 |
| K2 | 哈希 | **HMAC-SHA256 + 服务端 pepper**(env `BS_APIKEY_PEPPER`,未设即 fail-closed,与 KEK 同风格),`subtle.ConstantTimeCompare` 比对哈希字节 | **拒绝 argon2/bcrypt 前提**:那是给低熵人类密码的;API key 是 160+ 位高熵随机串,每请求都验,记忆硬 KDF 会毁控制面延迟 + 送人一个喷坏 key 烧 CPU 的 DoS。高熵无需慢哈希(GitHub/Stripe 模式) |
| K3 | 格式 | `bsk_<keyid>_<secret><crc>`:`bsk_` 前缀 + 非密 **keyid**(索引,O(1) 查) + ≥160 位 base62 **secret**(crypto/rand) + 短 **CRC** 校验位 | keyid 非密、可索引单查;CRC 免 DB 命中即拒坏 key,且让 gitleaks/GitHub secret-scanning 能识别;存 `HMAC(secret)` 按 keyid 索引。secret 只在签发响应里出现一次 |
| K4 | 认证接入 | authn 拦截器加**第三分支**:`Authorization: Bearer bsk_…` 前缀分流到 apikey 校验器(而非 Keycloak Verifier)→ `Caller{PrincipalID: key.PrincipalID}`。加 `Caller.AuthMethod`(oidc/apikey/root)供审计 `via` | 单一 `Authorization` 头、前缀分派,客户端最省心;下游只读 `PrincipalID`/`SystemAdmin`,key 路径填这两个即全兼容 |
| K5 | 权限/衰减 | **v1:key 以所绑 principal 的完整权限认证,无每-key 细粒度作用域收窄;不存 scope 列**。attenuation 推 v1.1 | 专家已**撤回**"衰减 v1 就上、几乎免费"(代码实况:委托 scope 交集埋在 JWT 验签后、非可复用函数,且控制面 RPC 根本不走 scope 词汇——真衰减要新控制面动作词汇 + 跨全 handler 强制点,是授权路径的跨切改动,风险高)。且这是**层级错配**:细粒度最小权限属 agent/数据面(短 TTL 委托已做),API key 是粗粒度长期机器身份,由 K6/K8/过期/吊销把关已杀掉提权/admin/混淆代理。存不强制的 scope 列 = 安全剧场,更糟。见 §8 |
| K5b | 唯一诚实衰减切片 | **可选 `ReadOnly` key**:一个 bool,**在 authn 拦截器单一收敛点**强制——只读 key 仅放行方法名前缀 ∈ {`Get`,`List`,`Check`,`Verify`} 的 procedure,其余(含未来新增的所有 mutation)**默认拒**(fail-safe 白名单,非黑名单) | 唯一有**真收敛点**的粗粒度能力(拦截器已是每 RPC 必经)。服务只读用例真实:验权资源服务器 / CI 监控只调 `CheckDelegated`/`authz.Check`/`List` 验证、绝不改动;泄漏一把只读 key 爆炸半径极小。一处一表,非 K5 的跨 handler 线 |
| K6 | system-admin | **API key 永不携带 SystemAdmin**(key 认证的 Caller 恒 `SystemAdmin=false`);bootstrap 仍只走 root-token | 现状 SystemAdmin 只经 root-token 产生;key→principal 恒非 admin,是干净且安全的默认——key 泄漏不会给到跨租户特权 |
| K7 | 生命周期 | 每 principal **多把活跃 key**(轮换=重叠);**可选过期**(`expires_at` 可空,NULL=不过期);单-key 吊销(`revoked` bool);principal 删除级联吊销;`last_used_at` 尽力更新(节流/异步,不阻塞) | 多活跃 key 让轮换 = 建新→部署→吊旧(`last_used_at` 确认旧 key 静默),这就是 v1 的全部轮换;无定时轮换、无宽限窗自动化 |
| K8 | 签发授权 | **caller 只能给自己签 key**(`caller.PrincipalID == req.PrincipalId`),system-admin(root-token)可为任意 principal 签 | 镜像委托 Issue 的 caller==delegator 反混淆代理:principal 自己铸自己的 key;service/agent 首把 key 由 root-token break-glass 引导。永不允许 A 给 B 铸 key(除 break-glass) |
| K9 | 审计 | 签发/吊销进审计(`apikey.issue`/`apikey.revoke`);**不**对每次成功认证发事件(每请求会淹);无效/过期/已吊销 key 的**认证失败**发 `apikey.auth`(outcome=denied,量有界、信号有用) | key 触发的真正 authz 决策已被下游审计;成功认证本身量太大不记,失败记以便查滥用/泄漏 |

---

## 3. 架构

```
        调用方(service / CI / 第三方 / agent 引导)
            │ Authorization: Bearer bsk_<keyid>_<secret><crc>
            ▼
        ┌──────────────────────────────────────────────┐
        │ authn 拦截器(既有,加第三分支)                 │
        │   root-token → bearer(bsk_?→apikey : keycloak) │
        │   apikey.Verifier: 解析→CRC→按 keyid 查→        │
        │     HMAC(secret) 常量时间比对→未吊销/未过期      │
        │     → Caller{PrincipalID, AuthMethod:"apikey"}  │
        └───────────────┬──────────────────────────────┘
                        │ 认证后与 OIDC 路径完全一致
                        ▼
        既有 handler(org.IsMember / authz.Check / 委托…)+ 审计
        ┌──────────────────────────────────────────────┐
        │ internal/apikey                                │
        │   Service.Issue/Revoke/List(签发只存哈希)      │
        │   Store(api_keys 表,按 keyid 查,last_used)    │
        │   Verifier(拦截器调,解析+比对+活性)            │
        │   ApiKeyService handler(Issue/Revoke/List)     │
        └───────────────┬──────────────────────────────┘
                        ▼   emit apikey.issue/revoke/auth(denied)
                 ┌──────────────┐
                 │ audit(Ring 1) │
                 └──────────────┘
```

---

## 4. 模块设计

### 4.1 数据:`api_keys` 表(迁移 `0007_api_keys.sql`)
```
key_id        TEXT PRIMARY KEY,           -- 非密、公开、格式内可见,索引单查
principal_id  TEXT NOT NULL,              -- 绑定的既有 principal(Keycloak 签发 id)
org_id        TEXT NOT NULL,              -- 归属 org("" 保留给未来无-org 服务凭证;v1 必填)
name          TEXT NOT NULL DEFAULT '',   -- 人给的标签,便于识别/轮换
hash          BYTEA NOT NULL,             -- HMAC-SHA256(pepper, secret)
created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
expires_at    TIMESTAMPTZ,               -- 可空;NULL=不过期
last_used_at  TIMESTAMPTZ,               -- 尽力更新
read_only     BOOLEAN NOT NULL DEFAULT false,  -- K5b:只读 key(拦截器强制)
revoked       BOOLEAN NOT NULL DEFAULT false
```
索引:`(principal_id)`(列 key 用)、`(org_id)`。**不可变性不必如审计**(key 可吊销/更新 last_used),故无 append-only 触发器。

### 4.2 密钥生成 / 校验(`internal/apikey`,新写,无现成可复用)
- **生成**:`key_id` = 短 base62(crypto/rand,唯一,如 16 char);`secret` = 32+ char base62(crypto/rand,≥160 位);`crc` = base62(CRC32(`bsk_`+keyid+`_`+secret))。明文 = `bsk_<keyid>_<secret><crc>`,**仅签发响应返回一次**。存 `HMAC-SHA256(pepper, secret)`。
- **校验(Verifier,拦截器调)**:① 前缀 `bsk_` + 结构 + CRC 自校验(坏 key 免 DB 直拒)② 按 `key_id` 查一行 ③ `subtle.ConstantTimeCompare(HMAC(pepper, secret), row.hash)` ④ `!revoked && (expires_at IS NULL || now < expires_at)`。任一不过 → 认证失败(fail closed)。成功 → `Caller{PrincipalID: row.principal_id, AuthMethod:"apikey"}`,并**尽力**节流更新 `last_used_at`(不阻塞请求)。
- **pepper**:`BS_APIKEY_PEPPER`(base64 of 32 随机字节),未设即拒启动(fail-closed,与 `BS_SIGNING_KEK` 同风格)。pepper 让"仅拿到 DB"的攻击者无法离线暴力/比对哈希。

### 4.3 认证接入(改 `internal/authn`)
- `Caller` 加 `AuthMethod string`(`"oidc"`/`"apikey"`/`"root"`;审计 `Actor`/decision 的 `via` 可用)+ `ReadOnly bool`。既有两路填 `"oidc"`/`"root"`、`ReadOnly=false`。
- 拦截器 `Interceptor(v *Verifier, rootToken string)` → 加一个 apikey 校验依赖(引 `apikey.Verifier` 接口,避免 authn→apikey→? 环:apikey.Verifier 只依赖自己的 store,不回依赖 authn)。`WrapUnary`/`WrapStreamingHandler` 的 bearer 分支:`strings.HasPrefix(token, "bsk_")` → apikey 路径,否则 → Keycloak `v.Verify`。**key 认证的 Caller 恒 `SystemAdmin=false`**(K6)。
- **K5b 只读强制(单一收敛点)**:构造出 `Caller` 后,若 `Caller.ReadOnly`,取 `req.Spec().Procedure`(形如 `/baseservers.v1.OrgService/AddMember`)的方法名,**仅当方法名以 {`Get`,`List`,`Check`,`Verify`} 之一为前缀才放行**,否则 `PermissionDenied`。白名单按前缀 = fail-safe:任何未来新增的 mutation(不以读前缀开头)对只读 key 默认拒。此判定只依赖 `Caller.ReadOnly` + procedure 名,与凭证来源无关(理论上也可给未来的只读 OIDC 场景复用),放在拦截器 authn 之后、`next` 之前。
- 与 OIDC 路径认证后完全同构:下游 handler 的 `RequireMember`/`authz.Check`/委托 `caller==delegator` 全不改。

### 4.4 API(`proto/baseservers/v1/apikey.proto` → buf → handler,认证门后)
- `ApiKeyService.Issue(IssueApiKeyRequest{principal_id, org_id, name, ttl_seconds(0=不过期), read_only}) → {key_id, secret_once, expires_at}` —— 授权 K8:`caller.PrincipalID==principal_id` 或 system-admin;org 成员校验复用 `RequireMember`。`secret_once` 仅此一次返回。`read_only` 落 `api_keys.read_only`。
- `ApiKeyService.Revoke(RevokeApiKeyRequest{key_id}) → {}` —— 授权:key 属主 principal 自己 或 system-admin;回读 key 的 principal/org 做 K8 校验(不新增查询之外)。
- `ApiKeyService.List(ListApiKeysRequest{principal_id}) → {keys[]}` —— 只出**非密元数据**(key_id、name、created/expires/last_used、revoked),**永不出 secret/hash**;授权同 Revoke。
- 三者都在 Ring 0 认证门后;handler 侧做 authz + 审计埋点。

### 4.5 装配(改 `cmd/base-servers/main.go`)
- 构造 `apikeyStore := apikey.NewStore(pool)`、`apikeyVerifier := apikey.NewVerifier(apikeyStore, pepper)`;传入 `authn.Interceptor(verifier, apikeyVerifier, cfg.RootToken)`;`server.New(...)` handler 列表加 `apikey.NewHandler(apikeyStore, orgStore, auditRec)`。config 加 `BS_APIKEY_PEPPER`(fail-closed)。

---

## 5. 数据/接口增量
- **新表** `api_keys`(§4.1),迁移 `0007`。
- **新 proto** `apikey.proto`:`ApiKeyService{Issue, Revoke, List}` + 消息。
- **新配置**:`BS_APIKEY_PEPPER`(必填,fail-closed)。
- **改动**:`authn.Caller` 加 `AuthMethod` + `ReadOnly`;`authn.Interceptor` 加 apikey 校验依赖 + bearer 前缀分派 + 只读 procedure 前缀白名单门;main 装配。既有 handler 逻辑**不改**。
- **公开路由不变**;key 管理 RPC 走认证门。

---

## 6. 明确不做 / 推后
- **每-key 细粒度作用域衰减(attenuation)** —— v1.1;需先有控制面动作词汇(审计 Action 动词是天然候选)+ 跨 handler 强制点。(v1 只做 K5b 粗粒度 `ReadOnly` 这一个有真收敛点的切片。)
- 定时/自动轮换、宽限窗自动化 —— 手动重叠已够。
- 管理台 UI —— alpha 保持 API/CLI 优先。
- IP 白名单、泄漏 key 扫描合作、每请求成功认证审计 —— 后续。
- 无-org 全局服务凭证(`org_id=""`)—— 表留位,v1 必填 org。
- API key 作为 agent 默认运行时凭证 —— **刻意不做**(红线);agent 走短 TTL 委托。

---

## 7. 测试与验收(全程真 Postgres 容器;认证接入对真 Keycloak+Postgres)
- **签发/只存哈希**:Issue 返回明文一次;DB 里无明文、只有 HMAC;再查 List 拿不到 secret。
- **认证成功**:用签发的明文 key 走拦截器 → `Caller{PrincipalID=绑定 principal, AuthMethod:"apikey", SystemAdmin:false}`;能调其 principal 有权的 RPC。
- **认证失败(fail closed)**:坏 CRC/改一位/未知 keyid/已吊销/已过期 → `Unauthenticated`,且发一条 `apikey.auth` outcome=denied;**成功认证不发审计洪水**。
- **常量时间**:比对走 `subtle.ConstantTimeCompare(hash)`,不比明文。
- **K8 授权**:A 给 B 签 key → `PermissionDenied`;自己给自己签 → OK;system-admin 给任意 → OK。
- **K6**:key 认证的 Caller 恒非 system-admin(即便绑的 principal 是……——principal 本就无 admin 位,断言 Caller.SystemAdmin=false)。
- **K5b 只读**:`read_only` key → 调 `List`/`Get`/`Check`/`Verify`/`CheckDelegated` 放行;调任一 mutation(`Create*`/`Add*`/`Assign*`/`Register*`/`Issue`/`Revoke`)→ `PermissionDenied`。非只读 key 两类都按其 principal 权限走。断言前缀白名单 fail-safe:一个构造的"未来 mutation"方法名同样被拒。
- **吊销即断**:吊销后同一 key 立即 `Unauthenticated`;principal 删除级联吊销其所有 key。
- **多活跃 key/轮换**:同 principal 两把 key 都能认证;吊一把不影响另一把。
- **脱敏**:审计 `apikey.issue`/`revoke` 的 detail 里查不到 secret/hash(detail 只放 name/principal/过期;注意 `audit.Redact` 会丢任何含 "key" 的键,故 detail 字段名避开 "key",key_id 走 TargetID)。
- **pepper fail-closed**:未设 `BS_APIKEY_PEPPER` → 拒启动。
- 提交署名 Silas、无 Co-Authored-By/Claude trailer;精确 `git add`。

---

## 8. 风险与开放问题
- **attenuation 不进 v1 —— 已由专家复核代码后确认(撤回原"几乎免费")**。定论:v1 key = 所绑 principal 完整权限,细粒度衰减推 v1.1(属数据面/agent 关切,已由短 TTL 委托承载);K6/K8/过期/吊销已杀掉提权/admin/混淆代理。宁可不存 scope 列,不做安全剧场。v1 仅纳入 **K5b `ReadOnly`** 这一个由拦截器单点强制的诚实切片(泄漏只读 key 爆炸半径极小的真实用例)。
- **key 绑高权 principal**:key 继承其 principal 的全部权限。缓解=K8(只能自签)+ K6(永不 admin)+ 可选过期 + 审计。真需要"更小权限的 key"时上 attenuation(v1.1)。
- **last_used_at 写放大**:每请求更新一行是写压力。缓解=节流(如每 key 最多每分钟写一次)或异步 best-effort;精度到分钟够审计/轮换用。
- **pepper 轮换**:换 pepper 使所有旧 key 哈希失配 = 全体失效。v1 pepper 固定,轮换=运维事件(重签所有 key),文档化;带版本的 pepper 轮换留后续。
- **认证失败审计的放大**:被喷坏 key 时 `apikey.auth` denied 可能量大——与 JWKS 未知-kid 同类,必要时限流(复用审计 best-effort 丢弃)。
