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
| K5b | 唯一诚实衰减切片 | **可选 `ReadOnly` key**,**在 authn 拦截器单一收敛点**强制。**判定用显式 per-procedure 分类,默认 deny**:每个 RPC 在 proto 上打 `option (baseservers.v1.read_safe) = true;` 声明自己是纯读;只读 key 仅放行 `read_safe=true` 的 procedure,**未标注即拒**(真 fail-safe,无命名耦合)。拦截器持一个"只读安全 procedure 全集",一处集中、code-review 可见 | 唯一有**真收敛点**的粗粒度能力(拦截器已是每 RPC 必经)。服务只读用例真实:验权资源服务器 / CI 监控只调 `CheckDelegated`/`authz.Check`/`List` 验证、绝不改动;泄漏一把只读 key 爆炸半径极小。**放弃前缀白名单**(评审 C1:`GetOrCreate*`/`Verify*` 会被误放行、`Resolve*`/`Introspect*` 读会被误拒,且把安全边界耦合到全系统命名约定上——新加一个 `GetOrCreateX` 就在只读边界打洞) |
| K5c | key 不能生 key | **`Issue` 要求 `AuthMethod ∈ {oidc, root}`** —— API key 认证的调用**不得**调 `Issue`(即便非只读) | 评审 C2:否则一把泄漏的全权 key 可给同 principal 再铸任意多把新 key,**吊销原 key 无法止血**(持久化后门)。禁 key 生 key 把泄漏爆炸半径从"永久"压回"单把有效期内";契合"key 是引导/边缘凭证、非自助铸币机"的定位。叠加 per-principal 活跃 key 上限(见 §8)做纵深 |
| K6 | system-admin | **API key 永不携带 SystemAdmin**(key 认证的 Caller 恒 `SystemAdmin=false`);bootstrap 仍只走 root-token | 现状 SystemAdmin 只经 root-token 产生;key→principal 恒非 admin,是干净且安全的默认——key 泄漏不会给到跨租户特权 |
| K7 | 生命周期 | 每 principal **多把活跃 key**(轮换=重叠);**可选过期**(`expires_at` 可空)受 **max-TTL 策略**约束(I9,`BS_APIKEY_MAX_TTL_SECONDS` 默认 90d;永不过期须显式 opt-in);单-key 吊销(`revoked` bool);**principal 删除不自动级联**(I1:KC-external 身份无可靠通知,需单独吊销);`last_used_at` 尽力更新(节流/异步,不阻塞,**绝不用于安全判定**,M6) | 多活跃 key 让轮换 = 建新→部署→吊旧(`last_used_at` 确认旧 key 静默),这就是 v1 的全部轮换;无定时轮换、无宽限窗自动化 |
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
org_id        TEXT NOT NULL,              -- 归属 org:仅分组/审计元数据,v1 不约束 authz 触达(见 I2)
name          TEXT NOT NULL DEFAULT '',   -- 人给的标签,便于识别/轮换
hash          BYTEA NOT NULL,             -- HMAC-SHA256(pepper, secret)
hash_version  SMALLINT NOT NULL DEFAULT 1,-- I5:pepper 版本,为前向兼容双验/轮换预留
created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
expires_at    TIMESTAMPTZ,               -- 可空;NULL=不过期(受 max-TTL 策略约束,见 K7/I9)
last_used_at  TIMESTAMPTZ,               -- 尽力更新;非精确、多副本非同步,绝不用于任何安全判定
read_only     BOOLEAN NOT NULL DEFAULT false,  -- K5b:只读 key(拦截器 read_safe 白名单强制)
revoked       BOOLEAN NOT NULL DEFAULT false
```
索引:`(principal_id)`(列 key 用)、`(org_id)`。**不可变性不必如审计**(key 可吊销/更新 last_used),故无 append-only 触发器。
- **I2 · org_id 语义(明确)**:v1 里 `org_id` **仅为分组/审计元数据,不约束 key 的 authz 触达** —— 一把 key 认证的 Caller 只带 `PrincipalID`,授权仍走该 principal 的角色/成员资格。若 principal 同时是 org B 成员,该 key 也能作用于 B(与"无衰减"一致)。真把 key 锁死到单一 org = 需把 org 注入 Caller + 下游改动,那等于 attenuation,推 v1.1。字段注释与文档须写清此点,避免"已被 org 限定"的错觉。
- **I1 · principal 删除与 key(诚实降级)**:principal 是 **Keycloak 签发**,base-servers 收不到 KC 侧带外删除通知,故**没有可靠的"删 principal 即级联吊销其 key"机制**。v1 定论:**key 生命周期独立于 principal 删除** —— 删 principal 必须**单独吊销其 key**(或靠过期)。若 base-servers 后续提供 `DeletePrincipal` RPC,可在其中显式吊销该 principal 的全部 key(应用层,非 DB FK);带 Keycloak 对账的自动吊销留后续。§7 不写"级联吊销"这条不可实现的验收。

### 4.2 密钥生成 / 校验(`internal/apikey`,新写,无现成可复用)
- **生成**:`key_id` = 短 base62(crypto/rand,唯一,如 16 char);`secret` = 32+ char base62(crypto/rand,≥160 位);`crc` = base62(CRC32(`bsk_`+keyid+`_`+secret))。明文 = `bsk_<keyid>_<secret><crc>`,**仅签发响应返回一次**。存 `HMAC-SHA256(pepper, secret)`。
- **校验(Verifier,拦截器调)**:① 解析 `bsk_<keyid>_<secret><crc>`,**先切出并丢弃 secret 段**(I7:secret 一个字节都不得进入任何错误/审计/日志路径),CRC 自校验(坏 key 免 DB 直拒;CRC 公开、不参与认证决策)② 按 `key_id` 查一行 ③ `subtle.ConstantTimeCompare(HMAC(pepper, secret), row.hash)` ④ `!revoked && (expires_at IS NULL || now < expires_at)`。任一不过 → 认证失败(fail closed);**DB 出错也 fail-closed,绝不回落 Keycloak**。成功 → 返回**原语**`(principalID, readOnly bool, nil)`(I3:Verifier 不返回 `authn.Caller`,由 authn 侧构造 Caller,避免 apikey→authn 导入环;接口定义在 authn 消费侧),authn 据此构造 `Caller{PrincipalID, AuthMethod:"apikey", ReadOnly}`,并**尽力**节流更新 `last_used_at`(不阻塞请求)。
- **返回给拦截器的 denied 信号里也不得含 secret**(I7);对畸形/坏 CRC 的 token(可能连合法 keyid 都没有)审计只可记非密 keyid 段、绝不记原始 token。
- **pepper**:`BS_APIKEY_PEPPER`(base64 of 32 随机字节),未设即拒启动(fail-closed,与 `BS_SIGNING_KEK` 同风格)。pepper 让"仅拿到 DB"的攻击者无法离线暴力/比对哈希。**不加 per-key salt**:secret 是 160+ 位随机、彩虹表不可行、撞值可忽略,salt 零收益;pepper 提供仅-拖库的离线防护。轮换 pepper = 全体 key 失配,故 `hash_version` 列预留将来双验平滑迁移(v1 只认版本 1)。

### 4.3 认证接入(改 `internal/authn`)
- `Caller` 加 `AuthMethod string`(`"oidc"`/`"apikey"`/`"root"`;审计 `Actor`/decision 的 `via` 可用)+ `ReadOnly bool`。既有两路填 `"oidc"`/`"root"`、`ReadOnly=false`。
- 拦截器 `Interceptor(v *Verifier, rootToken string)` → 加一个 apikey 校验依赖(接口定义在 authn 侧,`apikey.Verifier` 只依赖自己的 store、返回原语,永不 import authn——见 I3,杜绝导入环)。`WrapUnary`/`WrapStreamingHandler` 的 bearer 分支:**`strings.HasPrefix(token, "bsk_")` → 排他走 apikey 路径,失败即 `Unauthenticated`,绝不回落 Keycloak**(M1;JWT 恒以 `eyJ` 开头,命名空间不冲突);否则 → Keycloak `v.Verify`。**key 认证的 Caller 恒 `SystemAdmin=false`**(K6)。
- **K5b 只读强制(单一收敛点,显式分类默认 deny)**:构造出 `Caller` 后,若 `Caller.ReadOnly`,取 `req.Spec().Procedure`,**仅当该 procedure 在"只读安全全集"中才放行**,否则 `PermissionDenied`。该全集来自 proto 上每个 RPC 的 `read_safe` 选项(纯读才标 true),在拦截器持有为一个集中常量集合;**未标注/未知 procedure 一律拒**(真 fail-safe,无命名耦合)。**不用方法名前缀**(评审 C1:前缀会误放行 `GetOrCreate*`/`Verify*` 副作用方法、误拒 `Resolve*`/`Introspect*` 读)。streaming procedure 同样按此集合判定。加一条测试**枚举所有已注册 procedure**,断言每个都被显式归类(read_safe true/false),未归类即测试失败——防止将来新增 RPC 在只读边界留盲区。此判定只依赖 `Caller.ReadOnly` + procedure 名,与凭证来源无关,放在拦截器 authn 之后、`next` 之前。
- 与 OIDC 路径认证后完全同构:下游 handler 的 `RequireMember`/`authz.Check`/委托 `caller==delegator` 全不改。

### 4.4 API(`proto/baseservers/v1/apikey.proto` → buf → handler,认证门后)
- `ApiKeyService.Issue(IssueApiKeyRequest{principal_id, org_id, name, ttl_seconds(0=按策略上限/不过期), read_only}) → {key_id, secret_once, expires_at}` ——
  - **C2/K5c:要求 `caller.AuthMethod ∈ {oidc, root}`;API key 认证的调用调 Issue 直接 `PermissionDenied`**(key 不能生 key)。
  - 授权 K8:`caller.PrincipalID==principal_id`(自签)**或** system-admin(root-token)为任意 principal 引导。**I4:system-admin(root-token,PrincipalID 为空、非任何 org 成员)绕过 `RequireMember`**;非 admin 的自签路径才走 `RequireMember(caller.PrincipalID, org_id)`。**Bootstrap 流程(写清)**:service/agent 无交互会话,其**首把 key 由持 root-token 的运维经 system-admin 路径引导**(指定 principal_id + org_id,跳过成员校验)。
  - **I9:`ttl_seconds` 受 max-TTL 策略约束** —— 新增 `BS_APIKEY_MAX_TTL_SECONDS`(默认如 90d);请求 `ttl_seconds` 超上限即拒;`ttl_seconds=0`=永不过期仅当策略显式允许(`BS_APIKEY_ALLOW_NEVER_EXPIRE=true`),否则 0 落为策略上限。默认不鼓励永久 key(与"消灭静态密钥蔓延"定位一致)。
  - **M4:Issue 非幂等** —— 重试会多铸一把 key(且首个 secret 可能已丢);文档点名,靠 name+List+Revoke 清理;可选 idempotency key 留后续。
  - `secret_once` 仅此一次返回;`read_only` 落 `api_keys.read_only`。
- `ApiKeyService.Revoke(RevokeApiKeyRequest{key_id}) → {}` —— 授权:key 属主 principal 自己 **或** system-admin;回读 key 的 principal/org 做校验(不新增查询之外)。(**I8** org-admin/owner 吊销/签发本 org 内 principal 的 key —— 需先有明确的 org-admin 角色定义,列为紧邻 fast-follow;v1 先 self + system-admin,service key 事件响应经 root-token break-glass。)
- `ApiKeyService.List(ListApiKeysRequest{principal_id, page_size, page_token}) → {keys[], next_page_token}` —— 只出**非密元数据**(key_id、name、created/expires/last_used、read_only、revoked),**永不出 secret/hash**;**M3:游标分页**(对齐审计 List);授权同 Revoke。
- 三者都在 Ring 0 认证门后;handler 侧做 authz + 审计埋点。

### 4.5 装配(改 `cmd/base-servers/main.go`)
- 构造 `apikeyStore := apikey.NewStore(pool)`、`apikeyVerifier := apikey.NewVerifier(apikeyStore, pepper)`;传入 `authn.Interceptor(verifier, apikeyVerifier, cfg.RootToken)`;`server.New(...)` handler 列表加 `apikey.NewHandler(apikeyStore, orgStore, auditRec)`。config 加 `BS_APIKEY_PEPPER`(fail-closed)。

---

## 5. 数据/接口增量
- **新表** `api_keys`(§4.1),迁移 `0007`。
- **新 proto** `apikey.proto`:`ApiKeyService{Issue, Revoke, List}` + 消息。
- **新配置**:`BS_APIKEY_PEPPER`(必填,fail-closed);`BS_APIKEY_MAX_TTL_SECONDS`(默认 90d);`BS_APIKEY_ALLOW_NEVER_EXPIRE`(默认 false)。
- **新 proto 选项**:`baseservers.v1.read_safe`(method option),各 RPC 标注是否纯读(K5b 只读门用);现有 List/Get/Check/Verify 类 RPC 标 `true`,mutation 不标。
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
- **K5b 只读**:`read_only` key → 调标了 `read_safe` 的 procedure(List/Get/Check/Verify/CheckDelegated)放行;调任一未标注的(全部 mutation)→ `PermissionDenied`。非只读 key 两类都按其 principal 权限走。**枚举测试**:遍历所有已注册 procedure,断言每个都被显式归类(read_safe true/false),无未归类者。
- **K5c key 不能生 key**:API key 认证的调用调 `Issue` → `PermissionDenied`(即便非只读 key);oidc/root 认证调 Issue 正常。
- **吊销即断 + 无法再生**:吊销后该 key 立即 `Unauthenticated`(每请求实时查库、无缓存,故即时生效);且用泄漏的全权 key 调 Issue 早已被 K5c 拒,吊销无法被"再生新 key"绕过。
- **I4 bootstrap**:root-token(system-admin)为一个无会话的 service/agent principal 引导首把 key(绕过 `RequireMember`)→ 该 key 可认证并调其 principal 有权的 RPC。
- **I9 max-TTL**:超 `BS_APIKEY_MAX_TTL_SECONDS` 的 ttl 请求被拒;未开 `ALLOW_NEVER_EXPIRE` 时 `ttl=0` 落为上限而非永久。
- **I6/I7 无 secret 泄漏**:`Issue` 响应外的任何日志/审计路径都查不到 secret;denied 审计/错误只含非密 keyid。
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
- **I6 · Authorization 头日志泄漏(头号真实泄漏面)**:`Bearer bsk_…` 是长期密钥,任何反代访问日志/APM/请求日志记 header 即把它永久写盘(不像短命 JWT)。缓解:前置代理/中间件必须对 Authorization 头脱敏;**`Issue` 响应(含 `secret_once`)严禁进任何请求/响应日志**(单独点名的经典泄漏点);`bsk_` 前缀让 secret scanner 能识别作部分缓解。文档必写明。
- **I7 · secret 绝不入审计/日志**:校验时 secret 段在进入任何错误/审计路径前即丢弃;denied 只记非密 keyid(或前缀);畸形 token 不记原文。
- **自铸上限(纵深)**:K5c(key 不能生 key)已堵持久化;再叠加 **per-principal 活跃 key 上限**(如默认 50)防单 principal 无限自铸。
- **M2 · 认证路径不对称(取舍即卖点)**:OIDC 走 JWKS 本地验签零 DB;apikey 每个已认证请求多一次 keyid 点查。控制面 QPS 低,换来的 **instant-revoke 是相对 JWT 的真优势**(作卖点写出);不缓存以保即时吊销。
- **M5 · 新认证路径无限流(DoS)**:攻击者本地算合法 CRC 喷 `bsk_` token,每次触发一次 keyid 点查。未知 keyid 是廉价索引 miss,但高并发仍是面;Ring 1 限流子模块(排本模块后)应覆盖,过渡期复用审计 best-effort 思路做入口节流。
- **I8 · service key 事件响应**:v1 只 self + system-admin 可吊销,非交互 service 的 key 泄漏只能经 root-token break-glass(重)。org-admin 在本 org 内吊销/签发列为紧邻 fast-follow(需先定义 org-admin 角色)。
