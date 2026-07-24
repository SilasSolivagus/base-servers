# base-servers · Ring 1 · 限流(Rate Limiting)· 设计文档

- 日期:2026-07-24
- 状态:设计待评审
- 范围:Ring 1(信任与安全)第三个子项目 —— **限流(Rate Limiting)**,并**顺带补齐** API Keys 模块推后的 `apikey.auth` 认证失败遥测
- 前置:Ring 0 + Ring 1(审计 + API Keys)已在 main(`9d5db44`)
- 仓库:https://github.com/SilasSolivagus/base-servers

---

## 1. 背景与目标

控制面现全部经**一个** Connect 认证拦截器(`authn.Interceptor.WrapUnary`,所有真 RPC 都是 unary;streaming 无条件 fail-closed)。但没有任何节流:一个失控/被盗的 agent 可以猛打控制面;更具体地,**上个模块(API Keys)新开了一个认证前攻击面** —— `apikey.Verifier` 对未知 keyid 每次都打一次 `GetByKeyID` DB 查询(凭证喷洒 = 认证 DB 上的 DoS),API Keys 的 review 明确标记此洞未覆盖。

> 定位:在控制面唯一收敛点(拦截器)加**两道 token-bucket 门**——**认证前 per-IP**(挡未知-keyid DB 喷洒 / 认证-DoS)+ **认证后 per-principal**(挡失控/被盗 agent、租户公平)——每副本内存、fail-open、绝不让限流自身故障拖垮可用性;被限流进审计"决策流"。**顺带**把 API Keys 推后的 `apikey.auth` 认证失败遥测补上(Gate A 天然给它限了量)。

### 北极星对齐 / 红线
- **保可用性,不自毁可用性**:限流是保护控制面的;它自身故障必须 **fail-open**(与审计同类,非与认证同类)。
- **喂控制塔**:`ratelimit.throttled`(进入被限流态那一刻)进审计决策流 —— "控制塔看到 agent 被限流"。
- **北极星线索(点名不建)**:per-principal 桶是未来 **per-delegation / per-agent 调用预算**("这个 OBO token 最多调 N 次")的基座 —— 那才是把限流讲成"委托治理"的差异化;v1 只建 per-principal,spec 点名方向。

---

## 2. 核心设计决策(含理由)

| # | 决策 | 选择 | 理由 |
|---|---|---|---|
| R1 | 两道门 | **Gate A(认证前,per-源IP)** + **Gate B(认证后,per-principal)**,都在 `WrapUnary` | 请求流是 `authenticate→才有 Caller`。凭证喷洒的贵操作(`GetByKeyID`)发生在认证**前**、且认证**失败**时无 principal 可 key —— 只有认证前 per-IP 门能挡(唯一覆盖该确认漏洞的东西)。Gate B 挡认证后的失控 agent |
| R2 | 算法 | **token bucket**,用 `golang.org/x/time/rate`(准标准库,不手搓);sharded `map[key]*rate.Limiter` + mutex + 空闲 key 定期驱逐 | burst+refill 两个旋钮贴合 agent 合法批量;O(1) 内存;惰性 refill 无后台清扫;可读性优于 GCRA。search-before-building:`x/time/rate` 即内置惰性桶 |
| R3 | 存储 | **每副本内存**;藏在 `Limiter` 接口(`Allow(key)(allowed bool, retryAfter time.Duration, transitioned bool)`)后;**集群有效上限 = 配置 × 副本数**(文档写明,alpha 可接受的滥用天花板精度) | 每请求同步打 Postgres 去"保护过载"是自毁:限流器成最热竞争写、恰在攻击时成瓶颈。审计自己都异步批量丢弃不同步落库(recorder.go)。这些是**滥用天花板**非计费额度,量级对即可。Postgres-共享后端藏接口后留 v2;**不引 Redis**(自托管负担) |
| R4 | 失败语义 | **fail-open** | 限流保可用性,不能把自身故障升级成对合法请求的拒绝(否则送人更好的 DoS:打翻限流器=打翻整个面)。内存实现本无"后端不可用"态,但把语义写进接口(`Allow` 不返回 error;将来 DB 后端出错→allow),防 v2 意外引入 fail-closed |
| R5 | 豁免 & 分级 | **`AuthMethod=="root"`(root-token break-glass)绕过两道门**(非泛 SystemAdmin);per-AuthMethod 不同预算:**apikey > oidc**(M2M 自动化量合法且被盗最危险,给更高但仍有界的预算;人点击给低量) | 限流自己的应急访问=事故时把自己锁在门外。豁免精确 keyed 在 root-token 路径,非 SystemAdmin(可分离;被盗 admin principal 仍应被限)。AuthMethod 已在 Caller 里,免费分级 |
| R6 | 源 IP 提取 | 默认 `req.Peer().Addr` 的 host;**开关 `BS_RATELIMIT_TRUST_PROXY`(默认 false)**打开时取 `X-Forwarded-For` **最左**客户端 IP | 部署前置 Caddy 网关时 peer 是网关一个 IP → per-IP 塌成全局。**盲信 XFF 让客户端伪造 IP 逃逸/投毒**,故默认不信;仅在"确有信任代理设/剥 XFF"时 opt-in。footgun 文档点名 |
| R7 | 响应 | `connect.CodeResourceExhausted`(→ HTTP 429)+ `Retry-After` 头(到下一 token 的秒数,token bucket 已能算) | 惯用;良好客户端据 Retry-After 退避。v1 不出完整 `X-RateLimit-*` 三元组(per-副本下 remaining 本就模糊) |
| R8 | 被限流审计 | `ratelimit.throttled` 事件,**只在 per-key"进入被限流态"的边沿发一次**(非每个被拒请求),走既有异步 best-effort recorder | 洪水下每请求发审计=放大器,会用 throttle 事件淹掉真安全事件。边沿触发 + 异步丢弃 = "某 key 在 T 开始被限流"信号而不洪水。**导入环**:拦截器在 authn 包,audit 又 import authn → authn 不能 import audit;故 throttle 审计经**注入的 hook 接口**(consumer 侧定义,main 提供 audit 适配器)发 |
| R9 | apikey.auth 遥测(1+3 折入) | `apikey.Verifier` 加一个 `audit.Recorder`,认证**失败**(未知/不符/已吊销/已过期)发 `apikey.auth` outcome=denied,detail 只含非密 keyid(前缀)、绝不含 secret | apikey 已 import audit(无新环:authn 不 import apikey);Gate A 已在认证前限了喷洒量,天然给此遥测封顶;recorder 满则丢。给 Gate B 将来定数的"认证尝试量"数据 |
| R10 | 配置 | ~6 env 旋钮 + `BS_RATELIMIT_ENABLED` 杀开关;**不建 `rate_limits` 表** | 最小可用面;杀开关关键(限流在谁的部署里抽风可无逻辑改动关掉)。per-subject 策略表是"产品版限流",零客户需求,违 YAGNI —— 真有人要"给这个 agent 更高额"时再建,藏同一 `Allow(key)` 接口后 |

---

## 3. 架构

```
        Connect WrapUnary(一个拦截器,唯一收敛点)
        ┌─────────────────────────────────────────────────────────┐
        │ 0) root-token? → 有效则跳两门(break-glass),Caller{root} │
        │ 1) [Gate A] per-IP 桶(认证前)                             │
        │      Limiter.Allow("ip:"+clientIP) 不过 → 429+Retry-After │
        │      (edge→ throttle hook: gate=ip)                       │
        │ 2) authenticate(oidc / apikey.Verify)→ Caller             │
        │      apikey 失败 → Verifier 发 apikey.auth denied(R9)     │
        │ 3) [Gate B] per-principal 桶(认证后,按 AuthMethod 预算)  │
        │      Limiter.Allow("pr:"+authMethod+":"+principalID)      │
        │      不过 → 429+Retry-After (edge→ throttle hook: gate=pr)│
        │ 4) ReadOnly 门(既有)                                      │
        │ 5) next                                                    │
        └─────────────────────────────────────────────────────────┘
              limiter: internal/ratelimit(x/time/rate,每副本内存,纯,无 audit/authn 依赖)
              throttle hook: 注入接口(main 用 audit.Recorder 适配)
```

---

## 4. 模块设计

### 4.1 `internal/ratelimit`(纯,只依赖 x/time/rate + stdlib)
- 接口:
  ```go
  type Limiter interface {
      // Allow 报告该 key 此刻是否放行;retryAfter=到下一 token 的建议等待;
      // transitioned=本次调用是否让该 key 从"未限流"跨入"被限流"(边沿,用于审计一次)。
      // 绝不返回 error(fail-open 内建):任何内部故障都当作 allowed。
      Allow(key string) (allowed bool, retryAfter time.Duration, transitioned bool)
  }
  ```
- 内存实现 `MemoryLimiter`:`NewMemory(rps float64, burst int) *MemoryLimiter`。sharded `map[string]*entry`(entry={`*rate.Limiter`, lastSeen, wasLimited bool})+ `sync.Mutex`(或分片锁)。`Allow`:取/建 entry → `lim.Allow()`(x/time/rate 惰性桶)→ 若拒,`retryAfter = lim.Reserve().Delay()` 之类算 or `res.DelayFrom`;`transitioned = !entry.wasLimited && !allowed`,更新 `wasLimited`;放行时清 `wasLimited`。后台 `go evictIdle(ttl)`:定期删 lastSeen 超 ttl 的 key(防无界增长);进程退出停。
- 一个"关掉"实现 `AllowAll`(或 `MemoryLimiter` 在 disabled 时用 nil-limiter):`Allow` 恒 `(true,0,false)`。杀开关用。

### 4.2 authn 拦截器改造
- `Interceptor(...)` 增加依赖:`ipLimiter Limiter`、`principalLimiter map[string]Limiter`(按 AuthMethod:apikey/oidc;缺省桶给未知)、`onThrottle ThrottleHook`(见下)。任一 limiter 为 nil ⇒ 该门关闭(杀开关/未配置)。
- `ThrottleHook`(**consumer 侧定义在 authn**,避免 authn→audit 环):
  ```go
  type ThrottleEvent struct { Gate, Key, AuthMethod, PrincipalID string }
  type ThrottleHook func(ctx context.Context, ev ThrottleEvent)
  ```
  main 提供实现:把 `ThrottleEvent` 映射成 `audit.Event{Action:"ratelimit.throttled", Outcome:OutcomeDenied, ...}` 交 `audit.Recorder`。nil hook ⇒ 不发审计(仍限流)。
- `WrapUnary` 顺序(改):① root-token 命中且有效 → 跳两门、`Caller{SystemAdmin,AuthMethod:"root"}`、next(break-glass R5)。② Gate A:`clientIP(req)`(R6)→ `ipLimiter.Allow("ip:"+ip)`;拒 → `ResourceExhausted`+Retry-After,edge 触发 hook(gate=ip),**不进 authenticate**。③ `authenticate`(oidc/apikey)。④ Gate B:按 `caller.AuthMethod` 选桶 → `Allow("pr:"+authMethod+":"+principalID)`;拒 → 429+Retry-After,edge hook(gate=principal)。⑤ ReadOnly 门(不变)。⑥ next。
- `clientIP(req)`:`BS_RATELIMIT_TRUST_PROXY` 关 → `req.Peer().Addr` 的 host;开 → `X-Forwarded-For` 最左 host,空则回落 peer。
- `WrapStreamingHandler` 维持无条件 fail-closed(无 streaming RPC,不接门)。
- Retry-After:拒时在响应 header 写 `Retry-After: <ceil(retryAfter秒)>`(经 `connect.NewError` 的 meta / 或 interceptor 设 header)。

### 4.3 apikey.auth 遥测(R9,改 `internal/apikey`)
- `apikey.Verifier` 加字段 `rec audit.Recorder`(`NewVerifier(store, hasher, rec)`)。`Verify` 在返回 `ErrInvalidKey` 前(仅"曾解析出合法 keyid 但校验/活性不过"及"未知 keyid"两类;坏 CRC 可选)发一条:`audit.Event{Action:"apikey.auth", Outcome:OutcomeDenied, TargetType:"apikey", TargetID:<keyid或前缀>, Detail:{reason:"unknown|mismatch|revoked|expired"}}`,**secret 段已在解析后即弃**,detail 无 secret。best-effort(recorder 满则丢)。成功认证**不发**(量太大)。
- main 给 Verifier 传 `auditRec`(已构造)。

### 4.4 装配(改 `cmd/base-servers/main.go` + `internal/config`)
- config 加:`RateLimitEnabled bool`、`RateLimitIPRPS/Burst`、`RateLimitAPIKeyRPS/Burst`、`RateLimitOIDCRPS/Burst`、`RateLimitTrustProxy bool`。
- main:若 `RateLimitEnabled`,构造 `ipLim := ratelimit.NewMemory(cfg.RateLimitIPRPS, cfg.RateLimitIPBurst)`,`prLims := {"apikey":NewMemory(apikey...), "oidc":NewMemory(oidc...)}`;否则全 nil(门关)。构造 throttle hook 适配 `auditRec`。把这些 + trustProxy 传入 `authn.Interceptor(...)`。Verifier 传 `auditRec`。

---

## 5. 数据/接口增量
- **新包** `internal/ratelimit`(接口 + 内存实现 + 驱逐)。
- **新依赖** `golang.org/x/time/rate`(准标准库;`go get`)。
- **无新表、无新 proto、无新 RPC**(限流在拦截器,不是服务)。
- **新配置**:R10 的 6~7 个 env(全有默认;`BS_RATELIMIT_ENABLED` 默认 true)。
- **改动**:`authn.Interceptor` 签名(加 limiter×2 + hook + trustProxy)+ `WrapUnary` 两门;`apikey.Verifier` 加 recorder + `apikey.auth` 发射;main 装配;既有 `authn.Interceptor(...)` / `apikey.NewVerifier(...)` 全部调用点更新(含各 *_test.go)。
- **公开路由不变**;health(/healthz、/readyz)不经拦截器,不受限流。

---

## 6. 明确不做 / 推后
- **per-org/租户公平** —— Caller 无 org id,解析需热路径多查 + principal 多-org 无单一"租户";v1.1。per-principal 是 alpha 够用的公平代理(agent 是高频 principal、1:1 workload)。
- **per-procedure / per-(principal,procedure) 限额** —— 需成本数据 + 桶数×procedure 基数;v1.1。
- **per-delegation / per-agent 调用预算** —— 北极星线索,需 limiter key 到 delegation/token 身份(Caller 里没);spec 点名,v1 不建。
- **Postgres-共享后端(精确全局限)** —— 藏 `Limiter` 接口后,v2;v1 每副本内存 + N× 文档化。
- **`rate_limits` 策略表 + 每-subject 覆盖 + 管理 RPC** —— 产品版,零需求,YAGNI;真需求出现再建。
- **完整 `X-RateLimit-*` 三元组** —— 仅 `Retry-After`。

---

## 7. 测试与验收(纯逻辑单测 + 拦截器集成对真容器少量)
- **token bucket 正确**:`MemoryLimiter` burst 内连过、超 burst 拒、按 rps 恢复;`transitioned` 只在跨入被限流的那一次为 true,恢复放行后再次跨入再为 true(边沿语义)。`Allow` 永不 error。
- **Gate A per-IP(认证前)**:未认证请求同 IP 超限 → `ResourceExhausted` + `Retry-After`;**且证明在 authenticate 之前拒**(注入一个会 panic/计数的 fake verifier,超限请求根本不该到它)。不同 IP 独立桶。`TRUST_PROXY` 开时按 XFF 最左分桶;关时按 peer。
- **Gate B per-principal(认证后)**:同 principal 超限 → 429;不同 principal 独立;apikey 与 oidc 用各自预算(apikey 预算 > oidc,构造证明)。
- **root 豁免**:root-token 请求超任何量都不被限(跳两门)。
- **fail-open**:limiter 永不使合法请求失败(无 error 路径);杀开关 `ENABLED=false` → 门全关,任意量放行。
- **审计边沿**:同 key 连续 N 次被拒,`ratelimit.throttled` 只发 1 条(用 FakeRecorder-hook 断言);恢复后再被限再发 1 条。actor:Gate A 无 principal(记 ip),Gate B 记 principal + auth_method。
- **apikey.auth 遥测(R9)**:未知 keyid / 改一位 / 已吊销 / 已过期 认证失败各产生一条 `apikey.auth` denied、detail **无 secret**、只非密 keyid;**成功认证不发**;坏 key 洪水下 recorder 满则丢不阻塞。
- **无环 / 无泄漏**:`internal/ratelimit` 不 import audit/authn;`authn` 不 import audit(throttle 经注入 hook);secret 不入任何 throttle/apikey.auth detail。
- **既有全绿**:改了 `Interceptor`/`NewVerifier` 签名后,既有 authn/apikey/各 handler 测试仍通过。
- 全量 `go test ./...`(真 Keycloak+Postgres);`internal/ratelimit -race`(分片桶 + 驱逐 goroutine 竞争)。提交署名 Silas、无 cc trailer;精确 `git add`。

---

## 8. 风险与开放问题
- **每副本内存 → N× 上限**:多副本下有效上限=配置×副本数。这是滥用天花板非计费额度,量级对即可;文档化;精确全局留 Postgres 后端 v2。
- **XFF 信任**:开 `TRUST_PROXY` 而前面没有真剥/设 XFF 的可信代理 → 客户端可伪造源 IP 逃逸 per-IP。默认 false;文档强调"仅当确有可信代理时开"。
- **Gate A × 合法共享出口 IP**:多个合法客户端(或 agent 集群)共用一个出口 IP/NAT → 互相挤 per-IP 预算。Gate A 预算给足 + 主防线是 Gate B(per-principal)。极端场景靠 per-org(v1.1)。
- **驱逐 × 长尾 key**:海量不同 IP(分布式喷洒)→ map 膨胀。驱逐 TTL + 分片;必要时给桶总数上限(超则 LRU/直接放行低价 miss)。文档化。
- **限流数字靠猜**:v1 无认证尝试量历史,Gate B 默认值是估计。缓解:R9 遥测 + 杀开关 + 可调 env;有真流量后校准(与专家旗标一致)。
- **Retry-After 精度**:per-副本 + 惰性桶下是近似;够良好客户端退避,不作精确契约。
