# base-servers · Ring 1 · 限流(Rate Limiting)· 设计文档

- 日期:2026-07-24
- 状态:设计已定稿(经专家对抗性评审,10 项 must-fix 已并入),待写实现计划
- 范围:Ring 1(信任与安全)第三个子项目 —— **限流(Rate Limiting)**,并**顺带补齐** API Keys 推后的 `apikey.auth` 认证失败遥测
- 前置:Ring 0 + Ring 1(审计 + API Keys)已在 main(`9d5db44`)
- 仓库:https://github.com/SilasSolivagus/base-servers

---

## 1. 背景与目标

控制面全部经**一个** Connect 认证拦截器(所有真 RPC 都是 unary;streaming 无条件 fail-closed),但无任何节流。具体地,API Keys 模块新开了一个**认证前**攻击面:`apikey.Verifier.Verify` 对**格式合法但未知**的 keyid 每次打一次 `GetByKeyID`(Postgres 往返)—— 凭证喷洒 = 认证 DB 上的 DoS,review 已标记未覆盖。

> 定位:在控制面加**两道 token-bucket 门** —— **认证前(外层 HTTP 中间件,per-源IP + 全局桶)** 挡未知-keyid DB 喷洒;**认证后(Connect 拦截器,per-principal)** 挡失控/被盗 agent。每副本内存、分片+硬上限有界、**fail-open**、绝不自毁可用性;被限流(边沿去抖)进审计。顺带补 `apikey.auth` 认证失败遥测(已知-keyid 全保真、未知-keyid 采样聚合,防审计缓冲被淹)。

### 北极星 / 红线
- **保可用性,不自毁可用性**:限流自身故障 **fail-open**(与审计同类,非与认证同类);限流器自身内存/锁必须有界,绝不成为它要防的那个瓶颈/DoS。
- **喂控制塔**:`ratelimit.throttled`(进入被限流态边沿,去抖)进审计决策流。
- **北极星线索(点名不建)**:per-principal 桶是未来 **per-delegation / per-agent 调用预算** 的基座。

---

## 2. 核心设计决策(含理由)

| # | 决策 | 选择 | 理由 / 评审来源 |
|---|---|---|---|
| R1 | 两道门的**位置** | **Gate A = 外层 `http.Handler` 中间件**(包住整个 mux,在 Connect/authenticate **之前**);**Gate B = Connect 拦截器 `WrapUnary`**(authenticate **之后**、ReadOnly 门之前) | Gate A 需要在 GetByKeyID 之前、且需拿真客户端 IP + 原生响应头写 `Retry-After`——外层 HTTP 中间件天然满足(拿 `*http.Request`、`w.Header()`、直接回 429)。Gate B 需要认证后的 `Caller`,只能在拦截器内。**[评审 C3:Connect unary 拒路径返回 (nil,err),无法设前导响应头;Retry-After 移到 HTTP 中间件]** |
| R2 | Gate A 的**桶** | **per-源IP 桶 + 一个全局桶(source-independent)** 并存;IP 桶 **IPv6 按 /64、IPv4 按 /24 前缀**分桶(/24 更抗规避:占一个 /24 的攻击者只挤一个桶而非 256 个;且复用作审计 IP 前缀) | **[评审 C1:per-IP 单独挡不住 DB 洞]** —— 攻击者一个 IPv6 /64 有 2^64 地址、僵尸网络多 IP,每 IP 少量未知-keyid 仍打 DB。全局桶把**总** GetByKeyID 量封死(与 IP 基数无关),是真正的 DB 洞后盾;per-IP 桶做常态公平。IPv6 /64 分桶让 per-IP 在 v6 下非摆设 |
| R3 | 算法 | **token bucket**,`golang.org/x/time/rate`(不手搓);**拒路径算 Retry-After 绝不消费 token**(`res:=lim.Reserve(); d:=res.Delay(); res.Cancel()` 或用 `lim.Tokens()` 反算) | **[评审 I1:Reserve() 会消费下一个 token,不 Cancel 则桶越勒越紧、Retry-After 无界增长]**。burst+refill 贴合 agent 合法批量;O(1) 内存;惰性 refill 无清扫 |
| R4 | 存储 & 有界 | **每副本内存,sharded(256 分片,FNV(key)%256,每分片各自 `sync.Mutex`)+ 每分片定容 LRU(硬上限)**;藏 `Limiter` 接口后;集群有效上限 = 配置 × 副本数(文档化) | **[评审 I5:分片 + 硬上限是强制的,非"必要时"]** —— 单锁 = 限流器自己成最热竞争点(正是要防的);无上限 map 在百万-IP 喷洒下 OOM = 限流器把进程 DoS。定容 LRU 使内存与攻击基数无关(达上限即 fail-open miss——这正是 R2 全局桶作真后盾的原因)。Postgres-共享后端留 v2,藏同一接口后;**不引 Redis** |
| R5 | 失败语义 | **fail-open**;`Limiter.Allow` **不返回 error**(内部故障即当 allowed) | 限流保可用性,不能把自身故障升级成对合法请求的拒绝(否则送更好的 DoS)。内存实现本无"后端不可用"态,但把语义焊进接口,防 v2 DB 后端意外引入 fail-closed |
| R6 | Gate B **键 & 预算** | **只按 `principalID` 分桶**(键不含 AuthMethod);**单一 per-principal 预算**(一档 rps/burst)。per-AuthMethod 分级预算**推后** | **[评审 I6:按 (authMethod,principalID) 分桶 → 同一 principal 经 oidc+apikey 两路可拿 2× 预算,双花绕过"被盗 agent"爆炸半径控制]**。apikey 绑的 principal 与 oidc sub 同命名空间、可重叠,故只按 principalID 分桶(爆炸半径正确、无双花)。方法分级预算无遥测=瞎猜,连同校准一起推后 |
| R7 | 豁免 | **有效 root-token(break-glass)跳两门**;抽出共享 `CheckRoot(header) (present, valid bool)`(定义在 `internal/authn`,裸函数,常量时间)供 Gate A 中间件与拦截器**同一处**判定。**必须焊回现有拦截器的两道护栏**:仅当(已配置 root token,即 `len(rootBytes)>0`)**且**(header 非空 `rt!=""`)才做 `ConstantTimeCompare`;否则 `valid=false`。`present = rt!=""` | **[评审 I7 + 二审 Critical:草图丢了两道护栏 → `BS_ROOT_TOKEN` 未设(裸/默认部署常态)时空 header 的 `ConstantTimeCompare("","")==1` → valid=true → 每请求跳 Gate A、限流器出厂即空转]**。只在 present&&valid 时跳;无效落 Gate A。精确 keyed 在 root-token 路径,非泛 SystemAdmin |
| R8 | 响应 | Gate A(中间件):HTTP **429 + `Retry-After`**(秒,已验证经 Caddy 到客户端)。Gate B(拦截器):`connect.CodeResourceExhausted`,Retry-After 走 `connect.Error.Meta()`(best-effort,**实现期端到端验证经 Caddy 是否落成真 `Retry-After` 头**,不成则接受仅 code) | **[评审 C3 must-verify]**:实现第一步用 curl 经 bundled Caddy 验证头名恰为 `Retry-After`;不成则 Gate B 也降到 HTTP 中间件层或只保 code |
| R9 | 被限流审计(边沿+去抖) | `ratelimit.throttled` 只在 per-key **进入被限流态边沿**发,且**每 key 冷却窗(默认 60s)去抖**:`entry.lastEmit`,`now-lastEmit>cooldown` 才发;经既有异步 best-effort recorder | **[评审 I2:纯边沿在稳态过载下震荡 allow/deny → 每秒约 rps 次转变/key,跨多 key 淹掉共享 recorder,真安全事件被丢]**。冷却窗把审计量封到 `keys/cooldown`,与 rps 无关。`lastEmit`/`wasLimited` 读改写必须在与桶操作**同一分片锁**内 |
| R10 | 审计事件的租户归属 | Gate A(认证前无 Caller)事件走 **"system" 链**(`OrgID=""`,adapter **不**调 `CallerFromContext`),Actor 空;Detail 记 **IP 前缀**(v6/64、v4/24,非全地址)+ gate/reason。Gate B 记 `principalID`(Actor 经 hook 显式传,非 ctx 取) | **[评审 I4:Gate A 事件无 principal/org,而审计是每租户;且原始 IP 进永久防篡改日志是 PII]**。系统链已存在(`ChainOf("")="system"`)。IP 前缀既留 ops 溯源信号又降 PII/永久留存面 |
| R11 | apikey.auth 遥测(1+3 折入,分级保真) | `apikey.Verifier` 加 `audit.Recorder`。**已知-keyid 失败(mismatch/revoked/expired)= 真攻击信号 → 全保真发** `apikey.auth` denied;**未知-keyid = 高基数噪声 → 独立去抖/采样**(周期发一条聚合计数,而非每次随机 miss 一条);secret 段解析后即弃、detail 只非密 keyid(前缀);成功认证不发 | **[评审 I3:R9 无独立封顶,靠"Gate A 天然封顶"是循环论证(仅在 C2 说是错的那个退化默认下成立);未知-keyid 随机喷洒是纯噪声,会饿死审计缓冲]**。apikey 已 import audit(authn 不 import apikey,无环) |
| R12 | 失败 root-token 遥测 | **仅当 `present && !valid`**(带了 header 但错,非"没带")发 `root.auth` denied,去抖(同 R9 缓冲安全);**只在 Gate A 中间件发一次**(它最先看 header 且决定 Gate A 跳/不跳),拦截器不重发 | **[评审 I7 gap + 二审:裸 bool 分不清 absent/invalid → 每个正常 OIDC 请求(无 header)都发会淹审计;中间件+拦截器都判会双发。故用 `present` 信号 + 单一发射层]**。爆破全局 break-glass 密钥是全系统最高信号事件 |
| R13 | 配置 | `BS_RATELIMIT_ENABLED`(杀开关,默认 true);`BS_RATELIMIT_IP_RPS/_BURST`(Gate A per-IP,常态公平,默认如 20/40);`BS_RATELIMIT_GLOBAL_RPS/_BURST`(Gate A 全局**灾难后盾**,**默认必须远高于全副本合法聚合峰值**,如 500/1000 —— 只作 DB 保护上限,绝非主限流,数值文档明确此意);`BS_RATELIMIT_PRINCIPAL_RPS/_BURST`(Gate B,默认如 10/20);`BS_RATELIMIT_TRUSTED_PROXY_CIDRS`(信任代理网段,默认含 compose 网关/loopback);`BS_RATELIMIT_MAX_KEYS`(每分片 LRU 容量,默认如 4096);冷却窗常量(默认 60s)。**不建 `rate_limits` 表** | 最小可用 + 杀开关。**[二审:全局桶计全部流量,默认值未定则实现者随手设小 → 车队正常峰值被全局节流饿死所有租户;必须写死"后盾非主限流"的量级]**。per-subject 策略表 YAGNI,真需求出现再建、藏 `Allow(key)` 接口后 |
| R14 | 源 IP & 信任代理 | 默认取 `http.Request.RemoteAddr` 的 host;**仅当 RemoteAddr ∈ `TRUSTED_PROXY_CIDRS`** 时取 `X-Forwarded-For` **最左**客户端 IP;否则用 RemoteAddr。**bundled Caddy 配置为设/覆盖 XFF**(本模块交付物之一) | **[评审 C2:默认 XFF-off 时 bundled Caddy 后 per-IP 塌成全局单桶——出厂即坏;盲信 XFF 又让裸部署被伪造]**。信任代理模型:网关后 peer=网关 IP(∈ 可信网段)→ 读 XFF;裸部署 peer=真客户端→用 peer。安全默认两头都对 |

---

## 3. 架构

```
   ┌─ 外层 http.Handler 中间件(server.New 包 mux)—— Gate A,认证前 ───────────┐
   │  clientIP(r) = TRUSTED_PROXY_CIDRS 含 RemoteAddr ? XFF最左 : RemoteAddr    │
   │  ValidRootToken(header)? → 跳 Gate A(break-glass)                        │
   │  globalLim.Allow("global") 不过 → 429+Retry-After (edge+cooldown→hook)    │
   │  ipLim.Allow("ip:"+prefix(clientIP)) 不过 → 429+Retry-After (→hook)       │
   │        ↓ 放行                                                             │
   │  ┌─ Connect WrapUnary(拦截器)────────────────────────────────────────┐   │
   │  │ rootPresent&&Valid? → Caller{SystemAdmin,AuthMethod:root}, 跳 Gate B│   │
   │  │ authenticate(oidc / apikey.Verify)→ Caller                         │   │
   │  │     apikey 失败 → Verifier 发 apikey.auth(R11:已知全保真/未知采样)  │   │
   │  │     (root.auth denied 只在中间件发一次,见 R12,拦截器不重发)        │   │
   │  │ [Gate B] prLim.Allow("pr:"+principalID) 不过 → ResourceExhausted    │   │
   │  │     +Retry-After(meta,best-effort)(edge+cooldown→hook)            │   │
   │  │ ReadOnly 门(既有)→ next                                            │   │
   │  └────────────────────────────────────────────────────────────────────┘   │
   └────────────────────────────────────────────────────────────────────────────┘
     limiter: internal/ratelimit(x/time/rate;sharded 256 + 每分片定容 LRU;纯,无 audit/authn 依赖)
     throttle hook: 注入接口(main 用 audit.Recorder 适配;Gate A→system 链,Gate B→principal)
```
(health /healthz、/readyz 不经拦截器;须确认外层中间件**不**套在它们上,或对其放行。)

---

## 4. 模块设计

### 4.1 `internal/ratelimit`(纯:只依赖 x/time/rate + stdlib)
```go
type Limiter interface {
    // Allow 报告该 key 此刻是否放行。retryAfter=到下一 token 的建议等待(拒时;不消费 token)。
    // transitioned=本次是否触发"进入被限流态"边沿且已过冷却窗(用于审计一次)。绝不返回 error(fail-open)。
    Allow(key string) (allowed bool, retryAfter time.Duration, transitioned bool)
    Close()
}
```
- `NewMemory(rps float64, burst, maxKeysPerShard int, cooldown time.Duration) *MemoryLimiter`。
- 内部:`shards [256]struct{ mu sync.Mutex; lru *lruCache }`;`shard = fnv32(key)%256`;`lruCache` 定容(`maxKeysPerShard`),满则驱逐最旧,value=`entry{lim *rate.Limiter, wasLimited bool, lastEmit time.Time}`。**所有** `entry` 读改写 + `lim.Allow()` + `wasLimited`/`lastEmit` 更新在**同一分片锁内**(R9 竞争安全)。
- `Allow`:锁分片→取/建 entry→`ok := entry.lim.Allow()`→拒时 `res:=entry.lim.Reserve(); retryAfter=res.Delay(); res.Cancel()`(R3,不消费);`transitioned = !entry.wasLimited && !ok && now-entry.lastEmit>cooldown`,若 transitioned 则 `entry.lastEmit=now`;`entry.wasLimited = !ok`;放行清 `wasLimited`。**`now` 由调用方传入或用注入时钟**(测试可控;`x/time/rate` 内部用 time.Now,测试用 `rate.Limiter` 的 `AllowN(t, 1)` 变体注入时间)。
- `Close()` 停任何后台;LRU 定容替代了独立驱逐 goroutine(无长尾 map 增长,故可不要 evictor;若保留 evictor 须 `Close()` 可停,R-minor M4)。
- `AllowAll{}`:`Allow` 恒 `(true,0,false)`(杀开关/门关时用,避免 nil 判散落)。

### 4.2 Gate A —— 外层 HTTP 中间件(**中间件放 `internal/server`,共享 `CheckRoot` 裸函数放 `internal/authn`**;`server→authn` 单向无环)
- `func RateLimitMiddleware(next http.Handler, cfg GateAConfig) http.Handler`,`GateAConfig{ IPLim, GlobalLim Limiter; TrustedProxies []*net.IPNet; CheckRoot func(http.Header)(present,valid bool); OnThrottle ThrottleHook }`。
- 逻辑:① **health 放行**见下(先判,免落限流)。② `present, valid := CheckRoot(r.Header)`;`if present && !valid { OnThrottle(root.auth denied,去抖) }`(R12,只此一处发);`if present && valid { next.ServeHTTP; return }`(break-glass 跳 Gate A)。③ `ip := clientIP(r, TrustedProxies)`(R14);`if a,ra,tr := GlobalLim.Allow("global"); !a { reject(...) }`;`if a,ra,tr := IPLim.Allow("ip:"+ipKey(ip)); !a { reject(...) }`(ipKey=v6/64、v4/32 前缀);放行 `next.ServeHTTP`。
- `reject`:`w.Header().Set("Retry-After", strconv.Itoa(ceilSec(ra)))`;`w.WriteHeader(429)`;若 `tr` 调 `OnThrottle`(best-effort,不阻塞)。
- `clientIP`:解析 `RemoteAddr`(带 port、IPv6)稳健;RemoteAddr∈TrustedProxies 时取 XFF 最左、strip 空格、校验是合法 IP,失败回落 RemoteAddr;**绝不 panic**(R-minor M3)。
- **health 放行(精确)**:仅 `/healthz`(纯静态、不打后端)对**所有**桶放行。**`/readyz` 不对全局桶豁免** —— 二审发现:`/readyz` 的 ready 闭包每击都 `pool.Ping`(Postgres)+ `keycloakReachable`(Keycloak 往返),正是 Gate A 要挡的认证前 DB/上游放大;豁免它 = 亲手重开洞。`/readyz` 仍过全局桶 + per-IP 桶(廉价、只挡洪水);或(可选)让 readiness 缓存结果不每击真打后端。§7 加"洪水 /readyz 不放大 DB/Keycloak"断言。

### 4.3 Gate B —— Connect 拦截器(改 `internal/authn/interceptor.go`)
- `Interceptor(...)` 增依赖:`prLimiter Limiter`、`onThrottle ThrottleHook`。nil ⇒ 门关。
- `WrapUnary`:① `_, valid := CheckRoot(header)`;valid → `Caller{SystemAdmin,AuthMethod:root}`,跳 Gate B、跳 ReadOnly(root 全权),next(**拦截器不发 root.auth;那由中间件唯一发**,R12)。② `authenticate`(内部 root 分支**改为复用 `CheckRoot`**——单一真相,R7,不再各判各的)。③ Gate B:`a,ra,tr := prLimiter.Allow("pr:"+caller.PrincipalID)`;`!a` → `err := connect.NewError(CodeResourceExhausted,...)`;`err.Meta().Set("Retry-After", ...)`(R8 best-effort);`tr` → onThrottle(gate=principal, principalID, authMethod);return err。④ ReadOnly 门(不变)。⑤ next。
- `ThrottleHook`(**定义在 authn,避免 authn→audit 环**):`type ThrottleEvent struct{ Gate, Key, IPPrefix, PrincipalID, AuthMethod, Reason string }; type ThrottleHook func(ctx context.Context, ev ThrottleEvent)`。

### 4.4 apikey.auth + root.auth 遥测(R11/R12)
- `apikey.Verifier` 加 `rec audit.Recorder` + 一个未知-keyid 采样器。`Verify` 失败分级:
  - **已知-keyid 类**(解析出 DB 内存在的 keyid、但 hash 不符/已吊销/已过期)——DB 内有界、是真攻击信号,**每次全保真**发 `apikey.auth` denied(detail{reason, keyid 前缀}、非密)。
  - **未知-keyid 类**(keyid 不在 DB)——**攻击者可控的高基数**,**强制"单个原子聚合计数器 + 周期 flush"**:`atomic.AddInt64(&unknownCount,1)`,后台每 T(如 10s)若 count>0 发一条 `apikey.auth` denied detail{reason:"unknown", count:N} 并清零。**禁止 per-keyid-前缀 map/冷却**(二审:那是攻击者可撑爆的无界 map,采样器自己成 DoS 面)。计数器 atomic、flush goroutine 用注入时钟且 `Close()` 可停(测试 -race)。
  - secret 段解析后即弃,绝不入任何 detail。成功认证不发。
- root.auth(R12):**只在 Gate A 中间件、且 `present && !valid` 时**去抖发 `root.auth` denied(单一发射层,拦截器不重发)。**authn/server 不能 import audit**,故经注入 hook 由 main 适配成 recorder 调用。

### 4.5 装配(改 `cmd/base-servers/main.go` + `internal/config` + `deploy/Caddyfile`)
- config:R13 全部 env。
- main:构造 `ipLim/globalLim/prLim`(ENABLED=false 则全用 `AllowAll{}`);解析 `TRUSTED_PROXY_CIDRS`;`authn.CheckRoot`(带 R7 两道护栏,拦截器与中间件同一函数);`throttleHook := func(ctx,ev){ auditRec.Record(map ev→audit.Event) }`(Gate=global/ip 或 root.auth→system 链 `OrgID=""`、不调 CallerFromContext;Gate=principal→`ActorID=ev.PrincipalID`);`server.New(...)` 外包 `RateLimitMiddleware`;拦截器传 prLim+hook;`apikey.NewVerifier(store,hasher,auditRec)`(采样器在 Verifier 内部,`Close()` 交 main 的 shutdown)。
- **deploy/Caddyfile**:配置 reverse_proxy 设/覆盖 `X-Forwarded-For` 为真实客户端(Caddy 默认即追加),并确保 base-servers 容器视 Caddy 为可信(compose 网关 IP ∈ 默认 `TRUSTED_PROXY_CIDRS`)。文档说明裸部署(无网关)默认用 peer。

---

## 5. 数据/接口增量
- **新包** `internal/ratelimit`(接口 + sharded-LRU 内存实现)。
- **新依赖** `golang.org/x/time/rate`(准标准库)。
- **无新表、无新 proto、无新 RPC**。
- **新配置**:R13。
- **改动**:新增 Gate A HTTP 中间件(server 装配);`authn.Interceptor` 签名(+prLimiter/+hook)+ Gate B + root 复用 `ValidRootToken`;`apikey.Verifier` 加 recorder+采样器 + apikey.auth 发射;`deploy/Caddyfile`;main 装配;所有 `authn.Interceptor(...)` / `apikey.NewVerifier(...)` 调用点(含 *_test.go)更新。
- **公开路由不变**;health 不受限流(中间件放行)。

---

## 6. 明确不做 / 推后
- **per-AuthMethod 分级预算(Gate B)** —— 需遥测校准,推后(R6)。
- **per-org/租户公平** —— Caller 无 org id;per-principal 是 alpha 够用代理;v1.1。
- **per-procedure / per-(principal,procedure) 限额** —— v1.1。
- **per-delegation / per-agent 调用预算** —— 北极星线索,点名不建。
- **Postgres-共享后端(精确全局)** —— 藏 `Limiter` 接口后,v2。
- **负缓存 / bloom 让未知-keyid miss 变廉价** —— R2 全局桶已封 DB 量;负缓存是优化,v1.1。
- **`rate_limits` 策略表 + 每-subject 覆盖 + 管理 RPC** —— 产品版,YAGNI。
- **完整 `X-RateLimit-*` 三元组** —— 仅 `Retry-After`。

---

## 7. 测试与验收
- **token bucket(纯,时钟可注入)**:burst 内过、超 burst 拒、按 rps 恢复;**拒不消费 token**(连拒 K 次后恢复速率不变——锁 I1);`transitioned` 仅边沿且过冷却窗才 true,冷却窗内再拒不重发(锁 I2);`Allow` 永不 error(R5)。
- **sharded-LRU 有界(-race)**:灌入远超 `maxKeys×256` 个不同 key,内存/entry 数有界(达上限驱逐最旧),并发无 race(锁 I5);达上限的新 key = fail-open 放行(与 R2 全局桶后盾一致)。
- **Gate A 全局桶封 DB 洞(锁 C1)**:构造"多不同 IP 各少量未知-keyid",证明**全局桶**在总量上拒(fake verifier 计 GetByKeyID 次数,证明被全局桶截在阈值内);单 per-IP 桶下同场景会漏(对照)。IPv6 /64 内多地址共桶。
- **Gate A 在 authenticate 前**:超全局/IP 限的请求根本不该到 verifier(fake verifier 若被调即 fail)。
- **信任代理 IP(锁 C2/R14)**:RemoteAddr∈可信网段→按 XFF 最左分桶;∉→用 peer(伪造 XFF 无效);裸部署(peer=客户端)正确;malformed XFF/RemoteAddr 回落不 panic(M3)。
- **Retry-After 端到端(锁 C3)**:经 bundled Caddy curl,断言 429 响应含真 `Retry-After` 头(Gate A);Gate B 至少回 `CodeResourceExhausted`(Retry-After 头达成则加断言,否则文档记为已知限制)。
- **Gate B per-principal(锁 I6)**:同 principalID 超限 → ResourceExhausted;不同 principal 独立;**同一 principalID 经 oidc 与 apikey 两路共用一个桶(无 2× 双花)**。
- **root 豁免 & 单一真相 & 出厂安全(锁 I7 + 二审 Critical)**:有效 root 超任何量不被限(跳两门);**无效/伪造 X-BS-Root-Token 不跳 Gate A**(落限流);**`BS_ROOT_TOKEN` 未配置(空)时,不带 header 的普通请求 `CheckRoot` 返回 (present=false,valid=false) → 不跳 Gate A**(证明空 token 不致限流器出厂空转);拦截器与中间件用同一 `authn.CheckRoot`(改一处两处同变)。
- **/readyz 不放大(二审发现3)**:洪水打 `/readyz` 被 Gate A 全局桶/per-IP 桶挡住(证明超限的 /readyz 请求不再触达 `pool.Ping`/`keycloakReachable`);`/healthz` 纯静态放行不受限。
- **root.auth 遥测(R12)**:`present && !valid`(带错 token)去抖发一条 denied;**不带 header 的正常请求不发**(证明不淹);中间件发、拦截器不重发(单条)。
- **审计边沿+去抖+租户(锁 I2/I4/R10)**:同 key 稳态过载,`ratelimit.throttled` 每冷却窗 ≤1 条(FakeRecorder-hook 断言);Gate A 事件走 system 链(OrgID="")、Actor 空、detail 记 IP **前缀**非全址、不调 CallerFromContext;Gate B 记 principalID。
- **apikey.auth 分级(锁 I3/R11)**:已知-keyid 失败(mismatch/revoked/expired)每条发、detail 无 secret;未知-keyid 洪水下走**单原子计数器 + 周期 flush**(发聚合 count、非每 miss 一条、无 per-prefix map)、不淹缓冲(注入满缓冲证明丢弃不阻塞);采样器 `Close()` 可停、-race 干净;成功不发。
- **杀开关**:`ENABLED=false` → 两门全放行(AllowAll)。
- **既有全绿**:改 `Interceptor`/`NewVerifier` 签名后 authn/apikey/各 handler 测试仍通过;health 不被限流。
- 全量 `go test ./...`(真 Keycloak+Postgres);`internal/ratelimit -race`。提交署名 Silas、无 cc trailer;精确 `git add`。

---

## 8. 风险与开放问题
- **达 LRU 上限 = fail-open miss**:极端高基数下新 key 放行——这是刻意的(限流器绝不 OOM),真后盾是 Gate A **全局桶**(封总量,与基数无关)+ R11 未知-keyid 采样。文档化。
- **每副本 N× 上限**:多副本 + 负载均衡下被盗 key 实测约 N× 配置速率;滥用天花板非计费额度,诚实写明"挡被盗 agent"保证是 N× 那个数。
- **默认 principal 单档预算靠估**:无历史流量,Gate B 默认值是估计。缓解:R11/R12 遥测 + 杀开关 + 可调 env;有真流量后校准(方法分级一并那时上)。
- **XFF 信任错配**:`TRUSTED_PROXY_CIDRS` 设错(把不剥 XFF 的网段列信任)→ 可伪造。默认只含 compose 网关/loopback;文档强调裸暴露端不得列入。
- **Retry-After 经 Connect+Caddy 可达性**:R8 标为实现期 must-verify;不成则降级(Gate B 仅 code)。
- **共享出口 IP/NAT**:多合法客户端共用一 IP 互挤 per-IP 预算;主防线是 Gate B(per-principal)+ 全局桶给足;极端靠 per-org(v1.1)。
- **429/时序信息泄漏(pre-auth)**:未认证即可探到限流存在/阈值。可接受,记之。
