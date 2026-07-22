# base-servers · Ring 1 · 审计(Audit)· 设计文档

- 日期:2026-07-22
- 状态:设计已定稿,待写实现计划
- 范围:Ring 1(信任与安全)的第一个子项目 —— **审计日志(Audit)**
- 前置:Ring 0 全部四阶段(身份 / 组织 / 权限 / agent 委托 + 交付 + OIDC 前门 + 认证门)已在 main
- 仓库:https://github.com/SilasSolivagus/base-servers

---

## 1. 背景与目标

Ring 0 把控制面做齐并关上了认证门,但**发生过什么无迹可查**。对一个卖"安全"的产品,审计是买家问的第一件事,也是那个 agent 控制塔"决策流"的真数据来源。

Ring 0 的原始 spec 曾写"审计 v1 只做引擎发事件、我们透出,不建独立审计子系统"——那是 Ring 0 阶段刻意不做。**Ring 1 的本模块就是那个独立审计子系统**:捕获 → 落库 → 查询 → 验真。

> 定位:一条**只追加、可篡改验证**的审计流,记录"谁在何时对谁做了什么、以及每一次授权放行/拒绝",服务端异步捕获、不拖慢控制面,按租户可查、可验完整性。

### 北极星对齐
- **agent 治理的招牌数据**:每一次 `CheckDelegated` 放行/拒绝进审计 → 控制塔"decision log"有真数据。
- **企业信任信号**:可查询 + 篡改可验的审计,是对外可卖的关键一环。
- **不拖慢控制面**:写入异步 best-effort,审计从不阻塞或失败业务请求。

---

## 2. 核心设计决策(含理由)

| # | 决策 | 选择 | 理由 |
|---|---|---|---|
| A1 | 捕获粒度 | **控制面写操作 + 委托生命周期 + 全部授权决策(放行∪拒绝)** | 最完整的"谁干了什么 + agent 每次决策"叙事,直喂控制塔;量大交给异步写 + 保留策略 |
| A2 | 写入路径 | **异步 best-effort**:入带缓冲 channel,后台 writer 排干;满/错则记日志丢弃,**绝不阻塞/失败请求** | 审计不能拖慢或拖垮控制面;审计丢一条 ≠ 业务失败 |
| A3 | 捕获机制 | **显式埋点**(每语义点 `rec.Record`),非拦截器 | 拦截器只给通用信封,拿不到"放行/拒绝 + 动作 + 资源 + 目标 org";语义在 handler/checker 处才知道 |
| A4 | 防篡改 | **每租户哈希链**(tamper-evident)+ 只追加不可变 | 安全产品差异化;每租户一条链兼顾隔离与独立验证 |
| A5 | 链 × 异步调和 | 异步 writer **成批排干**,一次拿该租户 `pg_advisory_xact_lock`,按序算 `prev_hash`/`hash`,单事务插入 | per-chain 串行保证链正确,异步+批量保证不阻塞、跨副本一致 |
| A6 | 租户边界 | 查询按 org 绑定(只看自己 org;system-admin 看全部/系统链);无 org 的系统事件走 **"system" 链** | 复用 Ring 0 认证门 + `RequireMember`/`RequireSystemAdmin` |
| A7 | 脱敏 | `detail` 走**白名单**,永不记令牌 / KEK / root token / client secret / DPoP proof | 审计自己不能成为泄密面 |
| A8 | 保留期 | **v1 只追加不删**(alpha 够用);带签名 checkpoint 的保留期裁剪留 v1.1 | 删旧记录会截断哈希链;v1 先保完整性,量的问题文档化 |

---

## 3. 架构

```
        Connect RPC handlers / delegation checker
        (principal·org·role·authz·delegation 语义点)
                        │ rec.Record(ctx, Event{...})  ← 显式埋点,非阻塞
                        ▼
        ┌───────────────────────────────────────────┐
        │ internal/audit                              │
        │  Recorder  —— 带缓冲 channel,best-effort    │
        │     │ (后台 writer 排干,成批)               │
        │     ▼                                        │
        │  Store —— 每租户哈希链 + 只追加插入          │
        │     · pg_advisory_xact_lock(chain)          │
        │     · read head → prev_hash → hash → INSERT │
        │  AuditService —— List(filter) / Verify(org) │
        └───────────────────┬─────────────────────────┘
                            ▼
                     ┌──────────────┐
                     │ audit_events  │  只追加(DB grant: INSERT/SELECT)
                     └──────────────┘
```

---

## 4. 模块设计

### 4.1 事件与 Recorder
- **Event**:`ActorID string · ActorType(human/service/agent/system) · SystemAdmin bool · Action string · TargetType/TargetID string · OrgID string(空=system 链) · Outcome(success|denied|error) · Detail map[string]any`。
- **Action** 用稳定语义动词:`principal.create`、`org.create`、`org.member.add`、`team.member.add`、`role.create`、`role.assign`、`ownership.register`、`delegation.issue`、`delegation.revoke`、`authz.decision`(带 detail.allowed)。
- **actor 来自 ctx**:`authn.CallerFromContext` → ActorID=Caller.PrincipalID(或 system);SystemAdmin 从 Caller。
- **Recorder**:`Record(ctx, Event)` 只做:补全 actor/ts → 塞进带缓冲 channel(如 4096);满则**丢弃并计数 + 记日志**,立即返回(永不阻塞)。后台单 goroutine `run()` 排干:按 OrgID 分组成批,交给 Store。进程退出时 flush 尽力排干。

### 4.2 哈希链 Store(每租户)
- 每条记录:`seq`(该链自增)、`prev_hash`、`hash = SHA256(canonical(seq,ts,actor,action,target,outcome,detail,org_id) ‖ prev_hash)`。
- 插入一批(同一 chain=org_id,或 "system"):
  1. `SELECT pg_advisory_xact_lock(hashtext('audit:'||chain))`(串行化该链写入,跨副本一致)。
  2. 读链头 `(seq,hash)`(无则 seq=0, prev_hash=创世常量)。
  3. 按序对每条算 seq+1、prev_hash、hash,`INSERT`。
  4. commit(释放锁)。
- `Verify(ctx, chain) (ok bool, brokenAtSeq int64, err error)`:按 seq 顺序读全链,重算每条 hash 并比对 prev 链接;第一处不符即 tamper。

### 4.3 存储
- `audit_events`:`chain TEXT(=org_id 或 'system')`、`seq BIGINT`、`ts TIMESTAMPTZ`、`actor_id/actor_type TEXT`、`system_admin BOOL`、`action TEXT`、`target_type/target_id TEXT`、`org_id TEXT`、`outcome TEXT`、`detail JSONB`、`prev_hash/hash BYTEA`;PK `(chain, seq)`;索引 `(org_id, ts DESC)`、`(actor_id)`、`(action)`。
- **不可变(强制层)**:迁移 `0006` 在 `audit_events` 上装 `BEFORE UPDATE/DELETE`(行级)+ `BEFORE TRUNCATE`(语句级)触发器,任何改/删/清空一律 `RAISE EXCEPTION`。**与角色无关**——连 owner/superuser `base` 也挡(`REVOKE` 挡不住 superuser,触发器能)。唯一绕过是 superuser 显式 `SET session_replication_role=replica`(或 `DISABLE TRIGGER`),那正是"拿到 superuser 的越权攻击者",由 4.2 哈希链 `Verify` 兜底检出。0005 的 `REVOKE UPDATE, DELETE FROM PUBLIC` 保留为额外一层。应用侧亦无改/删 RPC(sqlc 只生成 Insert/Select)。

### 4.4 查询 / 验真 API
- `AuditService.List(ListRequest{org_id, actor_id, action, outcome, from, to, page_size, page_token}) → {events[], next_page_token}`:授权——普通 caller 必须是 `org_id` 成员(`RequireMember`),system-admin 可查任意 org 及 "system" 链;结果按 ts 倒序、游标分页。
- `AuditService.Verify(VerifyRequest{org_id}) → {ok, broken_at_seq}`:同样授权;跑 4.2 的链校验。
- 两者都在认证门后(Ring 0 拦截器);handler 侧做 authz。

### 4.5 装配
- `cmd/base-servers/main.go`:构造 `audit.NewRecorder(store)`,`go recorder.Run(ctx)`;注入各 handler/service 与 delegation checker;`server.New` 加 `AuditService` handler。
- 迁移 `0005_audit_events.sql`;sqlc 加 audit 块。

---

## 5. 数据/接口增量

- **新表** `audit_events`(见 4.3),含创世链锚。
- **新 proto** `proto/baseservers/v1/audit.proto`:`AuditService{List, Verify}` + 消息。
- **新配置**:无必填新增(保留期 v1 不做)。可选 `AUDIT_BUFFER`(默认 4096)。
- **改动**:各 mutating handler + delegation `Issue`/`Revoke` + `CheckDelegated`/`authz.Check` 加一行 `rec.Record(...)`;`NewHandler`/`NewService`/`NewChecker` 注入 `audit.Recorder`(接口,便于测试用 fake/nil-op)。
- **公开路由不变**;审计查询 RPC 走认证门。

---

## 6. 明确不做 / 推后

- **保留期裁剪 + 签名 checkpoint**(删旧记录同时保链可验)—— v1.1。
- 全局(跨租户)单链、外部 WORM/对象存储归档、导出到 SIEM(Splunk/ELK)—— 后续。
- 实时告警 / 订阅审计流(webhook)—— Ring 2(触达)范畴。
- 控制台 UI 的审计页 —— 横切(Admin 控制台),本模块只出 API + 真数据。
- 拦截器式通用信封审计(与显式埋点二选一,已选显式)。

---

## 7. 测试与验收

- **捕获**:每类语义点产生一条正确 Event(actor/action/target/outcome 对);`authz.decision` 的 detail.allowed 正确区分放行/拒绝。
- **异步不阻塞**:`Record` 在 O(微秒)返回;缓冲打满时丢弃并计数,请求不受影响、不报错(压测/注入满缓冲)。
- **哈希链正确**:并发多写(多 goroutine、模拟两副本共库)后,每租户链 seq 连续、`Verify` 通过。
- **篡改可验**:superuser 绕过 append-only 触发器(`SET session_replication_role=replica`)直改一条 detail → `Verify` 返回 `ok=false` 且 `broken_at_seq` 指向该条(`TestVerifyDetectsTamper`)。
- **不可变**:普通 UPDATE/DELETE 一律被 append-only 触发器拒绝,与角色/权限无关(连 owner `base` 也挡),行仍在、链仍可验(`TestAuditEventsRejectsMutation`)。
- **租户绑定**:A 租户成员 `List(org=B)` → `PermissionDenied`;system-admin 可查任意 org 与 "system"。
- **脱敏**:构造带令牌/secret 的操作,审计 detail 里**查不到**这些值。
- 全程对**真 Postgres 容器**跑;delegation/authz 决策审计对真 Keycloak+Postgres 跑。
- 提交署名 Silas、无 Co-Authored-By/Claude trailer;精确 `git add`。

---

## 8. 风险与开放问题

- **链 × 高频决策的写入吞吐**:per-chain advisory 锁在单租户高频决策下是吞吐上限;缓解=异步缓冲 + 成批(一次锁插一批)。若某租户 agent 决策量极高,批量窗口/多分片链留作后续优化(可把 chain 拆成 `org_id:shard`,验真按 shard,牺牲单链全序)。
- **链 × 保留期**:删旧记录截断链;v1 只追加不删,量的增长文档化为运维约束,v1.1 上 checkpoint 裁剪。
- **best-effort 丢数据**:极端过载下审计可能丢条(有计数、有日志)。这是"审计不拖垮业务"的自觉取舍;若某类事件必须零丢失(如 revoke),可对该类走同步小路——v1 统一异步,零丢失需求出现再分级。
- **创世/多副本首写竞态**:空链首插由 advisory 锁 + `(chain,seq)` 唯一约束兜底(并发首插一方 seq 冲突则重试)。
- **detail 白名单维护**:新增字段默认不入 detail,显式加白;评审须盯住不让 secret 混入。
- **DB 层不可变 — 已由触发器强制(2026-07-22 落地)**:迁移 `0006` 的 append-only 触发器让任何 UPDATE/DELETE/TRUNCATE 直接 `RAISE EXCEPTION`,**不依赖角色**,连 owner/superuser `base` 都挡(`TestAuditEventsRejectsMutation` 断言普通改删被拒且链仍可验)。三层防御:(a) 触发器(强制,role-independent);(b) 应用层无 UPDATE/DELETE 审计路径(sqlc 只生成 Insert/Select);(c) 哈希链 `Verify` 兜底 superuser 绕过触发器(`SET session_replication_role=replica`)的极端攻击者(`TestVerifyDetectsTamper` 即以此路径模拟)。
- **跟进项(排进 Ring 1)· 最小权限运行时 DB 角色**:引入非-owner `base_app` 角色(全表 DML,但 audit_events 无 UPDATE/DELETE),迁移以 owner 跑、serve 以受限角色跑(第二个 `DATABASE_URL` + main.go 双连接池)。收益是把**整库**爆炸半径收窄(app 连 DROP/ALTER 任何表都不行),超出审计不可变本身——审计不可变已由触发器达成,故此项作为独立安全硬化工作单列,非本模块阻塞项。
