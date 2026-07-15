# Investigation Grants Repository Policy and Workflow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 实现 Snapshot 实时解析、Grant 签发/撤销、六级 Kill Switch、事件/定时/人工主动策略，以及统一、可重放的 Temporal 编排。

**Architecture:** PostgreSQL 在同一事务中重新验证 Asset/Connection/Capability/Runtime/Realm 并写 Snapshot、Grant、Policy 与 Run；Outbox 和 Temporal 只携带 ID/摘要，Schedule 每次发生都产生新的 Run，SHADOW 仅形成审计闭环而不访问目标。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、pgx/v5、go-chi/v5、Temporal Go SDK 1.46.0、OpenTelemetry Metric 1.39.0、JCS/SHA-256；Node >=24 <25、pnpm 10.34.0、React 19.2.7、Vite 8.1.4、TypeScript 7.0.2、TanStack Router 1.170.17、Query 5.101.2、Table 8.21.3、React Hook Form 7.81.0、Zod 4.4.3、radix-ui 1.6.2、lucide-react 1.24.0、CSS Modules；openapi-typescript 7.13.0、Vitest 4.1.10、Testing Library 16.3.2、MSW 2.15.0、Playwright 1.61.1、@axe-core/playwright 4.12.1。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- 实现基线固定为 main@ad50d9f；开始执行时先创建独立 worktree，且该模块根下不能包含嵌套 .worktrees。当前共享主目录会被既有架构唯一调用链测试扫描到用户 worktree，因此不得宣称其 go test ./... 基线全绿，也不得删除用户 worktree。
- 继续使用 Go 模块化单体；本阶段不新建微服务。
- PostgreSQL 是领域事实源，Temporal 只保存编排 ID、摘要和小型脱敏结果。
- 模型不是授权 Principal，不属于可信计算基，不能签发、扩大、复用或转换 Grant。
- 资产目录、浏览器、Task、事件 Payload 和模型都不能向 Runner 提交 endpoint、DSN、Secret、命令、SQL、任意 Header、任意请求体、Target、Credential、Network 或 Runner 选择。
- 只有 ACTIVE + EXACT + PUBLISHED + AVAILABLE 的资产能力可以进入实时调查；STALE、QUARANTINED、AMBIGUOUS、UNRESOLVED 必须 fail closed。
- 每次事件、定时或人工运行都创建新的不可变 Asset Snapshot 和 Grant；运行固定 Asset、Target、Capability、Runtime Bundle、Policy 和 Grant 摘要。
- Grant 只授权 READ，不能转化或复用于 WRITE；ActionPlan 仍需独立 ActionEnvelope、策略、审批和凭据链。
- SHADOW 不访问目标；READ_ONLY 不产生写执行；生产写和现有 READ Admission 均保持关闭，实施本计划不得新增配置开关绕过 Go/No-Go。
- 六级 Kill Switch 固定为 GLOBAL、WORKSPACE、ENVIRONMENT、ASSET、CONNECTION、CAPABILITY；任一级当前修订关闭都阻止新 Claim，并在 Start/Heartbeat/Complete fail closed。
- Runtime/配置更新只影响新 Grant；安全撤销、Kill Switch、资产 STALE/QUARANTINED 和身份漂移属于实时安全门禁，必须终止仍活动的授权。
- 公开 DTO、日志、Trace、Temporal History、Evidence 和审计不得包含 Secret、Token、PEM、完整 DSN、Vault URL/Path、内部 endpoint、原始上游错误、任意 SQL 或完整查询结果。
- 所有公共列表使用不透明 Cursor 与稳定排序；所有写请求要求 Idempotency-Key；发布、状态更新和撤销要求 ETag/If-Match；错误使用 RFC 9457、稳定 code 和 trace_id。
- Grant 撤销、策略发布/启停与 Kill Switch 变更要求 1–15 分钟范围内配置的最近 OIDC 认证，默认 5 分钟。
- 前端沿用唯一 web/ 工程、唯一 api/openapi/control-plane-v1.yaml 和唯一生成文件 web/src/shared/api/schema.d.ts；不引入 Redux，以 URL/Query 保存 Scope、筛选、排序、分页、Tab 和选中对象。
- 前端文案使用“主动调查”“系统调查运行”“Runner 与能力”，不得使用“Agent 已登录服务器”；不得引入聊天框、AI 头像、霓虹、发光或玻璃拟态。
- 前端满足 WCAG 2.2 AA、键盘操作、可见焦点、持久 Label、Reduced Motion 与 44px 触控目标；1440px、1024px、390px 均须验收。
- 生产级事件/定时只读调查是整个 Governed Operations Program 的中间门槛，不是终点；Program 最终必须进入固定类型化 ActionEnvelope、策略、审批、短期凭据、WRITE Runner、执行验证和不可变审计组成的受治理写闭环。
- 本阶段交付真实 PostgreSQL、Temporal、OIDC、mTLS、Runtime Publication 与 Gateway 路径上的可生产实现；fake、MSW、Temporal testsuite 和内存对象只能用于测试，绝不能成为生产装配或失败降级路径。

---

## Package Position

- 顺序：2 / 7；必须按 README.md 固定顺序执行。
- 前置：01-domain-schema.md 全部任务及其 migration 集成测试通过。
- 交付给下一包：可供 Gateway 调用的 Grant/Kill Switch Repository、可供 API 调用的 Policy/Run Service，以及统一 TriggerStarter/SchedulerPublisher。
- 本包内仍按 Task 编号顺序执行；每个 Task 必须先看到预期失败，再写最小实现、跑通过并提交对应 commit。

### Task 3: PostgreSQL Snapshot 解析、Grant 签发与六级 Kill Switch

**Files:**
- Create: internal/investigationgrant/service.go
- Create: internal/investigationgrant/postgres/repository.go
- Create: internal/investigationgrant/postgres/snapshot.go
- Create: internal/investigationgrant/postgres/grants.go
- Create: internal/investigationgrant/postgres/kill_switches.go
- Create: internal/investigationgrant/service_test.go
- Create: internal/investigationgrant/postgres/snapshot_test.go
- Create: internal/investigationgrant/postgres/grants_test.go
- Create: internal/investigationgrant/postgres/repository_integration_test.go

**Interfaces:**
- Consumes: assetcatalog.Repository.Get/List 的 Scope/Asset 安全投影；000016 已发布 Target、Capability Set、Runtime Publication、Runner Realm/Binding；现有 investigations、investigation_task_attempts、evidence、model_calls。
- Produces: Service.Preview(context.Context, PreviewRequest) (Preview, error)；Service.Issue(context.Context, IssueRequest) (IssueResult, error)；Repository.GetGrant/ListGrants/RevokeGrant；Repository.AppendKillSwitchRevision/EffectiveKillSwitches；Repository.AuthorizeBoundaryTx。

- [ ] **Step 1: 写 Snapshot 资格和安全投影失败测试**

在 service_test.go 使用显式 fake SnapshotSource。一次返回两个合格对象和五个排除对象，验证 Preview 只返回稳定 ID、原因码和计数；Issue 必须重新解析，不能信任 Preview 的资产集合。

~~~go
func TestServiceIssueReResolvesAndPinsOnlyEligiblePublishedAssets(t *testing.T) {
    source := &snapshotSourceFake{
        preview: Resolution{
            Eligible: []SnapshotItem{validItem(assetA), validItem(assetB)},
            Excluded: []ExcludedAsset{
                {AssetID: assetStale, ReasonCode: "ASSET_STALE"},
                {AssetID: assetAmbiguous, ReasonCode: "ASSET_MAPPING_NOT_EXACT"},
                {AssetID: assetUnpublished, ReasonCode: "RUNTIME_PUBLICATION_NOT_READY"},
            },
        },
    }
    repository := &grantRepositoryFake{}
    service, err := NewService(source, repository, fixedIDs(), fixedClock())
    if err != nil {
        t.Fatal(err)
    }
    preview, err := service.Preview(context.Background(), validPreviewRequest())
    if err != nil || preview.SelectedCount != 2 || preview.ExcludedCount != 3 {
        t.Fatalf("Preview() = %#v, %v", preview, err)
    }
    source.issue = Resolution{Eligible: []SnapshotItem{validItem(assetB)}}
    issued, err := service.Issue(context.Background(), validIssueRequest())
    if err != nil {
        t.Fatalf("Issue() error = %v", err)
    }
    if len(repository.persistedSnapshot.Items) != 1 || repository.persistedSnapshot.Items[0].AssetID != assetB ||
        issued.Grant.AssetSnapshotDigest != repository.persistedSnapshot.Digest {
        t.Fatalf("Issue() trusted preview or lost digest: %#v", issued)
    }
}
~~~

ExcludedAsset 只能包含 AssetID、ReasonCode；不得包含 endpoint、TargetRef、外部 Payload 或错误正文。

- [ ] **Step 2: 运行测试并确认缺少 Service**

Run: go test ./internal/investigationgrant -run TestServiceIssueReResolvesAndPinsOnlyEligiblePublishedAssets -count=1

Expected: FAIL，错误包含 undefined: NewService 或 undefined: Resolution。

- [ ] **Step 3: 定义窄端口并实现应用服务**

在 service.go 定义以下接口。Issue 调用 Repository.WithIssuanceTransaction，让 Snapshot 重新解析、当前 Kill Switch、Snapshot/Grant 插入处于同一 PostgreSQL 事务；Preview 只能只读，不能返回可在 Issue 中复用的 capability。

~~~go
type AssetSelector struct {
    AssetIDs []string
    AssetKinds []string
    ServiceIDs []string
}

type ResolveRequest struct {
    Scope Scope
    Selector AssetSelector
    CapabilitySetID string
    ExpectedCapabilitySetDigest string
    ExpectedRuntimeBundleDigest string
    Mode string
}

type ExcludedAsset struct {
    AssetID string
    ReasonCode string
}

type Resolution struct {
    Eligible []SnapshotItem
    Excluded []ExcludedAsset
    CapabilitySnapshotDigest string
    RuntimeBundleDigest string
}

type SnapshotSource interface {
    Resolve(context.Context, ResolveRequest) (Resolution, error)
}

type IssueRequest struct {
    Scope Scope
    IncidentID string
    TriggerType TriggerType
    TriggerID string
    Issuer Issuer
    Selector AssetSelector
    CapabilitySetID string
    CapabilitySetDigest string
    RuntimeBundleDigest string
    Classification DataClassification
    Budget Budget
    PolicyRevision int64
    PolicyDigest string
    Mode string
}

type IssuanceRepository interface {
    PersistIssue(context.Context, AssetSnapshot, Grant) error
    CurrentKillSwitchDigest(context.Context, Scope, []SnapshotItem) (string, error)
}

type Service struct {
    source SnapshotSource
    repository IssuanceRepository
    ids func() string
    now func() time.Time
}

func (service *Service) Issue(ctx context.Context, request IssueRequest) (IssueResult, error) {
    resolution, err := service.source.Resolve(ctx, ResolveRequest{
        Scope: request.Scope, Selector: request.Selector,
        CapabilitySetID: request.CapabilitySetID,
        ExpectedCapabilitySetDigest: request.CapabilitySetDigest,
        ExpectedRuntimeBundleDigest: request.RuntimeBundleDigest,
        Mode: request.Mode,
    })
    if err != nil || len(resolution.Eligible) == 0 ||
        resolution.CapabilitySnapshotDigest != request.CapabilitySetDigest ||
        resolution.RuntimeBundleDigest != request.RuntimeBundleDigest {
        return IssueResult{}, ErrAssetIneligible
    }
    now := service.now().UTC()
    snapshot, err := NewAssetSnapshot(request.Scope, service.ids(), resolution.Eligible, now)
    if err != nil {
        return IssueResult{}, err
    }
    killDigest, err := service.repository.CurrentKillSwitchDigest(ctx, request.Scope, snapshot.Items)
    if err != nil {
        return IssueResult{}, err
    }
    grant, err := NewGrant(IssueInput{
        ID: service.ids(), Scope: request.Scope, IncidentID: request.IncidentID,
        TriggerType: request.TriggerType, TriggerID: request.TriggerID, Issuer: request.Issuer,
        Snapshot: snapshot, CapabilitySnapshotDigest: request.CapabilitySetDigest,
        RuntimeBundleDigest: request.RuntimeBundleDigest, Classification: request.Classification,
        Budget: request.Budget, NotBefore: now, ExpiresAt: now.Add(request.Budget.MaxDuration),
        PolicyRevision: request.PolicyRevision, PolicyDigest: request.PolicyDigest,
        KillSwitchDigest: killDigest,
    })
    if err != nil {
        return IssueResult{}, err
    }
    if err := service.repository.PersistIssue(ctx, snapshot, grant); err != nil {
        return IssueResult{}, err
    }
    return IssueResult{Snapshot: snapshot, Grant: grant, Excluded: resolution.Excluded}, nil
}
~~~

生产 PostgreSQL Repository 的 PersistIssue 必须自己在 REPEATABLE READ 事务内再次执行 ResolveEligibleTx 和 CurrentKillSwitchDigestTx，然后比较完整 Snapshot/Grant digest 后插入；上面的应用层重解析是第一道检查，不得替代事务内 TOCTOU 防御。

- [ ] **Step 4: 写 PostgreSQL 解析查询与负向单元测试**

snapshot.go 使用一条受作用域约束的查询从资产、Service Binding、Connection Revision、Published Target、Capability Set/Items、Runtime Publication、Realm Binding 得到候选。JOIN/WHERE 必须同时包含以下谓词，测试用 pgxmock 精确匹配每个谓词：

~~~sql
JOIN connection_revisions connection
  ON (connection.tenant_id, connection.workspace_id, connection.environment_id, connection.asset_id) =
     (asset.tenant_id, asset.workspace_id, asset.environment_id, asset.id)
JOIN published_targets target
  ON (target.tenant_id, target.workspace_id, target.environment_id,
      target.connection_id, target.connection_revision) =
     (connection.tenant_id, connection.workspace_id, connection.environment_id,
      connection.connection_id, connection.revision)
JOIN published_capability_sets capability_set
  ON (capability_set.tenant_id, capability_set.workspace_id, capability_set.environment_id,
      capability_set.connection_id, capability_set.connection_revision) =
     (connection.tenant_id, connection.workspace_id, connection.environment_id,
      connection.connection_id, connection.revision)
JOIN published_capability_set_items capability_item
  ON (capability_item.tenant_id, capability_item.workspace_id,
      capability_item.environment_id, capability_item.capability_set_id) =
     (capability_set.tenant_id, capability_set.workspace_id,
      capability_set.environment_id, capability_set.id)
JOIN capability_definitions capability
  ON (capability.tenant_id, capability.workspace_id, capability.environment_id,
      capability.id, capability.revision) =
     (capability_item.tenant_id, capability_item.workspace_id,
      capability_item.environment_id, capability_item.capability_id,
      capability_item.capability_revision)
JOIN runtime_publications runtime
  ON (runtime.tenant_id, runtime.workspace_id, runtime.environment_id,
      runtime.connection_id, runtime.connection_revision,
      runtime.published_target_id, runtime.capability_set_id) =
     (connection.tenant_id, connection.workspace_id, connection.environment_id,
      connection.connection_id, connection.revision, target.id, capability_set.id)
JOIN runner_realms realm
  ON (realm.tenant_id, realm.workspace_id, realm.environment_id, realm.id) =
     (connection.tenant_id, connection.workspace_id, connection.environment_id,
      connection.runner_realm_id)
JOIN runner_capability_bindings realm_binding
  ON (realm_binding.tenant_id, realm_binding.workspace_id, realm_binding.environment_id,
      realm_binding.realm_id, realm_binding.provider_kind, realm_binding.capability_kind) =
     (realm.tenant_id, realm.workspace_id, realm.environment_id,
      realm.id, capability.provider_kind, capability.capability_kind)
WHERE asset.tenant_id = $1
  AND asset.workspace_id = $2
  AND asset.environment_id = $3
  AND asset.lifecycle = 'ACTIVE'
  AND asset.mapping_status = 'EXACT'
  AND connection.status = 'PUBLISHED'
  AND target.status = 'PUBLISHED'
  AND capability_set.status = 'PUBLISHED'
  AND capability_item.mode = 'AVAILABLE'
  AND capability.status = 'AVAILABLE'
  AND runtime.status = 'APPLIED'
  AND runtime.bundle_digest = $4
  AND realm.mode = 'READ'
  AND realm.enabled = true
  AND realm_binding.status = 'AVAILABLE'
ORDER BY asset.id, target.target_digest, capability_set.set_digest,
         capability_item.position, realm_binding.revision DESC
FOR SHARE OF asset, connection, target, capability_set, runtime, realm, realm_binding
~~~

pgxmock 与 PostgreSQL 集成测试都必须证明删除 capability item 或 definition 任意一个 Tenant/Workspace/Environment join predicate 会失败；不能依赖 UUID 全局唯一。每个 Capability 只取 Realm Binding 最新 revision；同一 Asset/Target/Capability 出现多个当前 Realm binding 或多个 APPLIED Runtime 必须拒绝，不能随意选一条。聚合后的 SnapshotItem 写入 capability_set.id/set_digest、runtime.id/bundle_digest 和 realm.id。Selector 只能变成 asset.id = ANY、asset.kind = ANY、binding.service_id = ANY 三类参数化谓词；空数组表示该维度不筛选。不得拼 SQL、排序字段或 Provider 名。

- [ ] **Step 5: 实现 Grant 仓储、Cursor 与状态变更**

repository.go 的 DB 最小接口固定为 BeginTx(context.Context, pgx.TxOptions)；Get/List 使用 READ ONLY 事务并在扫描后调用领域 Validate。List 默认 50、上限 100，按 created_at DESC, id DESC keyset；Cursor wire 为 v1、RFC3339Nano、UUID，经 base64url 编码。

~~~go
type Repository interface {
    PersistIssue(context.Context, AssetSnapshot, Grant) error
    GetGrant(context.Context, Scope, string) (Grant, error)
    ListGrants(context.Context, ListRequest) (Page, error)
    ActivateGrant(context.Context, Scope, string, int64) (Grant, error)
    CompleteGrant(context.Context, Scope, string, int64) (Grant, error)
    RevokeGrant(context.Context, RevokeRequest) (Grant, error)
    AppendKillSwitchRevision(context.Context, KillSwitchRevision) (KillSwitchRevision, error)
    EffectiveKillSwitches(context.Context, KillSwitchRequest) (EffectiveKillSwitchSet, error)
}

type RevokeRequest struct {
    Scope Scope
    GrantID string
    ExpectedVersion int64
    Reason string
    ActorSubject string
    IdempotencyKey string
}
~~~

每次状态变更在同一事务追加 audit_records 和 outbox_events；Payload 只含 grant_id、version、status、grant_digest。相同 Idempotency-Key 与相同请求返回原结果，不同请求返回 store.ErrIdempotencyConflict。

- [ ] **Step 6: 实现六级实时 Kill Switch 解析**

kill_switches.go 对每个 level 使用 DISTINCT ON 或 row_number 取得最新 revision；GLOBAL 是 Tenant 级，WORKSPACE/ENVIRONMENT 使用 Scope，ASSET/CONNECTION/CAPABILITY 来自已固定 Snapshot Items。当前任一 closed 即返回 ErrKillSwitchClosed；六级当前修订按 level+subject 排序后 JCS 生成 effective digest。Grant 内保存的旧 digest只用于审计，不得阻止新修订立即生效。

~~~go
type KillSwitchLevel string

const (
    KillGlobal KillSwitchLevel = "GLOBAL"
    KillWorkspace KillSwitchLevel = "WORKSPACE"
    KillEnvironment KillSwitchLevel = "ENVIRONMENT"
    KillAsset KillSwitchLevel = "ASSET"
    KillConnection KillSwitchLevel = "CONNECTION"
    KillCapability KillSwitchLevel = "CAPABILITY"
)

type EffectiveKillSwitch struct {
    Level KillSwitchLevel
    SubjectID string
    Revision int64
    Closed bool
    Digest string
}

type EffectiveKillSwitchSet struct {
    Items []EffectiveKillSwitch
    Digest string
}
~~~

关闭后不得通过重新打开使 REVOKED/EXPIRED Grant 恢复；打开只影响下一次边界判断和新 Grant。

- [ ] **Step 7: 运行 PostgreSQL 单元与集成测试**

Run: go test -race -shuffle=on -count=1 ./internal/investigationgrant ./internal/investigationgrant/postgres

Expected: PASS。

Run: AIOPS_TEST_POSTGRES_DSN='postgres://aiops:password@127.0.0.1:5432/aiops_test?sslmode=disable' go test -race -count=1 ./internal/investigationgrant/postgres -run 'TestRepository'

Expected: PASS，并证明跨 Scope 返回与未知 ID 相同的 store.ErrNotFound。

- [ ] **Step 8: 提交 Snapshot/Grant 仓储**

~~~bash
git add internal/investigationgrant
git commit -m "feat: persist bounded investigation grants"
~~~

### Task 4: 主动策略领域、Preview、发布和运行持久化

**Files:**
- Create: internal/proactivepolicy/types.go
- Create: internal/proactivepolicy/canonical.go
- Create: internal/proactivepolicy/service.go
- Create: internal/proactivepolicy/postgres/repository.go
- Create: internal/proactivepolicy/postgres/policies.go
- Create: internal/proactivepolicy/postgres/runs.go
- Create: internal/proactivepolicy/types_test.go
- Create: internal/proactivepolicy/service_test.go
- Create: internal/proactivepolicy/postgres/repository_test.go
- Create: internal/proactivepolicy/postgres/repository_integration_test.go

**Interfaces:**
- Consumes: investigationgrant.Service.Preview/Issue；investigation.Repository.CreateOrGetInvestigation；000016 Capability/Runtime 发布安全投影；store.OutboxRepository 写模型。
- Produces: Service.CreateRevision、PreviewRevision、PublishRevision、Disable、RequestRun、PrepareRun；Repository.Get/List Policy、Get/List Run；PolicyRevision、ProactiveRun 安全领域类型。

- [ ] **Step 1: 写策略触发、模式和状态机失败测试**

~~~go
func TestPolicyRevisionAcceptsOnlyFixedIncidentOrBoundedSchedule(t *testing.T) {
    incident := validDraft()
    incident.Trigger = Trigger{Type: TriggerIncident, EventType: "incident.created.v1"}
    if err := incident.Validate(); err != nil {
        t.Fatalf("incident policy error = %v", err)
    }
    schedule := validDraft()
    schedule.Trigger = Trigger{Type: TriggerSchedule, ScheduleExpression: "*/15 * * * *"}
    if err := schedule.Validate(); err != nil {
        t.Fatalf("schedule policy error = %v", err)
    }
    for _, invalid := range []Trigger{
        {Type: TriggerIncident, EventType: "signal.ingested.v1"},
        {Type: TriggerSchedule, ScheduleExpression: "* * * * *"},
        {Type: TriggerSchedule, ScheduleExpression: "@every 1s"},
        {Type: TriggerSchedule, ScheduleExpression: "0 0 * * *", EventType: "incident.created.v1"},
    } {
        candidate := validDraft()
        candidate.Trigger = invalid
        if err := candidate.Validate(); !errors.Is(err, ErrInvalidPolicy) {
            t.Fatalf("Validate(%#v) error = %v", invalid, err)
        }
    }
}

func TestPolicyTransitionRequiresNewRevisionToReenable(t *testing.T) {
    tests := []struct{ from, to Status; allowed bool }{
        {StatusDraft, StatusShadow, true},
        {StatusDraft, StatusReadOnly, true},
        {StatusShadow, StatusReadOnly, false},
        {StatusReadOnly, StatusDisabled, true},
        {StatusDisabled, StatusReadOnly, false},
        {StatusSuperseded, StatusShadow, false},
    }
    for _, test := range tests {
        if got := CanTransition(test.from, test.to); got != test.allowed {
            t.Fatalf("CanTransition(%s,%s) = %t", test.from, test.to, got)
        }
    }
}
~~~

- [ ] **Step 2: 运行测试并确认缺少类型**

Run: go test ./internal/proactivepolicy -run 'TestPolicy' -count=1

Expected: FAIL，错误包含 package 不存在或 undefined: PolicyRevision。

- [ ] **Step 3: 实现严格策略和运行领域类型**

~~~go
type Mode string
type Status string
type RunStatus string
type TriggerType string

const (
    ModeShadow Mode = "SHADOW"
    ModeReadOnly Mode = "READ_ONLY"
    StatusDraft Status = "DRAFT"
    StatusShadow Status = "SHADOW"
    StatusReadOnly Status = "READ_ONLY"
    StatusDisabled Status = "DISABLED"
    StatusSuperseded Status = "SUPERSEDED"
    RunQueued RunStatus = "QUEUED"
    RunResolving RunStatus = "RESOLVING"
    RunGranted RunStatus = "GRANTED"
    RunRunning RunStatus = "RUNNING"
    RunPartial RunStatus = "PARTIAL"
    RunCompleted RunStatus = "COMPLETED"
    RunFailed RunStatus = "FAILED"
    RunStopped RunStatus = "STOPPED"
    TriggerIncident TriggerType = "INCIDENT"
    TriggerSchedule TriggerType = "SCHEDULE"
    TriggerManual TriggerType = "MANUAL"
)

type Trigger struct {
    Type TriggerType
    EventType string
    ScheduleExpression string
}

type PolicyRevision struct {
    Scope investigationgrant.Scope
    PolicyID string
    Revision int64
    ServiceID string
    Name string
    Trigger Trigger
    Selector investigationgrant.AssetSelector
    CapabilitySetID string
    CapabilitySetDigest string
    RuntimeBundleDigest string
    Classification investigationgrant.DataClassification
    Mode Mode
    Status Status
    MinInterval time.Duration
    Budget investigationgrant.Budget
    Digest string
    Version int64
    CreatedBy string
    PublishedBy string
    CreatedAt time.Time
    PublishedAt time.Time
    UpdatedAt time.Time
}

type ProactiveRun struct {
    Scope investigationgrant.Scope
    ID string
    PolicyID string
    PolicyRevision int64
    PolicyDigest string
    Mode Mode
    TriggerType string
    TriggerID string
    TriggerDedupKey string
    AssetSnapshotID string
    GrantID string
    InvestigationID string
    Status RunStatus
    Version int64
    SelectedAssetCount int
    ExcludedAssetCount int
    FailureCode string
    CreatedAt time.Time
    StartedAt time.Time
    CompletedAt time.Time
    UpdatedAt time.Time
}
~~~

ScheduleExpression 仅接受 */5 * * * *、*/15 * * * *、0 * * * *、M H * * * 四种 UTC 五段表达式；拒绝秒级、别名、范围、列表和时区注入。MinInterval 固定 5 分钟–24 小时。Policy digest 覆盖所有内容字段，不覆盖状态、版本和发布 Actor。

- [ ] **Step 4: 写应用服务测试**

测试以下完整流程：CreateRevision 生成 DRAFT；Preview 总是调用 Grant Preview；Publish 要求 Preview digest 与当前解析一致、把旧活动 Revision 原子置 SUPERSEDED；Disable 使用 If-Match version；RequestRun 以 policy digest+trigger type+trigger ID 生成 dedup hash；PrepareRun 在 SHADOW 创建 Snapshot/Grant 但不创建 Investigation，在 READ_ONLY 创建并绑定普通 Investigation。

~~~go
func TestPrepareRunKeepsShadowAwayFromInvestigationCreator(t *testing.T) {
    grants := &grantServiceFake{issue: validIssuedGrant()}
    investigations := &investigationCreatorFake{}
    repository := &repositoryFake{policy: publishedPolicy(ModeShadow), run: queuedRun()}
    service := mustService(repository, grants, investigations, fixedStarterIdentity())

    result, err := service.PrepareRun(context.Background(), PrepareRunRequest{
        Scope: validScope(), RunID: runID, ExpectedPolicyDigest: policyDigest,
        SchedulerWorkloadIdentityDigest: schedulerIdentityDigest,
    })
    if err != nil {
        t.Fatalf("PrepareRun() error = %v", err)
    }
    if investigations.calls != 0 || result.Run.Status != RunCompleted ||
        result.Run.GrantID == "" || result.Run.AssetSnapshotID == "" {
        t.Fatalf("shadow run escaped boundary: %#v", result)
    }
}
~~~

- [ ] **Step 5: 实现 PostgreSQL 策略/运行 Repository**

每个写操作在单事务内：锁精确 Scope；计算数据库时间；校验 If-Match/version；写策略或运行；追加 audit_records；追加低敏 Outbox。CreateRevision 使用 advisory xact lock 锁定 policy_id 并分配 max(revision)+1；Publish 重新验证 Capability/Runtime digest 和 Preview digest；RequestRun 以触发去重键确保重放只返回同一 Run。

~~~go
type Repository interface {
    CreateRevision(context.Context, CreateRevisionRequest) (PolicyRevision, error)
    GetPolicy(context.Context, ScopeRequest) (PolicyRevision, error)
    ListPolicies(context.Context, ListPoliciesRequest) (PolicyPage, error)
    PublishRevision(context.Context, PublishRequest) (PolicyRevision, error)
    Disable(context.Context, DisableRequest) (PolicyRevision, error)
    CreateOrGetRun(context.Context, CreateRunRequest) (RunResult, error)
    TransitionRun(context.Context, TransitionRunRequest) (ProactiveRun, error)
    GetRun(context.Context, RunRequest) (ProactiveRun, error)
    ListRuns(context.Context, ListRunsRequest) (RunPage, error)
}
~~~

List Policy 稳定排序 updated_at DESC, policy_id DESC；List Run 排序 created_at DESC, id DESC；默认 50、最大 100。跨 Scope 与未知对象都返回 store.ErrNotFound。

- [ ] **Step 6: 运行领域、仓储和并发测试**

Run: go test -race -shuffle=on -count=1 ./internal/proactivepolicy ./internal/proactivepolicy/postgres

Expected: PASS。

Run: AIOPS_TEST_POSTGRES_DSN='postgres://aiops:password@127.0.0.1:5432/aiops_test?sslmode=disable' go test -race -count=1 ./internal/proactivepolicy/postgres -run 'TestRepository'

Expected: PASS，且并发 Publish/Disable/RequestRun 不产生双发布、双 Run 或越 Scope 行。

- [ ] **Step 7: 提交策略和运行持久化**

~~~bash
git add internal/proactivepolicy
git commit -m "feat: add proactive investigation policies"
~~~

### Task 5: 事件、定时与人工触发的统一编排

**Files:**
- Create: internal/proactiveworkflow/types.go
- Create: internal/proactiveworkflow/workflow.go
- Create: internal/proactiveworkflow/activities.go
- Create: internal/proactiveworkflow/registration.go
- Create: internal/proactiveworkflow/workflow_test.go
- Create: internal/proactiveworkflow/activities_test.go
- Create: internal/outbox/proactive_dispatcher.go
- Create: internal/outbox/proactive_dispatcher_test.go
- Modify: internal/investigationworkflow/runtime_v2_control_worker.go
- Modify: internal/investigationworkflow/runtime_v2_registration_internal_test.go

**Interfaces:**
- Consumes: proactivepolicy.Service.RequestRun/PrepareRun；store.OutboxRepository；Temporal SDK 1.46.0；现有 RuntimeV2ControlWorker 固定注册集。
- Produces: WorkflowName = aiops.proactive.investigation.v1；PrepareActivityName = aiops.proactive.investigation.prepare.activity.v1；TriggerStarter.Start(context.Context, TriggerInput)；SchedulerPublisher.Upsert/Disable。事件/人工 TriggerInput 必须已有 RunID，Schedule TriggerInput 不预生成 RunID，由每次 Workflow 的 deterministic start time 在同一 Prepare Activity 内 RequestRun。

- [ ] **Step 1: 写严格 History DTO 与 deterministic Workflow 失败测试**

~~~go
func TestTriggerInputContainsOnlyIDsAndDigests(t *testing.T) {
    value := TriggerInput{
        Version: 1, RunID: runID, TenantID: tenantID, WorkspaceID: workspaceID,
        EnvironmentID: environmentID, PolicyID: policyID, PolicyRevision: 4,
        PolicyDigest: policyDigest, TriggerType: "INCIDENT", TriggerID: incidentID,
        SchedulerWorkloadIdentityDigest: schedulerIdentityDigest,
    }
    raw, err := json.Marshal(value)
    if err != nil || len(raw) > 4096 || value.ValidateForStart() != nil {
        t.Fatalf("TriggerInput = %s, %v", raw, err)
    }
    lowered := strings.ToLower(string(raw))
    for _, forbidden := range []string{"endpoint", "secret", "token", "password", "query", "selector", "target_ref", "credential"} {
        if strings.Contains(lowered, forbidden) {
            t.Fatalf("History input leaked %q: %s", forbidden, raw)
        }
    }
}

func TestScheduleTriggerHasNoPublicationTimeRunID(t *testing.T) {
    value := validScheduleTriggerInput()
    if value.RunID != "" || value.TriggerID != "" || value.ScheduledAtUnixMicros != 0 ||
        value.ValidateForStart() != nil {
        t.Fatalf("schedule start input = %#v", value)
    }
}

func TestWorkflowCallsExactlyOnePreparationActivity(t *testing.T) {
    suite := testsuite.WorkflowTestSuite{}
    env := suite.NewTestWorkflowEnvironment()
    env.RegisterActivityWithOptions(func(context.Context, TriggerInput) (PrepareOutput, error) {
        return PrepareOutput{Version: 1, RunID: runID, Status: "GRANTED", GrantID: grantID}, nil
    }, activity.RegisterOptions{Name: PrepareActivityName})
    env.ExecuteWorkflow(Workflow, validTriggerInput())
    if !env.IsWorkflowCompleted() || env.GetWorkflowError() != nil {
        t.Fatalf("workflow error = %v", env.GetWorkflowError())
    }
    env.AssertExpectations(t)
}
~~~

- [ ] **Step 2: 运行 Workflow 测试并确认失败**

Run: go test ./internal/proactiveworkflow -run 'Test(TriggerInput|Workflow)' -count=1

Expected: FAIL，错误指出 package 或 TriggerInput/Workflow 不存在。

- [ ] **Step 3: 实现 Workflow、Activity 与固定注册集**

Workflow 只执行一次 Prepare Activity；RetryPolicy 固定 MaximumAttempts=3、InitialInterval=1s、BackoffCoefficient=2、MaximumInterval=10s；StartToCloseTimeout=30s。Activity 调用 PrepareRun，所有未知错误转为稳定 proactive_prepare_failed，不把原错误写入 Temporal Failure。

~~~go
const (
    WorkflowName = "aiops.proactive.investigation.v1"
    PrepareActivityName = "aiops.proactive.investigation.prepare.activity.v1"
)

type TriggerInput struct {
    Version int `json:"version"`
    RunID string `json:"run_id,omitempty"`
    TenantID string `json:"tenant_id"`
    WorkspaceID string `json:"workspace_id"`
    EnvironmentID string `json:"environment_id"`
    PolicyID string `json:"policy_id"`
    PolicyRevision int64 `json:"policy_revision"`
    PolicyDigest string `json:"policy_digest"`
    TriggerType string `json:"trigger_type"`
    TriggerID string `json:"trigger_id,omitempty"`
    ScheduledAtUnixMicros int64 `json:"scheduled_at_unix_micros,omitempty"`
    SchedulerWorkloadIdentityDigest string `json:"scheduler_workload_identity_digest,omitempty"`
}

func Workflow(ctx workflow.Context, input TriggerInput) (PrepareOutput, error) {
    if input.ValidateForStart() != nil {
        return PrepareOutput{}, temporal.NewNonRetryableApplicationError(
            "proactive trigger rejected", "PROACTIVE_TRIGGER_REJECTED", nil,
        )
    }
    if input.TriggerType == "SCHEDULE" {
        input.ScheduledAtUnixMicros = workflow.Now(ctx).UTC().UnixMicro()
    }
    if input.ValidateForActivity() != nil {
        return PrepareOutput{}, temporal.NewNonRetryableApplicationError(
            "proactive trigger rejected", "PROACTIVE_TRIGGER_REJECTED", nil,
        )
    }
    ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
        StartToCloseTimeout: 30 * time.Second,
        RetryPolicy: &temporal.RetryPolicy{
            InitialInterval: time.Second,
            BackoffCoefficient: 2,
            MaximumInterval: 10 * time.Second,
            MaximumAttempts: 3,
            NonRetryableErrorTypes: []string{"PROACTIVE_TRIGGER_REJECTED", "POLICY_SUPERSEDED"},
        },
    })
    var output PrepareOutput
    if err := workflow.ExecuteActivity(ctx, PrepareActivityName, input).Get(ctx, &output); err != nil {
        return PrepareOutput{}, err
    }
    if output.ValidateAgainst(input) != nil {
        return PrepareOutput{}, temporal.NewNonRetryableApplicationError(
            "proactive result rejected", "PROACTIVE_RESULT_REJECTED", nil,
        )
    }
    return output, nil
}
~~~

Prepare Activity 对 SCHEDULE 先把 ScheduledAtUnixMicros 严格转换为有限 UTC microsecond，再以 policy digest + ScheduledAt 的 JCS digest 作为 trigger dedup key 调用 RequestRun；对 INCIDENT/MANUAL 加载并校验既有 RunID。随后统一调用 PrepareRun：SHADOW 原子持久化 Snapshot/Grant、ISSUED→ACTIVE→COMPLETED 和 Run→COMPLETED，但不创建 Investigation/Task；READ_ONLY 原子绑定 Run/Snapshot/Grant/Investigation，先把 Grant 激活再让 QUEUED Task 对 Runner 可见。PrepareOutput.ValidateAgainst 对 INCIDENT/MANUAL 要求 output.RunID 等于 input.RunID，对 SCHEDULE 要求 output.RunID 是新建或幂等重放的有效 UUID。任何一步失败都不得留下可 Claim 的 Task 配未激活 Grant。

扩展 RuntimeV2ControlWorker 的固定注册集，只增加上述 Workflow/Activity；保留既有角色隔离、converter、queue 和 hidden-child 约束。架构测试锁定名称与恰好一次注册，拒绝 raw client.StartWorkflow 的旁路调用。

- [ ] **Step 4: 写 incident.created.v1 Outbox Dispatcher 测试**

Dispatcher 只接受 AggregateType=INCIDENT、AggregateVersion=1、event_type=incident.created.v1、严格 Payload 仅 incident_id。它调用 PolicyMatcher 取得已发布 INCIDENT 策略，然后为每个策略调用 RequestRun 并以 run ID 启动 Workflow；全部 STARTED/ALREADY_EXISTS 才 ACK。Poison event 不 ACK、不删除；未知 start outcome 进入有界 retry。

~~~go
func TestProactiveDispatcherStartsExactPublishedPoliciesAndAcks(t *testing.T) {
    event := domain.OutboxEvent{
        ID: outboxID, TenantID: tenantID, WorkspaceID: workspaceID,
        AggregateType: "INCIDENT", AggregateID: incidentID, AggregateVersion: 1,
        Type: "incident.created.v1", Payload: json.RawMessage("{\"incident_id\":\"" + incidentID + "\"}"),
        ClaimToken: claimToken, Attempts: 1,
    }
    repository := &outboxFake{events: []domain.OutboxEvent{event}}
    matcher := &matcherFake{matches: []MatchedPolicy{{PolicyID: policyID, Revision: 3, Digest: policyDigest}}}
    starter := &starterFake{outcome: StartOutcomeStarted}
    dispatcher := mustProactiveDispatcher(repository, matcher, starter)
    result, err := dispatcher.RunOnce(context.Background())
    if err != nil || result.Started != 1 || repository.acked != 1 {
        t.Fatalf("RunOnce() = %#v, %v", result, err)
    }
}
~~~

- [ ] **Step 5: 实现 Temporal Schedule 发布器**

发布 SCHEDULE Revision 时创建确定性 Schedule ID proactive/{tenant}/{workspace}/{environment}/{policyID}；Action 固定 WorkflowName 和不含 RunID/TriggerID/ScheduledAtUnixMicros 的 Schedule TriggerInput。Temporal 为每次触发创建独立 Workflow execution，Workflow 用 workflow.Now(ctx) 得到 deterministic ScheduledAtUnixMicros，Prepare Activity 再以 policy digest + ScheduledAt 创建/重放唯一 Run；不得在发布时冻结一个 RunID 供所有未来触发复用。Overlap=SKIP、CatchupWindow=1m、PauseOnFailure=true。更新必须比较 policy digest；Disable 只暂停同一 Schedule，不删除历史。Starter/Schedule 客户端从已有 Control Worker Temporal 身份注入，不能读取环境变量或自行 Dial。

~~~go
type SchedulerPublisher interface {
    Upsert(context.Context, PolicyRevision) error
    Disable(context.Context, PolicyRevision) error
}

func scheduleOptions(policy PolicyRevision, workloadDigest string) client.ScheduleOptions {
    return client.ScheduleOptions{
        ID: scheduleID(policy),
        Spec: client.ScheduleSpec{CronExpressions: []string{policy.Trigger.ScheduleExpression}},
        Action: &client.ScheduleWorkflowAction{
            ID: "proactive-schedule/" + policy.Scope.TenantID + "/" + policy.Scope.WorkspaceID + "/" +
                policy.Scope.EnvironmentID + "/" + policy.PolicyID,
            Workflow: proactiveworkflow.WorkflowName,
            Args: []any{scheduleTriggerInput(policy, workloadDigest)},
            TaskQueue: controlTaskQueue(policy.Scope.EnvironmentID),
        },
        Overlap: enums.SCHEDULE_OVERLAP_POLICY_SKIP,
        CatchupWindow: time.Minute,
        PauseOnFailure: true,
    }
}
~~~

增加 Schedule Workflow 测试：同一 Policy 在两个不同 Workflow start time 执行时，Prepare Activity 收到两个不同 ScheduledAtUnixMicros，Repository 生成两个不同 Run；重放同一 History 仍返回同一 Run。不得让浏览器提交 Task Queue、Workflow ID、Scheduler workload digest、ScheduledAtUnixMicros 或 Temporal namespace。

- [ ] **Step 6: 实现人工 Run 走同一 Starter**

POST :run 先幂等创建 TriggerType=MANUAL 的 ProactiveRun，Issuer=HUMAN，再通过同一 TriggerStarter 以 proactive/{runID} 启动 Workflow；incident.created.v1 Dispatcher 同样先 RequestRun 再启动。Schedule 是唯一允许无 RunID 启动的入口，并在 Prepare Activity 内 RequestRun。不允许 HTTP Handler 直接调用 Grant Repository 或 Investigation Repository。人工 Run 仍执行 Policy current revision、最小间隔、并发、Snapshot、Kill Switch 和预算检查。

- [ ] **Step 7: 运行 deterministic、Outbox 和注册边界测试**

Run: go test -race -shuffle=on -count=1 ./internal/proactiveworkflow ./internal/outbox ./internal/investigationworkflow

Expected: PASS；History canary 扫描不出现 Selector、Endpoint、Secret、Target、Credential 或原始错误。

- [ ] **Step 8: 提交统一触发编排**

~~~bash
git add internal/proactiveworkflow internal/outbox/proactive_dispatcher* internal/investigationworkflow/runtime_v2_control_worker.go internal/investigationworkflow/runtime_v2_registration_internal_test.go
git commit -m "feat: orchestrate proactive investigation triggers"
~~~
