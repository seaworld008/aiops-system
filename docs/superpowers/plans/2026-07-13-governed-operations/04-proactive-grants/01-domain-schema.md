# Investigation Grants Domain and Schema Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 定义不可变 Asset Snapshot、短期 InvestigationGrant、五轴预算及 000018 七表 PostgreSQL 事实模型，为后续策略、Evidence-backed ActionProposal、Gateway 和 UI 提供不可歧义的授权契约。

**Architecture:** 先以纯 Go 领域类型、JCS/SHA-256 和状态机锁定语义，再用 PostgreSQL 18.4+ 复合作用域外键、不可变触发器和 guarded rollback 落盘；本包不装配运行路径。

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

- 顺序：1 / 7；必须按 README.md 固定顺序执行。
- 前置：main@ad50d9f，以及 Program 的 000015 Asset、000016 Connection/Runtime、000017 VictoriaMetrics 前置计划接口。
- 交付给下一包：Snapshot/Grant/Budget 领域 API 与只拥有七张表的 000018 migration；`action_proposals` 的应用领域、Repository、生成约束和公共 API 由 `04-evidence-action-proposal.md` 实现。
- 本包内仍按 Task 编号顺序执行；每个 Task 必须先看到预期失败，再写最小实现、跑通过并提交对应 commit。

### Task 1: Asset Snapshot、Grant 与预算领域契约

**Files:**
- Create: internal/investigationgrant/types.go
- Create: internal/investigationgrant/canonical.go
- Create: internal/investigationgrant/budget.go
- Create: internal/investigationgrant/types_test.go
- Create: internal/investigationgrant/canonical_test.go
- Create: internal/investigationgrant/budget_test.go

**Interfaces:**
- Consumes: 无；本任务只依赖标准库和 github.com/cyberphone/json-canonicalization。
- Produces: Scope.Validate() error；NewAssetSnapshot(Scope, string, []SnapshotItem, time.Time) (AssetSnapshot, error)；NewGrant(IssueInput) (Grant, error)；Budget.Validate() error；EvaluateBudget(Budget, Usage, Reservation) error；Grant.ActiveAt(time.Time) error。

- [ ] **Step 1: 写失败的领域状态与边界测试**

将以下测试写入 internal/investigationgrant/types_test.go；固定时间、固定摘要和排序，禁止在测试中调用 time.Now。

~~~go
package investigationgrant

import (
    "errors"
    "testing"
    "time"
)

func TestNewAssetSnapshotSortsItemsAndRejectsIneligibleAssets(t *testing.T) {
    now := time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC)
    scope := Scope{TenantID: "11111111-1111-4111-8111-111111111111", WorkspaceID: "22222222-2222-4222-8222-222222222222", EnvironmentID: "33333333-3333-4333-8333-333333333333", ServiceID: "44444444-4444-4444-8444-444444444444"}
    eligible := func(id string, position int) SnapshotItem {
        return SnapshotItem{
            Position: position, AssetID: id, AssetRevision: 7,
            MappingStatus: MappingExact, Lifecycle: AssetActive,
            ConnectionID: "55555555-5555-4555-8555-555555555555", ConnectionRevision: 3,
            TargetRef: "victorialogs-prod-v1-" + digestA, TargetDigest: digestA,
            CapabilitySetID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            CapabilityIDs: []string{"VICTORIALOGS_SEARCH"}, CapabilitySetDigest: digestB,
            RuntimePublicationID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            RuntimeBundleDigest: digestC, RunnerRealmID: "66666666-6666-4666-8666-666666666666",
            AdapterFamily: "VICTORIALOGS", SourceKey: "victorialogs:prod",
        }
    }
    snapshot, err := NewAssetSnapshot(scope, "77777777-7777-4777-8777-777777777777", []SnapshotItem{
        eligible("99999999-9999-4999-8999-999999999999", 8),
        eligible("88888888-8888-4888-8888-888888888888", 2),
    }, now)
    if err != nil {
        t.Fatalf("NewAssetSnapshot() error = %v", err)
    }
    if snapshot.Items[0].AssetID != "88888888-8888-4888-8888-888888888888" || snapshot.Items[0].Position != 1 ||
        snapshot.Items[1].Position != 2 || snapshot.Digest == "" {
        t.Fatalf("snapshot is not canonical: %#v", snapshot)
    }

    stale := eligible("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", 1)
    stale.Lifecycle = AssetStale
    if _, err := NewAssetSnapshot(scope, "77777777-7777-4777-8777-777777777777", []SnapshotItem{stale}, now); !errors.Is(err, ErrAssetIneligible) {
        t.Fatalf("stale asset error = %v, want ErrAssetIneligible", err)
    }
}

func TestGrantStateAndTimeWindowFailClosed(t *testing.T) {
    now := time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC)
    grant, err := NewGrant(validIssueInput(now))
    if err != nil {
        t.Fatalf("NewGrant() error = %v", err)
    }
    if err := grant.ActiveAt(now); !errors.Is(err, ErrGrantInactive) {
        t.Fatalf("ISSUED ActiveAt() error = %v", err)
    }
    grant.Status = GrantActive
    if err := grant.ActiveAt(now.Add(time.Minute)); err != nil {
        t.Fatalf("ACTIVE ActiveAt() error = %v", err)
    }
    grant.Status = GrantRevoked
    if err := grant.ActiveAt(now.Add(time.Minute)); !errors.Is(err, ErrGrantRevoked) {
        t.Fatalf("REVOKED ActiveAt() error = %v", err)
    }
}
~~~

在同文件定义 digestA、digestB、digestC 为三个不同的 64 位小写十六进制常量，并让 validIssueInput 同时覆盖 Human 与 Scheduler 二选一约束：Scheduler 必须同时包含 Policy ID、Policy Revision、Policy Digest 和 workload identity digest，不能把策略本身当成 Principal。

- [ ] **Step 2: 运行领域测试并确认按预期失败**

Run: go test ./internal/investigationgrant -run 'Test(NewAssetSnapshot|GrantState)' -count=1

Expected: FAIL，错误包含 package github.com/seaworld008/aiops-system/internal/investigationgrant is not in std 或未定义 Scope/NewAssetSnapshot/NewGrant。

- [ ] **Step 3: 写最小且完整的领域类型、状态与校验**

在 internal/investigationgrant/types.go 定义以下公开契约；JSON DTO 不直接复用这些领域值，避免意外序列化私有授权事实。

~~~go
package investigationgrant

import (
    "errors"
    "time"
)

const (
    SnapshotSchemaVersion = "asset-snapshot.v1"
    GrantSchemaVersion = "investigation-grant.v1"
    MaxSnapshotItems = 256
    MaxCapabilitiesPerAsset = 32
)

var (
    ErrInvalidRequest = errors.New("invalid investigation grant request")
    ErrAssetIneligible = errors.New("asset is not eligible for investigation")
    ErrGrantInactive = errors.New("grant is not active")
    ErrGrantExpired = errors.New("grant expired")
    ErrGrantRevoked = errors.New("grant revoked")
    ErrBudgetExhausted = errors.New("grant budget exhausted")
    ErrKillSwitchClosed = errors.New("kill switch closed")
    ErrDigestMismatch = errors.New("grant digest mismatch")
)

type MappingStatus string
type AssetLifecycle string
type GrantStatus string
type TriggerType string
type IssuerType string
type DataClassification string

const (
    MappingExact MappingStatus = "EXACT"
    AssetActive AssetLifecycle = "ACTIVE"
    AssetStale AssetLifecycle = "STALE"
    AssetQuarantined AssetLifecycle = "QUARANTINED"
    GrantIssued GrantStatus = "ISSUED"
    GrantActive GrantStatus = "ACTIVE"
    GrantCompleted GrantStatus = "COMPLETED"
    GrantExpired GrantStatus = "EXPIRED"
    GrantRevoked GrantStatus = "REVOKED"
    GrantFailed GrantStatus = "FAILED"
    TriggerIncident TriggerType = "INCIDENT"
    TriggerSchedule TriggerType = "SCHEDULE"
    TriggerManual TriggerType = "MANUAL"
    IssuerHuman IssuerType = "HUMAN"
    IssuerScheduler IssuerType = "SCHEDULER"
    ClassificationInternal DataClassification = "INTERNAL"
    ClassificationSensitive DataClassification = "SENSITIVE"
)

type Scope struct {
    TenantID string
    WorkspaceID string
    EnvironmentID string
    ServiceID string
}

type SnapshotItem struct {
    Position int
    AssetID string
    AssetRevision int64
    MappingStatus MappingStatus
    Lifecycle AssetLifecycle
    ConnectionID string
    ConnectionRevision int64
    TargetRef string
    TargetDigest string
    CapabilitySetID string
    CapabilityIDs []string
    CapabilitySetDigest string
    RuntimePublicationID string
    RuntimeBundleDigest string
    RunnerRealmID string
    AdapterFamily string
    SourceKey string
}

type AssetSnapshot struct {
    SchemaVersion string
    ID string
    Scope Scope
    Items []SnapshotItem
    Digest string
    CreatedAt time.Time
}

type Budget struct {
    MaxToolCalls int
    MaxConcurrencyPerSource int
    MaxDuration time.Duration
    MaxEvidenceBytes int64
    MaxModelTokens int64
}

type Usage struct {
    DistinctToolCalls int
    ActiveBySource map[string]int
    EvidenceBytes int64
    ModelTokens int64
}

type Reservation struct {
    TaskID string
    SourceKey string
    EvidenceBytes int64
    ModelTokens int64
}

type Issuer struct {
    Type IssuerType
    HumanSubject string
    SchedulerPolicyID string
    SchedulerPolicyRevision int64
    SchedulerPolicyDigest string
    SchedulerWorkloadIdentityDigest string
}

type IssueInput struct {
    ID string
    Scope Scope
    IncidentID string
    TriggerType TriggerType
    TriggerID string
    Issuer Issuer
    Snapshot AssetSnapshot
    CapabilitySnapshotDigest string
    RuntimeBundleDigest string
    Classification DataClassification
    Budget Budget
    NotBefore time.Time
    ExpiresAt time.Time
    PolicyRevision int64
    PolicyDigest string
    KillSwitchDigest string
}

type Grant struct {
    SchemaVersion string
    ID string
    Scope Scope
    IncidentID string
    TriggerType TriggerType
    TriggerID string
    Issuer Issuer
    AssetSnapshotID string
    AssetSnapshotDigest string
    CapabilitySnapshotDigest string
    RuntimeBundleDigest string
    Classification DataClassification
    Budget Budget
    NotBefore time.Time
    ExpiresAt time.Time
    PolicyRevision int64
    PolicyDigest string
    KillSwitchDigest string
    Digest string
    Status GrantStatus
    Version int64
    RevokedAt time.Time
    RevokeReason string
    FailureCode string
}

func (grant Grant) ActiveAt(now time.Time) error {
    now = now.UTC()
    if grant.Status == GrantRevoked {
        return ErrGrantRevoked
    }
    if !now.Before(grant.ExpiresAt) {
        return ErrGrantExpired
    }
    if grant.Status != GrantActive || now.Before(grant.NotBefore) {
        return ErrGrantInactive
    }
    return nil
}
~~~

实现 Scope、SnapshotItem、Budget、Issuer、IssueInput 和 Grant 的 Validate；所有 ID（含 CapabilitySetID、RuntimePublicationID）使用小写 RFC 4122 UUID v1–v5，所有摘要固定 64 位小写十六进制，时间必须为有限 UTC，Snapshot 1–256 项、每资产 1–32 个 Capability，Capability ID/Adapter Family/Source Key 只允许有界 ASCII。Grant TTL 必须大于 0 且不超过 15 分钟。

- [ ] **Step 4: 写 canonical digest 与预算的失败测试**

将以下测试分别写入 canonical_test.go 和 budget_test.go。

~~~go
func TestSnapshotDigestIsOrderIndependentAndDomainSeparated(t *testing.T) {
    now := time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC)
    left, err := NewAssetSnapshot(validScope(), snapshotID, []SnapshotItem{validItem(assetB), validItem(assetA)}, now)
    if err != nil {
        t.Fatal(err)
    }
    right, err := NewAssetSnapshot(validScope(), snapshotID, []SnapshotItem{validItem(assetA), validItem(assetB)}, now)
    if err != nil {
        t.Fatal(err)
    }
    if left.Digest != right.Digest {
        t.Fatalf("digest changed with input order: %s != %s", left.Digest, right.Digest)
    }
    input := validIssueInput(now)
    input.Snapshot = left
    grant, err := NewGrant(input)
    if err != nil {
        t.Fatal(err)
    }
    if grant.Digest == left.Digest {
        t.Fatal("grant and snapshot domains share a digest")
    }
}

func TestEvaluateBudgetEnforcesEveryAxis(t *testing.T) {
    budget := Budget{MaxToolCalls: 2, MaxConcurrencyPerSource: 1, MaxDuration: 5 * time.Minute, MaxEvidenceBytes: 1024, MaxModelTokens: 2048}
    usage := Usage{DistinctToolCalls: 1, ActiveBySource: map[string]int{"metrics": 1}, EvidenceBytes: 1000, ModelTokens: 2000}
    for name, reservation := range map[string]Reservation{
        "source concurrency": {TaskID: taskA, SourceKey: "metrics"},
        "evidence bytes": {TaskID: taskA, SourceKey: "logs", EvidenceBytes: 25},
        "model tokens": {TaskID: taskA, SourceKey: "logs", ModelTokens: 49},
    } {
        t.Run(name, func(t *testing.T) {
            if err := EvaluateBudget(budget, usage, reservation); !errors.Is(err, ErrBudgetExhausted) {
                t.Fatalf("EvaluateBudget() error = %v", err)
            }
        })
    }
}
~~~

- [ ] **Step 5: 实现 JCS 摘要和预算计算**

在 canonical.go 使用显式 wire projection；先深拷贝并排序 AssetID、CapabilityIDs，再 JCS 规范化，最后计算 SHA-256。Digest 必须覆盖 Schema、Scope、每个 Asset Revision、Connection Revision、TargetRef/Target digest、CapabilitySet ID/digest、RuntimePublication ID/bundle digest、Realm ID、Issuer、Trigger、预算、有效期和 Kill Switch 摘要，但不得覆盖可变 Status/Version。

~~~go
func canonicalDigest(value any) (string, error) {
    raw, err := json.Marshal(value)
    if err != nil || len(raw) == 0 || len(raw) > 1<<20 {
        return "", ErrInvalidRequest
    }
    canonical, err := jsoncanonicalizer.Transform(raw)
    if err != nil {
        return "", ErrInvalidRequest
    }
    sum := sha256.Sum256(canonical)
    return hex.EncodeToString(sum[:]), nil
}

func EvaluateBudget(budget Budget, usage Usage, next Reservation) error {
    if budget.Validate() != nil || next.TaskID == "" || next.SourceKey == "" ||
        usage.DistinctToolCalls < 0 || usage.EvidenceBytes < 0 || usage.ModelTokens < 0 ||
        next.EvidenceBytes < 0 || next.ModelTokens < 0 {
        return ErrInvalidRequest
    }
    if usage.DistinctToolCalls >= budget.MaxToolCalls ||
        usage.ActiveBySource[next.SourceKey] >= budget.MaxConcurrencyPerSource ||
        usage.EvidenceBytes > budget.MaxEvidenceBytes-next.EvidenceBytes ||
        usage.ModelTokens > budget.MaxModelTokens-next.ModelTokens {
        return ErrBudgetExhausted
    }
    return nil
}
~~~

预算范围固定为：MaxToolCalls 1–12；MaxConcurrencyPerSource 1–4 且不得大于 MaxToolCalls；MaxDuration 30 秒–15 分钟；MaxEvidenceBytes 1 KiB–8 MiB；MaxModelTokens 0–65536。加法必须使用减法比较避免整数溢出。

- [ ] **Step 6: 运行包测试与 race**

Run: go test -race -shuffle=on -count=1 ./internal/investigationgrant

Expected: PASS；输出以 ok github.com/seaworld008/aiops-system/internal/investigationgrant 结束。

- [ ] **Step 7: 提交领域契约**

~~~bash
git add internal/investigationgrant
git commit -m "feat: define investigation grant contracts"
~~~

### Task 2: 000018 PostgreSQL Schema、状态机与回滚保护

**Files:**
- Create: migrations/000018_investigation_grants_proactive_policies.up.sql
- Create: migrations/000018_investigation_grants_proactive_policies.down.sql
- Create: internal/investigationgrant/postgres/migration_test.go
- Create: internal/investigationgrant/postgres/migration_integration_test.go

**Interfaces:**
- Consumes: 000015 的 assets、service_asset_bindings；000016 的 connection_profiles、connection_revisions、published_targets、published_capability_sets、runtime_publications、runner_realms、runner_capability_bindings；现有 tenants/workspaces/environments/services/incidents/investigations/audit_records/outbox_events。
- Produces: 七张且仅七张新表 asset_snapshots、asset_snapshot_items、investigation_grants、kill_switch_revisions、proactive_policy_revisions、proactive_runs、action_proposals；所有表均可用 tenant/workspace/environment 精确作用域读取。

- [ ] **Step 1: 写静态迁移失败测试**

在 migration_test.go 读取 up/down 文件并断言：恰好七个 CREATE TABLE；包含 SET LOCAL lock_timeout = '5s'、受保护 search_path、复合外键、状态转换触发器、不可变触发器和 down 的数据存在保护；禁止 jsonb、secret、token、password、endpoint、dsn、header、sql 字段。

~~~go
func TestMigrationOwnsExactlySevenSafeTables(t *testing.T) {
    body := readMigration(t, "../../../migrations/000018_investigation_grants_proactive_policies.up.sql")
    want := []string{
        "CREATE TABLE asset_snapshots",
        "CREATE TABLE asset_snapshot_items",
        "CREATE TABLE investigation_grants",
        "CREATE TABLE kill_switch_revisions",
        "CREATE TABLE proactive_policy_revisions",
        "CREATE TABLE proactive_runs",
        "CREATE TABLE action_proposals",
    }
    if strings.Count(body, "CREATE TABLE ") != len(want) {
        t.Fatalf("CREATE TABLE count = %d, want %d", strings.Count(body, "CREATE TABLE "), len(want))
    }
    for _, fragment := range want {
        if !strings.Contains(body, fragment) {
            t.Fatalf("migration missing %q", fragment)
        }
    }
    lowered := strings.ToLower(body)
    for _, forbidden := range []string{" jsonb", "secret", "password", "endpoint", " dsn", "header", "raw_error", "sql_text"} {
        if strings.Contains(lowered, forbidden) {
            t.Fatalf("migration contains forbidden storage fragment %q", forbidden)
        }
    }
}
~~~

- [ ] **Step 2: 运行静态迁移测试并确认失败**

Run: go test ./internal/investigationgrant/postgres -run TestMigrationOwnsExactlySevenSafeTables -count=1

Expected: FAIL，错误指出 000018 文件不存在。

- [ ] **Step 3: 写 up migration 的七表结构**

up migration 必须 BEGIN、5 秒 lock_timeout、受保护 search_path，并按依赖顺序创建以下精确主干。所有 timestamptz 添加有限时间 CHECK；所有 digest 使用 char(64) 和 C-collation 十六进制 CHECK；所有 text/array 添加 octet_length/cardinality 上限。

~~~sql
BEGIN;
SET LOCAL lock_timeout = '5s';
SELECT pg_catalog.set_config(
    'search_path',
    pg_catalog.quote_ident(current_schema()) || ', pg_catalog, pg_temp',
    true
);

ALTER TABLE incidents
    ADD CONSTRAINT incidents_environment_resource_uk
    UNIQUE (tenant_id, workspace_id, environment_id, id);

CREATE TABLE asset_snapshots (
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    id uuid NOT NULL,
    service_id uuid NOT NULL,
    schema_version text NOT NULL CHECK (schema_version = 'asset-snapshot.v1'),
    snapshot_digest char(64) COLLATE "C" NOT NULL,
    item_count integer NOT NULL CHECK (item_count BETWEEN 1 AND 256),
    created_by_type text NOT NULL CHECK (created_by_type IN ('HUMAN','SCHEDULER')),
    created_by_id text NOT NULL CHECK (octet_length(created_by_id) BETWEEN 1 AND 512),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, workspace_id, environment_id, id),
    UNIQUE (tenant_id, workspace_id, environment_id, id, snapshot_digest),
    UNIQUE (tenant_id, workspace_id, environment_id,
            id, snapshot_digest, service_id),
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces (tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, environment_id) REFERENCES environments (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, service_id) REFERENCES services (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    CHECK (snapshot_digest ~ '^[0-9a-f]{64}$'),
    CHECK (created_at > '-infinity'::timestamptz AND created_at < 'infinity'::timestamptz)
);

CREATE TABLE asset_snapshot_items (
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    snapshot_id uuid NOT NULL,
    position smallint NOT NULL CHECK (position BETWEEN 1 AND 256),
    asset_id uuid NOT NULL,
    asset_revision bigint NOT NULL CHECK (asset_revision > 0),
    mapping_status text NOT NULL CHECK (mapping_status = 'EXACT'),
    asset_lifecycle text NOT NULL CHECK (asset_lifecycle = 'ACTIVE'),
    connection_id uuid NOT NULL,
    connection_revision bigint NOT NULL CHECK (connection_revision > 0),
    target_ref text NOT NULL CHECK (octet_length(target_ref) BETWEEN 1 AND 512),
    target_digest char(64) COLLATE "C" NOT NULL CHECK (target_digest ~ '^[0-9a-f]{64}$'),
    capability_set_id uuid NOT NULL,
    capability_ids text[] NOT NULL CHECK (cardinality(capability_ids) BETWEEN 1 AND 32),
    capability_set_digest char(64) COLLATE "C" NOT NULL CHECK (capability_set_digest ~ '^[0-9a-f]{64}$'),
    runtime_publication_id uuid NOT NULL,
    runtime_bundle_digest char(64) COLLATE "C" NOT NULL CHECK (runtime_bundle_digest ~ '^[0-9a-f]{64}$'),
    runner_realm_id uuid NOT NULL,
    adapter_family text NOT NULL CHECK (octet_length(adapter_family) BETWEEN 1 AND 64),
    source_key text NOT NULL CHECK (octet_length(source_key) BETWEEN 1 AND 128),
    PRIMARY KEY (tenant_id, workspace_id, environment_id, snapshot_id, position),
    UNIQUE (tenant_id, workspace_id, environment_id, snapshot_id, asset_id),
    FOREIGN KEY (tenant_id, workspace_id, environment_id, snapshot_id)
        REFERENCES asset_snapshots (tenant_id, workspace_id, environment_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, environment_id, asset_id)
        REFERENCES assets (tenant_id, workspace_id, environment_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, environment_id, connection_id, connection_revision)
        REFERENCES connection_revisions (tenant_id, workspace_id, environment_id, connection_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, environment_id, target_ref)
        REFERENCES published_targets (tenant_id, workspace_id, environment_id, target_ref) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, environment_id, capability_set_id)
        REFERENCES published_capability_sets (tenant_id, workspace_id, environment_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, environment_id, runtime_publication_id)
        REFERENCES runtime_publications (tenant_id, workspace_id, environment_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, environment_id, runner_realm_id)
        REFERENCES runner_realms (tenant_id, workspace_id, environment_id, id) ON DELETE RESTRICT
);

CREATE TABLE investigation_grants (
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    id uuid NOT NULL,
    service_id uuid NOT NULL,
    incident_id uuid,
    trigger_type text NOT NULL CHECK (trigger_type IN ('INCIDENT','SCHEDULE','MANUAL')),
    trigger_id text NOT NULL CHECK (octet_length(trigger_id) BETWEEN 1 AND 512),
    issuer_type text NOT NULL CHECK (issuer_type IN ('HUMAN','SCHEDULER')),
    requester_subject text,
    scheduler_policy_id uuid,
    scheduler_policy_revision bigint,
    scheduler_policy_digest char(64) COLLATE "C",
    scheduler_workload_identity_digest char(64) COLLATE "C",
    asset_snapshot_id uuid NOT NULL,
    asset_snapshot_digest char(64) COLLATE "C" NOT NULL,
    capability_snapshot_digest char(64) COLLATE "C" NOT NULL,
    runtime_bundle_digest char(64) COLLATE "C" NOT NULL,
    data_classification text NOT NULL CHECK (data_classification IN ('INTERNAL','SENSITIVE')),
    max_tool_calls smallint NOT NULL CHECK (max_tool_calls BETWEEN 1 AND 12),
    max_concurrency_per_source smallint NOT NULL CHECK (max_concurrency_per_source BETWEEN 1 AND 4 AND max_concurrency_per_source <= max_tool_calls),
    max_duration_seconds integer NOT NULL CHECK (max_duration_seconds BETWEEN 30 AND 900),
    max_evidence_bytes bigint NOT NULL CHECK (max_evidence_bytes BETWEEN 1024 AND 8388608),
    max_model_tokens bigint NOT NULL CHECK (max_model_tokens BETWEEN 0 AND 65536),
    not_before timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    policy_revision bigint NOT NULL CHECK (policy_revision > 0),
    policy_digest char(64) COLLATE "C" NOT NULL,
    kill_switch_digest char(64) COLLATE "C" NOT NULL,
    grant_digest char(64) COLLATE "C" NOT NULL,
    status text NOT NULL CHECK (status IN ('ISSUED','ACTIVE','COMPLETED','EXPIRED','REVOKED','FAILED')),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    revoked_at timestamptz,
    revoke_reason text,
    failure_code text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, workspace_id, environment_id, id),
    UNIQUE (tenant_id, workspace_id, environment_id, id, grant_digest),
    FOREIGN KEY (tenant_id, workspace_id, environment_id,
                 asset_snapshot_id, asset_snapshot_digest, service_id)
        REFERENCES asset_snapshots
          (tenant_id, workspace_id, environment_id, id, snapshot_digest, service_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, environment_id, incident_id)
        REFERENCES incidents (tenant_id, workspace_id, environment_id, id) ON DELETE RESTRICT,
    CHECK (
        (issuer_type = 'HUMAN' AND requester_subject IS NOT NULL AND scheduler_policy_id IS NULL AND scheduler_policy_revision IS NULL AND scheduler_policy_digest IS NULL AND scheduler_workload_identity_digest IS NULL)
        OR
        (issuer_type = 'SCHEDULER' AND requester_subject IS NULL AND scheduler_policy_id IS NOT NULL AND scheduler_policy_revision > 0 AND scheduler_policy_digest ~ '^[0-9a-f]{64}$' AND scheduler_workload_identity_digest ~ '^[0-9a-f]{64}$')
    ),
    CHECK ((trigger_type = 'INCIDENT') = (incident_id IS NOT NULL)),
    CHECK (expires_at > not_before AND expires_at <= not_before + interval '15 minutes'),
    CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL AND revoke_reason IS NOT NULL)),
    CHECK ((status = 'FAILED') = (failure_code IS NOT NULL))
);

CREATE TABLE kill_switch_revisions (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    scope_level text NOT NULL CHECK (scope_level IN ('GLOBAL','WORKSPACE','ENVIRONMENT','ASSET','CONNECTION','CAPABILITY')),
    workspace_id uuid,
    environment_id uuid,
    subject_id text,
    revision bigint NOT NULL CHECK (revision > 0),
    closed boolean NOT NULL,
    revision_digest char(64) COLLATE "C" NOT NULL CHECK (revision_digest ~ '^[0-9a-f]{64}$'),
    reason text NOT NULL CHECK (octet_length(reason) BETWEEN 1 AND 1024),
    actor_subject text NOT NULL CHECK (octet_length(actor_subject) BETWEEN 1 AND 512),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE NULLS NOT DISTINCT (tenant_id, scope_level, workspace_id, environment_id, subject_id, revision),
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces (tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, environment_id) REFERENCES environments (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    CHECK (
        (scope_level = 'GLOBAL' AND workspace_id IS NULL AND environment_id IS NULL AND subject_id IS NULL)
        OR (scope_level = 'WORKSPACE' AND workspace_id IS NOT NULL AND environment_id IS NULL AND subject_id IS NULL)
        OR (scope_level = 'ENVIRONMENT' AND workspace_id IS NOT NULL AND environment_id IS NOT NULL AND subject_id IS NULL)
        OR (scope_level IN ('ASSET','CONNECTION','CAPABILITY') AND workspace_id IS NOT NULL AND environment_id IS NOT NULL AND subject_id IS NOT NULL)
    )
);

CREATE TABLE proactive_policy_revisions (
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    service_id uuid NOT NULL,
    name text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 160),
    trigger_type text NOT NULL CHECK (trigger_type IN ('INCIDENT','SCHEDULE')),
    event_type text,
    schedule_expression text,
    asset_ids uuid[] NOT NULL DEFAULT '{}',
    asset_kinds text[] NOT NULL DEFAULT '{}',
    service_ids uuid[] NOT NULL DEFAULT '{}',
    capability_set_id uuid NOT NULL,
    capability_set_digest char(64) COLLATE "C" NOT NULL,
    runtime_bundle_digest char(64) COLLATE "C" NOT NULL,
    data_classification text NOT NULL CHECK (data_classification IN ('INTERNAL','SENSITIVE')),
    mode text NOT NULL CHECK (mode IN ('SHADOW','READ_ONLY')),
    status text NOT NULL CHECK (status IN ('DRAFT','SHADOW','READ_ONLY','DISABLED','SUPERSEDED')),
    min_interval_seconds integer NOT NULL CHECK (min_interval_seconds BETWEEN 300 AND 86400),
    max_tool_calls smallint NOT NULL CHECK (max_tool_calls BETWEEN 1 AND 12),
    max_concurrency_per_source smallint NOT NULL CHECK (max_concurrency_per_source BETWEEN 1 AND 4 AND max_concurrency_per_source <= max_tool_calls),
    max_duration_seconds integer NOT NULL CHECK (max_duration_seconds BETWEEN 30 AND 900),
    max_evidence_bytes bigint NOT NULL CHECK (max_evidence_bytes BETWEEN 1024 AND 8388608),
    max_model_tokens bigint NOT NULL CHECK (max_model_tokens BETWEEN 0 AND 65536),
    policy_digest char(64) COLLATE "C" NOT NULL,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_by text NOT NULL,
    published_by text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    published_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, workspace_id, environment_id, policy_id, revision),
    UNIQUE (tenant_id, workspace_id, environment_id, policy_id, revision, policy_digest),
    FOREIGN KEY (tenant_id, workspace_id, environment_id) REFERENCES environments (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, service_id) REFERENCES services (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    CHECK ((trigger_type = 'INCIDENT' AND event_type = 'incident.created.v1' AND schedule_expression IS NULL) OR
           (trigger_type = 'SCHEDULE' AND event_type IS NULL AND schedule_expression IS NOT NULL)),
    CHECK (cardinality(asset_ids) <= 256 AND cardinality(asset_kinds) <= 32 AND cardinality(service_ids) <= 64),
    CHECK ((status = 'DRAFT' AND published_at IS NULL AND published_by IS NULL) OR
           (status <> 'DRAFT' AND published_at IS NOT NULL AND published_by IS NOT NULL))
);

CREATE TABLE proactive_runs (
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    id uuid NOT NULL,
    policy_id uuid NOT NULL,
    policy_revision bigint NOT NULL,
    policy_digest char(64) COLLATE "C" NOT NULL,
    mode text NOT NULL CHECK (mode IN ('SHADOW','READ_ONLY')),
    trigger_type text NOT NULL CHECK (trigger_type IN ('INCIDENT','SCHEDULE','MANUAL')),
    trigger_id text NOT NULL,
    trigger_dedup_key char(64) COLLATE "C" NOT NULL,
    asset_snapshot_id uuid,
    grant_id uuid,
    investigation_id uuid,
    status text NOT NULL CHECK (status IN ('QUEUED','RESOLVING','GRANTED','RUNNING','PARTIAL','COMPLETED','FAILED','STOPPED')),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    selected_asset_count integer NOT NULL DEFAULT 0 CHECK (selected_asset_count BETWEEN 0 AND 256),
    excluded_asset_count integer NOT NULL DEFAULT 0 CHECK (excluded_asset_count BETWEEN 0 AND 100000),
    failure_code text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    started_at timestamptz,
    completed_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, workspace_id, environment_id, id),
    UNIQUE (tenant_id, workspace_id, environment_id, trigger_dedup_key),
    FOREIGN KEY (tenant_id, workspace_id, environment_id, policy_id, policy_revision, policy_digest)
        REFERENCES proactive_policy_revisions (tenant_id, workspace_id, environment_id, policy_id, revision, policy_digest) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, environment_id, asset_snapshot_id)
        REFERENCES asset_snapshots (tenant_id, workspace_id, environment_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, environment_id, grant_id)
        REFERENCES investigation_grants (tenant_id, workspace_id, environment_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, investigation_id, environment_id)
        REFERENCES investigations (tenant_id, workspace_id, id, environment_id_snapshot) ON DELETE RESTRICT,
    CHECK ((status = 'FAILED') = (failure_code IS NOT NULL)),
    CHECK ((status IN ('PARTIAL','COMPLETED','FAILED','STOPPED')) = (completed_at IS NOT NULL))
);

CREATE TABLE action_proposals (
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    id uuid NOT NULL,
    service_id uuid NOT NULL,
    incident_id uuid NOT NULL,
    investigation_id uuid NOT NULL,
    asset_snapshot_id uuid NOT NULL,
    asset_snapshot_digest char(64) COLLATE "C" NOT NULL,
    asset_id uuid NOT NULL,
    asset_revision bigint NOT NULL CHECK (asset_revision > 0),
    evidence_ids uuid[] NOT NULL CHECK (cardinality(evidence_ids) BETWEEN 1 AND 16),
    evidence_digest char(64) COLLATE "C" NOT NULL CHECK (evidence_digest ~ '^[0-9a-f]{64}$'),
    catalog_revision bigint NOT NULL CHECK (catalog_revision > 0),
    catalog_digest char(64) COLLATE "C" NOT NULL CHECK (catalog_digest ~ '^[0-9a-f]{64}$'),
    action_type text NOT NULL CHECK (action_type IN (
        'K8S_ROLLOUT_RESTART','K8S_SCALE','GITOPS_REVERT','AWX_SERVICE_RESTART'
    )),
    intent_schema_version text NOT NULL,
    desired_replicas smallint,
    reason_code text,
    restart_scope text,
    proposal_mode text NOT NULL DEFAULT 'PROPOSAL_ONLY' CHECK (proposal_mode = 'PROPOSAL_ONLY'),
    actor_type text NOT NULL CHECK (actor_type = 'MODEL'),
    actor_attribution_id text NOT NULL CHECK (octet_length(actor_attribution_id) BETWEEN 1 AND 512),
    proposal_digest char(64) COLLATE "C" NOT NULL CHECK (proposal_digest ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, workspace_id, environment_id, id),
    UNIQUE (tenant_id, workspace_id, environment_id, id, proposal_digest),
    FOREIGN KEY (tenant_id, workspace_id, environment_id)
        REFERENCES environments (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, service_id)
        REFERENCES services (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, environment_id, incident_id)
        REFERENCES incidents (tenant_id, workspace_id, environment_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, investigation_id, environment_id)
        REFERENCES investigations (tenant_id, workspace_id, id, environment_id_snapshot) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, environment_id,
                 asset_snapshot_id, asset_snapshot_digest, service_id)
        REFERENCES asset_snapshots
          (tenant_id, workspace_id, environment_id, id, snapshot_digest, service_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, workspace_id, environment_id, asset_snapshot_id, asset_id)
        REFERENCES asset_snapshot_items
          (tenant_id, workspace_id, environment_id, snapshot_id, asset_id)
        ON DELETE RESTRICT,
    CHECK (created_at > '-infinity'::timestamptz AND created_at < 'infinity'::timestamptz),
    CHECK (
        (action_type = 'K8S_ROLLOUT_RESTART' AND intent_schema_version = 'k8s-rollout-restart-intent.v1'
            AND desired_replicas IS NULL AND reason_code IS NULL AND restart_scope IS NULL)
        OR
        (action_type = 'K8S_SCALE' AND intent_schema_version = 'k8s-scale-intent.v1'
            AND desired_replicas BETWEEN 0 AND 100 AND reason_code IS NULL AND restart_scope IS NULL)
        OR
        (action_type = 'GITOPS_REVERT' AND intent_schema_version = 'gitops-revert-intent.v1'
            AND desired_replicas IS NULL AND reason_code IN ('REGRESSION','FAILED_DEPLOYMENT') AND restart_scope IS NULL)
        OR
        (action_type = 'AWX_SERVICE_RESTART' AND intent_schema_version = 'awx-service-restart-intent.v1'
            AND desired_replicas IS NULL AND reason_code IS NULL AND restart_scope = 'SERVICE_INSTANCE')
    )
);
~~~

为数组增加逐项格式函数 proactive_text_array_valid。增加 asset_snapshot_item_reference_guard insert trigger，在一个查询中锁定 Connection Revision、Published Target、Capability Set/Items、Runtime Publication 与 Runner Realm，证明它们属于同一 Connection Revision，Target/Capability/Runtime digest 精确相等，Runtime 同时引用该 Target 与 Capability Set，Capability IDs 与 AVAILABLE items 精确相等，Realm mode=READ；任何零行、多行或摘要差异都用 23514 拒绝。为六级 subject_id 增加 insert trigger，分别锁定并确认 ASSET/CONNECTION/CAPABILITY 与相同 Tenant/Workspace/Environment。增加 `action_proposal_reference_guard`，在插入时锁定 Investigation、Incident、Snapshot Item 和按 UUID 排序后的全部 Evidence，要求 Evidence 数量精确等于数组基数、均属于同一 Investigation，并要求应用提交的 Evidence digest、Catalog digest 与事务内重新解析值一致；漂移以 SQLSTATE `23514` 拒绝。不得仅凭 UUID 全局唯一性授权。Down migration 在确认七表为空后同时删除 `incidents_environment_resource_uk`；若后续对象依赖该 key 则用 SQLSTATE `55000` 拒绝回滚，不能 `CASCADE`。

- [ ] **Step 4: 添加不可变和状态转换触发器**

Snapshot、Snapshot Item、Kill Switch Revision、ActionProposal 禁止 UPDATE/DELETE/TRUNCATE。Grant 只允许 ISSUED 到 ACTIVE/EXPIRED/REVOKED/FAILED，ACTIVE 到 COMPLETED/EXPIRED/REVOKED/FAILED；内容列不得变化，version 必须 +1。Policy 内容列不得变化；DRAFT 只能发布为该 Revision 固定的 mode，活动修订可 DISABLED/SUPERSEDED；SHADOW 提升 READ_ONLY、禁用后重启都必须创建新 Revision。Run 只允许 QUEUED→RESOLVING→GRANTED→RUNNING→PARTIAL/COMPLETED/FAILED/STOPPED，SHADOW 允许 GRANTED→COMPLETED。

~~~sql
CREATE OR REPLACE FUNCTION enforce_investigation_grant_update() RETURNS trigger AS $$
BEGIN
    IF ROW(
        OLD.tenant_id, OLD.workspace_id, OLD.environment_id, OLD.id, OLD.service_id,
        OLD.incident_id, OLD.trigger_type, OLD.trigger_id, OLD.issuer_type,
        OLD.requester_subject, OLD.scheduler_policy_id, OLD.scheduler_policy_revision,
        OLD.scheduler_policy_digest, OLD.scheduler_workload_identity_digest,
        OLD.asset_snapshot_id, OLD.asset_snapshot_digest, OLD.capability_snapshot_digest,
        OLD.runtime_bundle_digest, OLD.data_classification, OLD.max_tool_calls,
        OLD.max_concurrency_per_source, OLD.max_duration_seconds, OLD.max_evidence_bytes,
        OLD.max_model_tokens, OLD.not_before, OLD.expires_at, OLD.policy_revision,
        OLD.policy_digest, OLD.kill_switch_digest, OLD.grant_digest, OLD.created_at
    ) IS DISTINCT FROM ROW(
        NEW.tenant_id, NEW.workspace_id, NEW.environment_id, NEW.id, NEW.service_id,
        NEW.incident_id, NEW.trigger_type, NEW.trigger_id, NEW.issuer_type,
        NEW.requester_subject, NEW.scheduler_policy_id, NEW.scheduler_policy_revision,
        NEW.scheduler_policy_digest, NEW.scheduler_workload_identity_digest,
        NEW.asset_snapshot_id, NEW.asset_snapshot_digest, NEW.capability_snapshot_digest,
        NEW.runtime_bundle_digest, NEW.data_classification, NEW.max_tool_calls,
        NEW.max_concurrency_per_source, NEW.max_duration_seconds, NEW.max_evidence_bytes,
        NEW.max_model_tokens, NEW.not_before, NEW.expires_at, NEW.policy_revision,
        NEW.policy_digest, NEW.kill_switch_digest, NEW.grant_digest, NEW.created_at
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', CONSTRAINT = 'investigation_grants_content_immutable';
    END IF;
    IF NEW.version <> OLD.version + 1 OR NOT (
        (OLD.status = 'ISSUED' AND NEW.status IN ('ACTIVE','EXPIRED','REVOKED','FAILED')) OR
        (OLD.status = 'ACTIVE' AND NEW.status IN ('COMPLETED','EXPIRED','REVOKED','FAILED'))
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', CONSTRAINT = 'investigation_grants_transition_guard';
    END IF;
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SET search_path FROM CURRENT;
~~~

为 Policy 和 Run 写同样显式 ROW 内容比较，不使用 hstore/to_jsonb 规避新列漏保护；新增列时测试必须故意改写该列并证明触发器拒绝。

- [ ] **Step 5: 写 guarded down migration**

down migration 先锁七表；任一表存在行，或 outbox_events 中存在 proactive. / action-proposal. 前缀且未 delivered 的事件，均用 SQLSTATE 55000 拒绝回滚。确认空表后按 action proposal→run→grant→snapshot item→snapshot→policy→kill switch 的外键逆序删除触发器、函数、索引和表。

- [ ] **Step 6: 写并运行真实 PostgreSQL 18.4 集成测试**

测试必须覆盖：跨 Tenant/Workspace/Environment FK 拒绝；同 Workspace 下将 Environment A Grant 绑定 Environment B Incident、将 Environment A Run 绑定 Environment B Investigation、或把 Environment A Evidence/Asset 绑定到 Environment B ActionProposal 均失败；`published_targets(Scope,target_ref)` candidate key 可被 FK 建立；直接 SQL 创建 STALE/非 EXACT Snapshot Item 拒绝；重复 Trigger dedup 只产生一 Run；并发 Grant 激活仅一方成功；非法状态跳转、内容 UPDATE、DELETE/TRUNCATE 拒绝；ActionProposal 的 requester/approval/queue/credential/window/verification/compensation 列不存在且四种窄 intent 联合约束拒绝额外含义；Kill Switch 追加修订且旧行不变；有数据时 down 拒绝、清空后 down/up 可重放。

Run:

~~~bash
test -n "$AIOPS_TEST_POSTGRES_DSN"
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" \
  go test -race -count=1 ./internal/investigationgrant/postgres -run 'TestMigration'
~~~

Expected: PASS against PostgreSQL 18.4+ with zero required-test skips. Missing `AIOPS_TEST_POSTGRES_DSN` fails the prerequisite check, leaves this checkbox incomplete and forbids the task commit；SQLite, memory database and a diagnostic Skip are not completion evidence.

- [ ] **Step 7: 提交迁移**

~~~bash
git add migrations/000018_investigation_grants_proactive_policies.* internal/investigationgrant/postgres/migration*
git commit -m "feat: add grant and proactive policy schema"
~~~
