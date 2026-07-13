# Investigation Grants Gateway and Control Plane API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 READ Gateway Claim/Start/Heartbeat/Complete 四边界原子复验 Grant、预算、Runtime、Realm 与 Kill Switch，并交付严格 RBAC、OpenAPI 和 Control Plane 管理 API。

**Architecture:** Gateway 继续拥有认证和 Task mutation 的同一 pgx 事务，在既有 Runtime Authorizer 外组合不可绕过的 GrantGate；公共 API 仅返回安全 projection，以 OIDC Scope、显式权限、最近认证、Idempotency-Key 和强 ETag 治理。

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

- 顺序：3 / 7；必须按 README.md 固定顺序执行。
- 前置：02-repository-policy-workflow.md 的 Repository、Policy Service 和 Workflow 端口已实现。
- 交付给下一包：四边界 Gate、稳定拒绝码、唯一 OpenAPI/TypeScript schema 与严格 HTTP Manager 接口。
- 本包内仍按 Task 编号顺序执行；每个 Task 必须先看到预期失败，再写最小实现、跑通过并提交对应 commit。

### Task 6: Runner Gateway 四边界实时复验与原子预算门禁

**Files:**
- Create: internal/investigationgrant/gate.go
- Create: internal/investigationgrant/postgres/gate.go
- Create: internal/investigationgrant/postgres/gate_test.go
- Create: internal/investigationgrant/postgres/gate_integration_test.go
- Modify: internal/readtask/postgres/repository.go
- Modify: internal/readtask/postgres/runner_tx_test.go
- Modify: internal/readgateway/backend.go
- Create: internal/readgateway/grant_gate.go
- Create: internal/readgateway/backend_grant_test.go
- Modify: internal/readgateway/backend_test.go
- Modify: internal/runnergateway/read_routes.go
- Modify: internal/runnergateway/read_router_test.go
- Modify: internal/execution/action_queue.go
- Modify: internal/runneridentity/postgres/repository.go
- Modify: internal/runneridentity/postgres/repository_test.go
- Modify: cmd/control-plane/runner_gateway.go

**Interfaces:**
- Consumes: 000016 提供的 PublishedTarget、PublishedCapabilitySet、RuntimePublication、RunnerRealm/Binding 安全投影；Task 3 的 Grant/Kill Switch Repository；现有 execution.RunnerScope、readtask.Descriptor、readtask PostgreSQL 锁和 READ Admission。
- Produces: investigationgrant.Gate.AuthorizeTx(context.Context, pgx.Tx, Boundary, execution.RunnerScope, readtask.Descriptor, CompletionReservation) error；readtaskpostgres.ClaimRunnerAuthorizedTx；CompleteRunnerAuthorizedTx 的独立 BoundaryAuthorizer；Gateway Dependencies.GrantGate。

- [ ] **Step 1: 写四边界、关闭态短路和组合授权失败测试**

在 backend_grant_test.go 先写表驱动测试，必须证明 Claim、Start、Heartbeat、Complete 都在身份认证与 Task 变更的同一 pgx.Tx 内调用 GrantGate；Admission 关闭时零次 Begin、零次身份认证、零次 Gate；Release 不新增 Grant 扩权路径。

~~~go
func TestBackendRevalidatesGrantAtEveryRunnerBoundary(t *testing.T) {
    for _, boundary := range []investigationgrant.Boundary{
        investigationgrant.BoundaryClaim,
        investigationgrant.BoundaryStart,
        investigationgrant.BoundaryHeartbeat,
        investigationgrant.BoundaryComplete,
    } {
        t.Run(string(boundary), func(t *testing.T) {
            fixture := newGrantGatewayFixture(t)
            fixture.gate.denyAt = boundary
            err := fixture.invoke(boundary)
            if !errors.Is(err, readtask.ErrClaimsDisabled) {
                t.Fatalf("invoke(%s) error = %v, want fail-closed", boundary, err)
            }
            if fixture.gate.calls != []investigationgrant.Boundary{boundary} {
                t.Fatalf("gate calls = %#v", fixture.gate.calls)
            }
            if fixture.tx.commits != 0 || fixture.tx.rollbacks != 1 {
                t.Fatalf("transaction = commits %d rollbacks %d", fixture.tx.commits, fixture.tx.rollbacks)
            }
        })
    }
}

func TestClosedAdmissionShortCircuitsBeforeGrantAndDatabase(t *testing.T) {
    fixture := newGrantGatewayFixture(t)
    fixture.admission.CloseForTest()
    _, _, err := fixture.backend.Claim(context.Background(), fixture.identity, fixture.taskID)
    if !errors.Is(err, readtask.ErrClaimsDisabled) || fixture.database.begins != 0 || fixture.gate.callCount() != 0 {
        t.Fatalf("closed Claim = %v begins=%d gate=%d", err, fixture.database.begins, fixture.gate.callCount())
    }
}
~~~

Start 的组合测试固定顺序为 GrantGate 后 Connector Runtime Authorizer；Gate 拒绝时不得解析 Target/凭据。Heartbeat Gate 拒绝或 panic 必须复用既有 fail-closed 语义：事务提交 CANCELLED Attempt，返回 HeartbeatTerminate，而不是把内部 Grant 原因发送给 Runner。Complete 必须在输出 Schema/DLP 和 Evidence INSERT 之前执行 Gate；同一 Completion replay 也要实时复验，但不得重复累计预算。

- [ ] **Step 2: 运行 Gateway 测试并确认缺少 GrantGate**

Run: go test ./internal/readgateway ./internal/readtask/postgres -run 'Test(BackendRevalidatesGrant|ClosedAdmission|GrantAuthorizer)' -count=1

Expected: FAIL，错误包含 undefined: investigationgrant.Boundary 或 Dependencies 没有 GrantGate 字段。

- [ ] **Step 3: 定义不可绕过的边界接口和稳定拒绝分类**

在 internal/investigationgrant/gate.go 写入以下精确接口。GateDecision 只用于内部审计和低基数指标；Runner 协议一律折叠成 readtask.ErrClaimsDisabled 或 HeartbeatTerminate，绝不返回目标、资产或策略细节。

~~~go
package investigationgrant

import (
    "context"

    "github.com/jackc/pgx/v5"
    "github.com/seaworld008/aiops-system/internal/execution"
    "github.com/seaworld008/aiops-system/internal/readtask"
)

type Boundary string

const (
    BoundaryClaim Boundary = "CLAIM"
    BoundaryStart Boundary = "START"
    BoundaryHeartbeat Boundary = "HEARTBEAT"
    BoundaryComplete Boundary = "COMPLETE"
)

type DenialReason string

const (
    DenialGrantExpired DenialReason = "GRANT_EXPIRED"
    DenialGrantRevoked DenialReason = "GRANT_REVOKED"
    DenialGrantScopeMismatch DenialReason = "GRANT_SCOPE_MISMATCH"
    DenialBudgetExhausted DenialReason = "BUDGET_EXHAUSTED"
    DenialKillSwitchClosed DenialReason = "KILL_SWITCH_CLOSED"
    DenialAssetIneligible DenialReason = "ASSET_INELIGIBLE"
    DenialTargetDigestMismatch DenialReason = "TARGET_DIGEST_MISMATCH"
    DenialRuntimeDigestMismatch DenialReason = "RUNTIME_DIGEST_MISMATCH"
    DenialRealmMismatch DenialReason = "RUNNER_REALM_MISMATCH"
    DenialUnavailable DenialReason = "GATE_UNAVAILABLE"
)

type CompletionReservation struct {
    Outcome readtask.CompletionOutcome
    EvidenceBytes int64
    ModelTokens int64
}

type Gate interface {
    AuthorizeTx(
        context.Context,
        pgx.Tx,
        Boundary,
        execution.RunnerScope,
        readtask.Descriptor,
        CompletionReservation,
    ) error
}
~~~

新增 ErrDenied 与 DenialError，但 Error() 只能返回稳定 reason；不得 Wrap SQL、DSN、TargetRef、SourceKey 或 subject。增加 DenialReasonOf(error)；未知、nil Gate、panic、context deadline 和扫描不完整均返回 DenialUnavailable 并 fail closed。

- [ ] **Step 4: 把 Gate 注入 Task 锁内授权回调**

为 readtask/postgres 增加 ClaimAuthorizer 与 CompletionBoundaryAuthorizer。保留现有低层方法供仓储测试，但生产 Backend 只绑定带 Authorizer 的入口；架构测试扫描 cmd/ 与 internal/readgateway，禁止调用不带 Grant 回调的 ClaimRunnerTx/CompleteRunnerAuthorizedTx 旧签名。

~~~go
type ClaimAuthorizer func(context.Context, readtask.Descriptor) error

func (repository *Repository) ClaimRunnerAuthorizedTx(
    ctx context.Context,
    tx pgx.Tx,
    scope execution.RunnerScope,
    certificate readtask.CertificateBinding,
    taskID string,
    lease time.Duration,
    authorizer ClaimAuthorizer,
) (readtask.Claim, error) {
    if authorizer == nil {
        return readtask.Claim{}, readtask.ErrInvalidRequest
    }
    claim, err := repository.claimRunnerTx(ctx, tx, scope, certificate, taskID, lease)
    if err != nil {
        return readtask.Claim{}, err
    }
    descriptor := claim.Descriptor()
    if err := callClaimAuthorizer(ctx, authorizer, descriptor); err != nil {
        claim.Destroy()
        return readtask.Claim{}, err
    }
    return claim, nil
}

type CompletionBoundaryAuthorizer func(
    context.Context,
    readtask.Descriptor,
    readtask.CompletionOutcome,
) error
~~~

CompleteRunnerAuthorizedTx 增加 boundaryAuthorizer 参数，并在锁定 Task/Attempt/Investigation、验证 Fence、生成有界 Projection 后，任何 replay 分支和 Evidence 输出 authorizer 之前调用。BoundaryAuthorizer 不接收 Fence、Token、证书、原始 Evidence 或 Target；EvidenceBytes/ModelTokens 不信任 Runner 自报，最终预算由 Gate 在同一事务中从持久投影重算。Claim/Start 的授权异常回滚；Heartbeat 继续使用 authorizeHeartbeatRuntime 的 panic-to-TERMINATE；Complete 异常回滚并折叠为关闭态。

- [ ] **Step 5: 在 Backend 组合 Grant 和既有 Runtime Authorizer**

Dependencies 新增必填 GrantGate；New 遇到 typed nil 必须 ErrInvalidConfiguration。Backend 闭包捕获当前 requestTransaction.tx 和由认证得到的 RunnerScope，不能从 Runner body 重建 Scope。

~~~go
type Dependencies struct {
    Database             DB
    Identities           *runneridentitypostgres.Repository
    Tasks                *readtaskpostgres.Repository
    Admission            *Admission
    GrantGate            investigationgrant.Gate
    StartAuthorizer      StartAuthorizer
    HeartbeatAuthorizer  HeartbeatAuthorizer
    CompletionAuthorizer CompletionAuthorizer
}

func grantDescriptorAuthorizer(
    tx pgx.Tx,
    gate investigationgrant.Gate,
    boundary investigationgrant.Boundary,
    scope execution.RunnerScope,
    next func(context.Context, readtask.Descriptor) error,
) func(context.Context, readtask.Descriptor) error {
    return func(ctx context.Context, descriptor readtask.Descriptor) error {
        if err := authorizeGrantFailClosed(ctx, gate, tx, boundary, scope, descriptor, investigationgrant.CompletionReservation{}); err != nil {
            return readtask.ErrClaimsDisabled
        }
        if next == nil {
            return nil
        }
        return next(ctx, descriptor)
    }
}
~~~

Claim 使用 ClaimRunnerAuthorizedTx；Start/Heartbeat 传入上面的组合回调；Complete 传入独立 Grant BoundaryAuthorizer 和既有 typed Evidence authorizer。运行时 Target/Operation/Input Authorizer 不能删除、变成可选或被 Gate 成功结果替代。Release 只释放 LEASED Attempt，不延长授权，不新增工具调用，因此保持既有身份/Fence 路径。

- [ ] **Step 6: 写 PostgreSQL Gate 的漂移、预算和并发失败测试**

gate_test.go 使用 pgxmock/窄 Row 接口测试所有扫描错误 fail closed。gate_integration_test.go 用 PostgreSQL 18.4 建立真实 Snapshot、Grant、Run、Investigation、Task、Attempt、Runtime 与 Realm fixture，覆盖以下矩阵：

- Grant 非 ACTIVE、not_before、expires_at、撤销与 scope 不符；
- Snapshot digest、Target digest、Capability Set、Runtime Bundle、Task RuntimeBinding 任一不一致；
- 当前 Asset 变为 STALE/QUARANTINED 或 Mapping 非 EXACT；
- 固定 PublishedTarget/Capability 变为 REVOKED/CLOSED_BY_GATE/UNSUPPORTED，或固定 Runtime Publication 变为 DRIFTED/ROLLED_BACK；SUPERSEDED 但仍完整的旧发布继续允许活动 Grant 使用；
- 认证 Runner 的 Realm、Adapter Family、Network Zone、Scope Revision 或 binding 不匹配；
- GLOBAL、WORKSPACE、ENVIRONMENT、ASSET、CONNECTION、CAPABILITY 任一级最新 revision closed；旧 revision closed 但新 revision open 时允许；
- Duration、distinct Task、单 Source 活动 Attempt、Evidence bytes、Model tokens 任一达到上限；
- 两个事务并发 Claim 同一 Source 且预算为 1，恰好一个允许；
- Complete replay 不重复计数，Evidence 预算使用将要写入的规范化投影字节数并防整数溢出。

~~~go
func TestGateSerializesConcurrentSourceReservations(t *testing.T) {
    fixture := newGateIntegrationFixture(t, Budget{MaxToolCalls: 2, MaxConcurrencyPerSource: 1})
    results := runConcurrentClaims(t, fixture, fixture.taskA, fixture.taskB)
    allowed, denied := 0, 0
    for _, err := range results {
        if err == nil {
            allowed++
        } else if errors.Is(err, investigationgrant.ErrDenied) &&
            investigationgrant.DenialReasonOf(err) == investigationgrant.DenialBudgetExhausted {
            denied++
        }
    }
    if allowed != 1 || denied != 1 {
        t.Fatalf("allowed=%d denied=%d results=%v", allowed, denied, results)
    }
}
~~~

- [ ] **Step 7: 实现单次锁序、实时安全覆盖和派生预算查询**

Gate 查询顺序固定为 Task/Attempt 已由 readtask 锁定 → proactive_run → Grant FOR UPDATE → Snapshot Item → 当前 Asset/Connection/Target/Capability/Runtime → Runner Realm/Binding → 六级最新 Kill Switch。所有边界使用 PostgreSQL clock_timestamp()；不能使用应用时钟判断有效期。

预算使用量不能新增浏览器可写计数器，必须在 Grant 行锁下从事实派生：

~~~sql
WITH current_tasks AS (
    SELECT tia.task_id, tia.status, asi.source_key
    FROM proactive_runs pr
    JOIN investigation_grants ig
      ON (ig.tenant_id, ig.workspace_id, ig.environment_id, ig.id) =
         (pr.tenant_id, pr.workspace_id, pr.environment_id, pr.grant_id)
    JOIN tool_invocations ti
      ON (ti.tenant_id, ti.workspace_id, ti.investigation_id) =
         (pr.tenant_id, pr.workspace_id, pr.investigation_id)
    JOIN investigation_task_attempts tia
      ON (tia.tenant_id, tia.workspace_id, tia.investigation_id, tia.task_id) =
         (ti.tenant_id, ti.workspace_id, ti.investigation_id, ti.id)
    JOIN asset_snapshot_items asi
      ON (asi.tenant_id, asi.workspace_id, asi.environment_id, asi.snapshot_id, asi.target_digest) =
         (ig.tenant_id, ig.workspace_id, ig.environment_id, ig.asset_snapshot_id, ti.target_digest)
    WHERE ig.id = $1::uuid
      AND tia.status IN ('LEASED','RUNNING','COMPLETED')
)
SELECT
    COUNT(DISTINCT task_id) FILTER (WHERE task_id <> $3::uuid),
    COUNT(DISTINCT task_id) FILTER (
        WHERE task_id <> $3::uuid AND source_key = $2 AND status IN ('LEASED','RUNNING')
    )
FROM current_tasks;
~~~

tool_invocations.target_digest 使用 000013 已存在的显式不可变 Runtime binding 列；不得把 digest 塞进 JSONB。Evidence bytes 精确使用 SUM(octet_length(evidence.payload_document))；Model tokens 精确使用 SUM(model_calls.input_tokens + model_calls.output_tokens)；两者只统计同一 Grant 关联 Investigation。Snapshot target_digest 必须精确匹配一条 Snapshot Item，零条或多条都以 GRANT_SCOPE_MISMATCH fail closed。Source 并发只统计 LEASED/RUNNING，不统计 COMPLETED/RELEASED/EXPIRED/CANCELLED。

实时安全覆盖只比较当前安全状态，不要求当前发布摘要等于 Grant 摘要；正常新发布不改变活动 Grant 的固定语义。只有 REVOKED/DRIFTED、资产 STALE/QUARANTINED、Mapping 非 EXACT、Realm/Scope 漂移或 Kill Switch closed 才停止固定的旧 Runtime。

- [ ] **Step 8: 绑定 Control Plane 并锁死 SHADOW/Admission 不变量**

cmd/control-plane/runner_gateway.go 构造 PostgreSQL Gate 并注入 READ Backend；不能新增 ALLOW_PROACTIVE_READ、SKIP_GRANT_CHECK 等环境变量。SHADOW Run 创建并立即终结仅用于审计的 Snapshot/Grant，但不得创建 Investigation/Task，因此没有任何可被 Gateway Claim 的记录。既有 READ Admission 默认关闭，测试断言即使存在 ACTIVE Grant 也返回 claims disabled。

- [ ] **Step 9: 运行四边界、race 与真实并发测试**

Run: go test -race -shuffle=on -count=1 ./internal/readgateway ./internal/readtask/postgres ./internal/runnergateway ./internal/runneridentity/postgres

Expected: PASS；Heartbeat Grant 拒绝返回 TERMINATE，其他边界只返回有界 Runner Problem，不出现内部 DenialReason 详情。

Run:

~~~bash
test -n "$AIOPS_TEST_POSTGRES_DSN"
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" \
  go test -race -count=1 ./internal/investigationgrant/postgres -run 'TestGate'
~~~

Expected: PASS against PostgreSQL 18.4+ with zero required-test skips. Missing `AIOPS_TEST_POSTGRES_DSN` leaves the checkbox incomplete and forbids commit；a Skip or memory implementation cannot substitute for the concurrency proof.

- [ ] **Step 10: 提交四边界门禁**

~~~bash
git add internal/investigationgrant/gate.go internal/investigationgrant/postgres/gate* internal/readtask/postgres internal/readgateway internal/runnergateway/read_routes.go internal/runnergateway/read_router_test.go internal/execution/action_queue.go internal/runneridentity/postgres cmd/control-plane/runner_gateway.go
git commit -m "feat: enforce grants at read runner boundaries"
~~~

### Task 7: VIEWER/RBAC、最近认证与 Control Plane OpenAPI 合同

**Files:**
- Modify: internal/authn/authenticator.go
- Modify: internal/authn/authenticator_test.go
- Modify: internal/authz/authorizer.go
- Modify: internal/authz/authorizer_test.go
- Modify: api/openapi/control-plane-v1.yaml
- Create: api/openapi/control-plane-v1-proactive_test.go
- Modify: web/src/shared/api/schema.d.ts

**Interfaces:**
- Consumes: 既有 authn.Principal/authz.Authorizer、Task 4 的 Policy/Run、Task 3 的 Grant/Kill Switch；前序前端基础设施固定的 openapi-typescript 命令。
- Produces: RoleViewer；PermissionInvestigationGrantRead/Revoke、PermissionProactivePolicyRead/Manage、PermissionDiagnosticRun；主动策略、Run、Grant、Kill Switch 的唯一公共 OpenAPI 合同和生成类型。

- [ ] **Step 1: 写角色矩阵与最近认证失败测试**

在 authenticator_test.go 增加 VIEWER 标准化用例；在 authorizer_test.go 用以下矩阵证明权限是显式 allowlist，未知角色/权限 fail closed，ADMIN 不自动获得 DIAGNOSTIC_RUN。

~~~go
func TestProactivePolicyRoleMatrix(t *testing.T) {
    tests := []struct {
        role authn.Role
        allowed []authz.Permission
    }{
        {authn.RoleViewer, nil},
        {authn.RoleSRE, []authz.Permission{
            authz.PermissionProactivePolicyRead,
            authz.PermissionInvestigationGrantRead,
            authz.PermissionDiagnosticRun,
        }},
        {authn.RoleServiceOwner, []authz.Permission{authz.PermissionProactivePolicyRead}},
        {authn.RoleApprover, nil},
        {authn.RoleAuditor, []authz.Permission{
            authz.PermissionProactivePolicyRead,
            authz.PermissionInvestigationGrantRead,
        }},
        {authn.RoleAdmin, []authz.Permission{
            authz.PermissionProactivePolicyRead,
            authz.PermissionProactivePolicyManage,
            authz.PermissionInvestigationGrantRead,
            authz.PermissionInvestigationGrantRevoke,
        }},
    }
    assertExactRoleMatrix(t, tests)
}

func TestSensitiveProactiveMutationsRequireRecentAuthentication(t *testing.T) {
    for _, permission := range []authz.Permission{
        authz.PermissionProactivePolicyManage,
        authz.PermissionInvestigationGrantRevoke,
    } {
        principal := validPrincipal(authn.RoleAdmin)
        principal.AuthenticatedAt = fixedNow.Add(-6 * time.Minute)
        request := authz.Request{
            Permission: permission, WorkspaceID: workspaceID, EnvironmentID: environmentID,
            RequireRecentAuthentication: permission == authz.PermissionProactivePolicyManage,
        }
        err := testAuthorizer(t, fixedNow).Authorize(principal, request)
        if !errors.Is(err, authz.ErrReauthenticationRequired) {
            t.Fatalf("Authorize(%s) error = %v", permission, err)
        }
    }
}
~~~

Service Owner 的策略创建/修订属于“提议”能力，但本阶段没有独立 PROACTIVE_POLICY_PROPOSE 权限与审批流，因此只读，不能用 MANAGE 暗中发布。SRE 的 DIAGNOSTIC_RUN 必须带自身 ServiceID 约束；ADMIN 没有该权限，保持“治理不自动等于业务调查”。

- [ ] **Step 2: 运行权限测试并确认失败**

Run: go test ./internal/authn ./internal/authz -run 'Test(ProactivePolicyRoleMatrix|SensitiveProactive|Viewer)' -count=1

Expected: FAIL，错误包含 undefined: authn.RoleViewer 或 undefined: authz.PermissionProactivePolicyRead。

- [ ] **Step 3: 实现显式权限与最近认证表**

新增以下常量并更新 normalizeRoles、roleAllows、requiresService、requiresRecentAuthentication；不得用字符串前缀、角色层级或“ADMIN 全允许”。authz.Request 增加仅由服务端调用者设置的 RequireRecentAuthentication bool，使同一 MANAGE 权限下只有 Publish/Disable/Kill Switch 等具体高风险动作触发最近认证，创建草稿和 Preview 不被过度门禁。

~~~go
const (
    PermissionDiagnosticRun             Permission = "DIAGNOSTIC_RUN"
    PermissionInvestigationGrantRead    Permission = "INVESTIGATION_GRANT_READ"
    PermissionInvestigationGrantRevoke  Permission = "INVESTIGATION_GRANT_REVOKE"
    PermissionProactivePolicyRead       Permission = "PROACTIVE_POLICY_READ"
    PermissionProactivePolicyManage     Permission = "PROACTIVE_POLICY_MANAGE"
)

func requiresRecentAuthentication(permission Permission) bool {
    switch permission {
    case PermissionActionApprove,
        PermissionExecutionRequest,
        PermissionCredentialRevocationRequeue,
        PermissionCredentialRevocationConfirm,
        PermissionInvestigationGrantRevoke:
        return true
    default:
        return false
    }
}
~~~

Authorize 在 requiresRecentAuthentication(permission) || request.RequireRecentAuthentication 时执行同一 1–15 分钟窗口检查。ProactivePolicyManage 覆盖创建修订、Preview、Publish、Disable 与六级 Kill Switch 变更：Create/Revision/Preview 使用 Manage 且 RequireRecentAuthentication=false，Publish/Disable/Kill Switch 使用 Manage 且 true；Grant revoke 由权限本身强制最近认证。HTTP body 不能设置该 bool。

- [ ] **Step 4: 先写 OpenAPI 合同结构失败测试**

合同测试解析 YAML 后断言所有规范路径存在；workspace 路径参数与 environment_id 查询都 required；所有写接口声明 Idempotency-Key，修订/发布/禁用/撤销/Kill Switch 声明 If-Match；所有响应引用 Problem；禁止 schema property 名匹配 secret|token|password|endpoint|dsn|vault|pem|raw_error|sql|header。

~~~go
func TestProactiveControlPlaneContractIsScopedAndSecretFree(t *testing.T) {
    document := loadControlPlaneOpenAPI(t)
    for _, path := range []string{
        "/api/v1/workspaces/{workspace_id}/proactive-policies",
        "/api/v1/workspaces/{workspace_id}/proactive-policies/{policy_id}",
        "/api/v1/workspaces/{workspace_id}/proactive-policies/{policy_id}/revisions",
        "/api/v1/workspaces/{workspace_id}/proactive-policies/{policy_id}/revisions/{revision}:preview",
        "/api/v1/workspaces/{workspace_id}/proactive-policies/{policy_id}/revisions/{revision}:publish",
        "/api/v1/workspaces/{workspace_id}/proactive-policies/{policy_id}:disable",
        "/api/v1/workspaces/{workspace_id}/proactive-policies/{policy_id}:run",
        "/api/v1/workspaces/{workspace_id}/proactive-runs",
        "/api/v1/workspaces/{workspace_id}/proactive-runs/{run_id}",
        "/api/v1/workspaces/{workspace_id}/investigation-grants/{grant_id}",
        "/api/v1/workspaces/{workspace_id}/investigation-grants/{grant_id}:revoke",
        "/api/v1/workspaces/{workspace_id}/kill-switches",
        "/api/v1/workspaces/{workspace_id}/kill-switches:revise",
    } {
        assertPath(t, document, path)
    }
    assertNoSensitiveSchemaProperties(t, document)
}
~~~

- [ ] **Step 5: 定义主动策略、Run、Grant 与 Kill Switch 安全 DTO**

在唯一 api/openapi/control-plane-v1.yaml 增量添加 path 和 component；不能创建第二份 YAML。每个资源包含 id、environment_id、version、etag、orthogonal statuses、effective_actions；摘要只返回 64 位 digest，Grant Issuer 对 Human 只返回 actor_type=HUMAN 与安全 subject display，不回显 OIDC claims。

~~~yaml
ProactivePolicy:
  type: object
  additionalProperties: false
  required:
    - id
    - environment_id
    - revision
    - name
    - trigger
    - mode
    - status
    - policy_digest
    - version
    - etag
    - effective_actions
  properties:
    id: { type: string, format: uuid }
    environment_id: { type: string, format: uuid }
    revision: { type: integer, format: int64, minimum: 1 }
    name: { type: string, minLength: 1, maxLength: 160 }
    trigger: { $ref: '#/components/schemas/ProactiveTrigger' }
    mode: { type: string, enum: [SHADOW, READ_ONLY] }
    status: { type: string, enum: [DRAFT, SHADOW, READ_ONLY, DISABLED, SUPERSEDED] }
    policy_digest: { $ref: '#/components/schemas/Sha256Digest' }
    version: { type: integer, format: int64, minimum: 1 }
    etag: { type: string, pattern: '^"[a-z0-9:-]{1,128}"$' }
    effective_actions:
      type: array
      maxItems: 16
      uniqueItems: true
      items:
        type: string
        enum: [VIEW, CREATE_REVISION, PREVIEW, PUBLISH, DISABLE, RUN]

InvestigationGrant:
  type: object
  additionalProperties: false
  required:
    - id
    - environment_id
    - status
    - grant_digest
    - asset_snapshot_digest
    - capability_snapshot_digest
    - runtime_bundle_digest
    - budget
    - usage
    - not_before
    - expires_at
    - effective_kill_switches
    - effective_actions
  properties:
    id: { type: string, format: uuid }
    environment_id: { type: string, format: uuid }
    status: { type: string, enum: [ISSUED, ACTIVE, COMPLETED, EXPIRED, REVOKED, FAILED] }
    grant_digest: { $ref: '#/components/schemas/Sha256Digest' }
    asset_snapshot_digest: { $ref: '#/components/schemas/Sha256Digest' }
    capability_snapshot_digest: { $ref: '#/components/schemas/Sha256Digest' }
    runtime_bundle_digest: { $ref: '#/components/schemas/Sha256Digest' }
    budget: { $ref: '#/components/schemas/GrantBudget' }
    usage: { $ref: '#/components/schemas/GrantUsage' }
    not_before: { type: string, format: date-time }
    expires_at: { type: string, format: date-time }
    effective_kill_switches:
      type: array
      minItems: 3
      maxItems: 6
      items: { $ref: '#/components/schemas/EffectiveKillSwitch' }
    effective_actions:
      type: array
      uniqueItems: true
      items: { type: string, enum: [VIEW, REVOKE] }
~~~

ProactivePolicyDetail 另含 Selector、Capability 摘要、预算、修订、运行链；PreviewResponse 返回 selected_count、excluded_count、按稳定 reason 聚合和最多 100 条安全资产摘要。ProactiveRun 独立返回 run_status、grant_status、asset_snapshot_digest、trigger、调用/证据/模型/凭据撤销摘要、failure_code、audit_id。Kill Switch 返回六级 current revision、closed、reason、updated_at 和 effective_closed；不返回内部 selector、target 或凭据。

- [ ] **Step 6: 固定严格请求头、并发和 Problem 合同**

所有 POST requestBody 均 additionalProperties:false。写请求 Idempotency-Key 为必填、1–128 字节小写安全语法；If-Match 使用强 ETag。创建 Policy/Revision 返回 201，Preview/Run 返回 202，Publish/Disable/Revoke/Kill Switch revise 返回 200。412 为 etag_mismatch，409 为 state_conflict/idempotency_conflict，401 最近认证带 WWW-Authenticate，403 不泄露对象存在性，404 统一 resource_not_found。

- [ ] **Step 7: 生成唯一 TypeScript 类型并做零漂移检查**

复用 Phase 1 已固定的生成命令，不修改 `web/package.json`：

~~~json
{
  "scripts": {
    "generate:api": "openapi-typescript ../api/openapi/control-plane-v1.yaml -o src/shared/api/schema.d.ts",
    "generate:api:check": "sh ./scripts/check-generated-api.sh"
  }
}
~~~

Run: go test ./api/openapi -run 'TestProactive' -count=1

Expected: PASS；全部路径、header、DTO 和敏感字段扫描通过。

Run: pnpm --dir web generate:api && pnpm --dir web generate:api:check && pnpm --dir web typecheck

Expected: PASS；只更新 web/src/shared/api/schema.d.ts，类型中包含 ProactivePolicy、ProactiveRun、InvestigationGrant、EffectiveKillSwitch。

- [ ] **Step 8: 提交 RBAC 与合同**

~~~bash
git add internal/authn internal/authz api/openapi/control-plane-v1.yaml api/openapi/control-plane-v1-proactive_test.go web/src/shared/api/schema.d.ts
git commit -m "feat: define proactive control plane contract"
~~~

### Task 8: 严格主动策略、Run、Grant 与 Kill Switch HTTP API

**Files:**
- Create: internal/proactiveadmin/service.go
- Create: internal/proactiveadmin/service_test.go
- Create: internal/httpapi/proactive_dto.go
- Create: internal/httpapi/proactive_policies.go
- Create: internal/httpapi/proactive_policies_test.go
- Create: internal/httpapi/proactive_runs.go
- Create: internal/httpapi/proactive_runs_test.go
- Create: internal/httpapi/investigation_grants.go
- Create: internal/httpapi/investigation_grants_test.go
- Create: internal/httpapi/kill_switches.go
- Create: internal/httpapi/kill_switches_test.go
- Modify: internal/httpapi/router.go
- Modify: internal/httpapi/router_test.go
- Modify: cmd/control-plane/main.go

**Interfaces:**
- Consumes: authn.Principal、authz.Authorizer；Task 3/4 的 Repository 与 Service；Task 5 TriggerStarter；Task 7 OpenAPI DTO。
- Produces: ProactivePolicyManager、ProactiveRunReader、InvestigationGrantManager、KillSwitchManager 窄 HTTP 端口；全部 workspace/environment scoped 且返回安全 projection。

- [ ] **Step 1: 写 BOLA、严格解码、幂等与错误清洗失败测试**

每个 Handler 测试必须通过 NewRouter，不直接调用私有函数；覆盖无认证、跨 Workspace/Environment、typed nil 依赖、未知/重复字段、尾随 JSON、错误 Content-Type、超长 body、重复 query、Cursor 伪造、缺 Idempotency-Key、弱/缺 If-Match、旧认证、ETag 竞争和存储错误 canary。

~~~go
func TestProactivePolicyPublishIsScopedReauthenticatedAndSecretFree(t *testing.T) {
    manager := &fakeProactiveManager{publishResult: validPolicyProjection()}
    router := httpapi.NewRouter(httpapi.Dependencies{
        Authenticator: fakeAuthenticator{principal: adminPrincipal(fixedNow)},
        ProactivePolicies: manager,
    })
    request := httptest.NewRequest(http.MethodPost,
        "/api/v1/workspaces/"+workspaceID+"/proactive-policies/"+policyID+
            "/revisions/3:publish?environment_id="+environmentID,
        strings.NewReader(`{"reason":"enable production read-only"}`))
    request.Header.Set("Content-Type", "application/json")
    request.Header.Set("Idempotency-Key", "publish:policy:3")
    request.Header.Set("If-Match", `"policy:3:7"`)
    response := httptest.NewRecorder()
    router.ServeHTTP(response, request)
    if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "secret-canary") {
        t.Fatalf("publish response = %d %s", response.Code, response.Body.String())
    }
}

func TestCrossEnvironmentGrantIsIndistinguishableFromMissing(t *testing.T) {
    manager := &fakeGrantManager{getErr: proactiveadmin.ErrNotFound}
    response := serveGrantGet(t, manager, viewerPrincipal(), otherEnvironmentID)
    if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), grantID) {
        t.Fatalf("cross-scope response = %d %s", response.Code, response.Body.String())
    }
}
~~~

- [ ] **Step 2: 运行 HTTP 测试并确认路由缺失**

Run: go test ./internal/httpapi ./internal/proactiveadmin -run 'Test(Proactive|Grant|KillSwitch|CrossEnvironment)' -count=1

Expected: FAIL，错误包含 undefined: proactiveadmin 或返回 route_not_found。

- [ ] **Step 3: 定义应用层命令、查询与安全 Projection**

proactiveadmin/service.go 只接收 Principal 与强类型 Scope，不接收 http.Request。所有 Item 先用 Tenant/Workspace/Environment 复合键读取，再授权，Repository 对无权对象与不存在对象都返回 ErrNotFound。

~~~go
type Scope struct {
    TenantID string
    WorkspaceID string
    EnvironmentID string
}

type PolicyManager interface {
    List(context.Context, authn.Principal, ListPolicies) (PolicyPage, error)
    Create(context.Context, authn.Principal, CreatePolicy) (PolicyProjection, error)
    Get(context.Context, authn.Principal, PolicyItem) (PolicyDetailProjection, error)
    CreateRevision(context.Context, authn.Principal, CreateRevision) (PolicyProjection, error)
    Preview(context.Context, authn.Principal, PreviewRevision) (PreviewProjection, error)
    Publish(context.Context, authn.Principal, PublishRevision) (PolicyProjection, error)
    Disable(context.Context, authn.Principal, DisablePolicy) (PolicyProjection, error)
    Run(context.Context, authn.Principal, ManualRun) (RunProjection, error)
}

type GrantManager interface {
    Get(context.Context, authn.Principal, GrantItem) (GrantProjection, error)
    Revoke(context.Context, authn.Principal, RevokeGrant) (GrantProjection, error)
}
~~~

Command 明确包含 IdempotencyKey、ExpectedVersion、Reason；请求 Hash 使用 JCS 并绑定 Scope、资源 ID、revision 和 body。相同 key/hash 返回原 immutable response，不重新授权或重新启动 Workflow；相同 key/不同 hash 返回 ErrIdempotencyConflict。effective_actions 由应用服务根据具体资源状态和 Authorizer 计算，前端不得推断角色。

- [ ] **Step 4: 实现共享严格解析与 Cursor/ETag**

在 proactive_dto.go 实现唯一 strictJSON：Content-Type 必须恰好一个 application/json；MaxBytesReader 上限 64 KiB；decoder.DisallowUnknownFields；拒绝重复字段需要 token scanner，拒绝尾随值；所有空 body 动作上限 1 byte 且必须长度 0。Query 只接受声明键，每键恰好一个非空值。

Cursor wire 固定 v1、created_at RFC3339Nano UTC、resource_id UUID，经 base64.RawURLEncoding.Strict 编码，最大 512；排序固定 created_at DESC, id DESC。ETag 固定 `"{kind}:{revision}:{version}"`，只接受单个强 If-Match，不接受 * 或 W/。

- [ ] **Step 5: 实现规范路由和状态码**

router.go 增加以下认证路由；workspace 来自 URL，environment_id 是必填 query，tenant 只能来自认证/服务端映射，不能由 Header/body 提供。

~~~go
router.Route("/api/v1/workspaces/{workspaceID}", func(router chi.Router) {
    router.Use(authenticationMiddleware(deps.Authenticator))
    router.Get("/proactive-policies", proactivePolicyListHandler(deps.ProactivePolicies))
    router.Post("/proactive-policies", proactivePolicyCreateHandler(deps.ProactivePolicies))
    router.Get("/proactive-policies/{policyID}", proactivePolicyGetHandler(deps.ProactivePolicies))
    router.Post("/proactive-policies/{policyID}/revisions", proactivePolicyRevisionHandler(deps.ProactivePolicies))
    router.Post("/proactive-policies/{policyID}/revisions/{revision}:preview", proactivePolicyPreviewHandler(deps.ProactivePolicies))
    router.Post("/proactive-policies/{policyID}/revisions/{revision}:publish", proactivePolicyPublishHandler(deps.ProactivePolicies))
    router.Post("/proactive-policies/{policyID}:disable", proactivePolicyDisableHandler(deps.ProactivePolicies))
    router.Post("/proactive-policies/{policyID}:run", proactivePolicyRunHandler(deps.ProactivePolicies))
    router.Get("/proactive-runs", proactiveRunListHandler(deps.ProactiveRuns))
    router.Get("/proactive-runs/{runID}", proactiveRunGetHandler(deps.ProactiveRuns))
    router.Get("/investigation-grants/{grantID}", investigationGrantGetHandler(deps.InvestigationGrants))
    router.Post("/investigation-grants/{grantID}:revoke", investigationGrantRevokeHandler(deps.InvestigationGrants))
    router.Get("/kill-switches", killSwitchListHandler(deps.KillSwitches))
    router.Post("/kill-switches:revise", killSwitchReviseHandler(deps.KillSwitches))
})
~~~

所有这些路径设置 Cache-Control:no-store、X-Content-Type-Options:nosniff。Preview 与 Run 返回 202 和可轮询 run/operation ID；不伪造同步完成。错误映射固定：400 invalid_request，401 authentication_required/reauthentication_required，403 operation_forbidden，404 resource_not_found，409 state_conflict/idempotency_conflict，412 etag_mismatch，413 payload_too_large，415 unsupported_media_type，503 management_unavailable，500 management_failed；每个 Problem 含 trace_id，不含存储错误正文。

- [ ] **Step 6: 实现撤销、Kill Switch 和 Run 的事务语义**

Grant revoke 在同一事务锁 Grant，校验 If-Match，追加 Audit/Outbox，ACTIVE/ISSUED→REVOKED；重放返回原版本。它不直接删除 Attempt，后续 Heartbeat Gate 终止；撤销 Worker 处理 READ credential revocation，不得复用 WRITE Credential 权限。

Kill Switch revise 追加新 revision，按 scope_level 严格验证 subject：GLOBAL 无 workspace/environment subject；WORKSPACE 只 workspace；ENVIRONMENT 到 environment；ASSET/CONNECTION/CAPABILITY 必须加载同 Scope 资源。关闭/重新打开都要 recent auth、If-Match、Idempotency-Key、reason 和审计。

Manual Run 仅 DIAGNOSTIC_RUN，必须 service_id 属于 Principal，调用 Task 5 同一 TriggerStarter；Handler 不直接创建 Investigation/Grant 或调用 Temporal client。

- [ ] **Step 7: 接线与反射型安全扫描**

cmd/control-plane/main.go 注入真实 PostgreSQL Repository、Authorizer、Starter。增加 DTO 反射测试与 JSON canary，扫描响应、log recorder、Problem、audit fixture 均不得出现 Secret、Token、PEM、DSN、endpoint、Vault Path、SQL 或 raw error。Dependencies typed nil 返回 503，不 panic。

- [ ] **Step 8: 运行 HTTP、race 和路由合同测试**

Run: go test -race -shuffle=on -count=1 ./internal/proactiveadmin ./internal/httpapi ./internal/authn ./internal/authz

Expected: PASS；BOLA、最近认证、严格 JSON、Cursor、ETag、幂等和安全 canary 全部通过。

Run: go test ./... -run 'Test.*(Route|OpenAPI|Architecture).*' -count=1

Expected: 在无嵌套 .worktrees 的独立执行 worktree 中 PASS；若在当前共享主目录运行，必须记录既有 worktree 扫描限制，不能删除用户目录伪造结果。

- [ ] **Step 9: 提交 Control Plane API**

~~~bash
git add internal/proactiveadmin internal/httpapi cmd/control-plane/main.go
git commit -m "feat: expose proactive investigation governance api"
~~~
