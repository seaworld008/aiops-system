# Evidence-backed ActionProposal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把可信 Evidence 转换为 append-only、恒为 `PROPOSAL_ONLY` 的类型化 ActionProposal，同时证明模型永远不能借提案获得 Scope、授权、审批、排队、凭据或执行语义。

**Architecture:** Control Plane 先在 PostgreSQL 事务中从 Investigation、Evidence、不可变 Asset Snapshot 与当前发布能力解析内容寻址 ActionProposal Catalog，再把安全 Evidence 摘要及可提议的 `action_type`/窄 intent schema 交给模型选择。严格 Decoder 只接受 `action_type + typed intent` 或无建议 Finding；Evidence IDs、Scope、目标绑定、Catalog/Evidence digest 与 Actor attribution 全由服务端补齐并追加写入 `action_proposals`。Phase 4 生成路径不直接或自动创建 ActionPlan/queue item；Phase 7 仅能在经认证的人通过完整 T/W/E/S URL Scope 明确发起后，在其封存事务中通过内部 Handoff Loader 重载可信 ActionProposal/Catalog/Evidence/Snapshot、复验摘要并派生封存新的 ActionPlan。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、pgx/v5、go-chi/v5、JCS/SHA-256、现有 Model Router、RFC 9457；OpenAPI 3.1、openapi-typescript 7.13.0；真实 Control Plane/PostgreSQL/Keycloak Server 26.6.3 E2E。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- 实现基线固定为 main@ad50d9f；开始执行时先创建独立 worktree，且该模块根下不能包含嵌套 .worktrees。
- 000018 migration 的唯一文件仍是 `migrations/000018_investigation_grants_proactive_policies.*.sql`，七表完整 DDL 由 `01-domain-schema.md` Task 2 一次创建；本包不得创建 000018b 或平行迁移。
- 模型不是 Principal，也不是 Scope、Catalog、Actor attribution、授权、审批或队列事实源。
- 模型可输出的业务内容仅为服务端目录内的 `action_type` 与该类型极窄 typed intent；Evidence IDs 与 Evidence digest 完全由服务端固定，模型不得输出或选择。
- `K8S_ROLLOUT_RESTART` intent 无参数；`K8S_SCALE` 只有 `desired_replicas 0..100`；`GITOPS_REVERT` 只有 `reason_code=REGRESSION|FAILED_DEPLOYMENT`；`AWX_SERVICE_RESTART` 只有常量 `restart_scope=SERVICE_INSTANCE`。
- ActionProposal 恒为 `PROPOSAL_ONLY`，没有执行、审批、排队、凭据、验证或补偿权，不能直接/自动转换成 ActionPlan，也不能作为任何执行授权。
- Phase 4 公共 API 只有 ActionProposal/Catalog 的 GET，不提供创建 ActionPlan、接受 ActionProposal、派生 Plan、审批、排队或执行 mutation。
- Phase 7 可以在经认证的人通过 `POST /api/v1/workspaces/{workspace_id}/environments/{environment_id}/services/{service_id}/action-plans` 明确发起后开启封存事务并调用内部 Handoff Loader；Tenant 只来自认证 Principal，Workspace/Environment/Service 只来自 path。Loader 必须在该同一事务按完整 T/W/E/S Scope 与 ActionProposal ID 锁定并重载可信 ActionProposal、Catalog、Evidence、Snapshot 和摘要，复验当前资格后，Phase 7 才能派生并封存全新的 ActionPlan。Loader 前不得预读 Proposal 来获得 ServiceID；客户端回传的 body Scope/Catalog/Evidence/Plan 内容不能成为事实源，任一漂移使整笔事务回滚并升级人工。
- 模型不得提供或覆盖 requester、approver、approval、queue、Scope、Tenant、Workspace、Environment、Service、Asset、Target、Runtime、credential、window、verification、compensation、endpoint、Header、Body、命令、脚本或 SQL。
- 无目录匹配、Evidence 不足、多个目标、置信不确定、模型越权、Catalog/Evidence/Asset 漂移都只形成 append-only Human Review Finding；不能“取最可能值”或降级为自由文本 ActionProposal。
- 浏览器和公共 API 只能读取安全 Catalog/ActionProposal/Finding projection；本阶段没有公开生成、接受、转换、批准、排队或执行 ActionProposal 的 mutation API。
- 所有跨对象读取与追加写入必须以 Tenant/Workspace/Environment 复合 Scope 约束；跨 Scope 返回统一安全 `404`，不得泄露对象存在性。
- `action_proposals` 禁止 UPDATE、DELETE、TRUNCATE；更正只能写新的 ActionProposal 或 Human Review Finding，并用 supersedes digest 在审计中关联，不能改旧行。
- ActionProposal 生成前后必须在同一事务重新解析 Evidence content hash、Snapshot、Catalog revision/digest、Asset 状态与能力状态；任一漂移 fail closed。
- 公开 DTO、日志、Trace、模型输入输出存档和审计不得包含 Secret、Token、PEM、DSN、内部 endpoint、原始上游错误、任意 SQL 或完整查询结果。
- 所有公共列表使用不透明 Cursor 与稳定排序；错误使用 RFC 9457、稳定 code 和 trace_id。
- 生产装配必须注入 PostgreSQL Repository、Catalog Resolver、真实 Model Router、Audit Finding Recorder 和 Handoff Loader；nil/typed nil、panic 或依赖不可用使生成停止，不得回退内存或静态 ActionProposal。
- fake model、memory repository 和测试 Catalog 只能位于 `*_test.go` 或 `test/e2e`，不能进入 `cmd/` 或生产依赖装配。

---

## Package Position

- 顺序：4 / 7；必须按 README.md 固定顺序执行。
- 前置：`01-domain-schema.md` 已创建七表 000018；`02-repository-policy-workflow.md` 的 Snapshot/Grant/Run 已完成；`03-gateway-api.md` 的 OIDC、RBAC、OpenAPI 基础和安全 HTTP 约定已通过。
- 交付给下一包：ActionProposal Catalog、严格生成边界、append-only Repository、只读 API、Handoff Loader、Mutation/Overreach/Drift 与真实 E2E 证据。
- Phase 7 只能把已持久 ActionProposal 当作不可信建议输入：经认证的人明确发起后，由 Phase 7 开启封存事务并通过 `HandoffLoader.LoadTrustedForActionPlanDerivation` 在同一事务重载可信 ActionProposal/Catalog/Evidence/Snapshot、复验摘要与当前门禁，再派生并封存全新不可变 ActionPlan 后原子提交；Policy/Approval/queue/credential/verification 仍是 ActionPlan 后续独立事实。

### Task 9: ActionProposal Catalog、窄 typed intent 与模型生成边界

**Files:**
- Create: internal/actionproposal/types.go
- Create: internal/actionproposal/types_test.go
- Create: internal/actionproposal/catalog.go
- Create: internal/actionproposal/catalog_test.go
- Create: internal/actionproposal/canonical.go
- Create: internal/actionproposal/canonical_test.go
- Create: internal/actionproposal/generator.go
- Create: internal/actionproposal/generator_test.go
- Create: internal/actionproposal/model_boundary.go
- Create: internal/actionproposal/model_boundary_test.go
- Modify: internal/model/router.go
- Modify: internal/model/router_test.go

**Interfaces:**
- Consumes: `investigationgrant.Scope`、不可变 Asset Snapshot/Item、Evidence ID/content hash、Published Capability/Runtime 安全投影、现有 Model Router 的有界生成调用。
- Produces: `CatalogResolver.Resolve(context.Context, ResolveRequest) (Catalog, error)`；`Generator.Generate(context.Context, GenerateRequest) (Outcome, error)`；`ActionProposal`、`HumanReviewFinding`、四种 typed `Intent`；`Outcome.Validate() error`。

- [ ] **Step 1: 写 Catalog、窄联合与 exact-one Outcome 失败测试**

在 `types_test.go` 和 `catalog_test.go` 固定四种允许类型、参数边界、`PROPOSAL_ONLY` 状态及 Outcome 恰好一支。测试要证明 Catalog Entry 不含 Target、endpoint、credential、permission、window、verification 或 compensation。

~~~go
func TestCatalogExposesOnlyProposalSafeTypedIntents(t *testing.T) {
    catalog := validCatalog(t)
    if catalog.Mode != ProposalOnly || len(catalog.Entries) != 4 {
        t.Fatalf("catalog mode/entries = %s/%d", catalog.Mode, len(catalog.Entries))
    }
    got := map[ActionType]string{}
    for _, entry := range catalog.Entries {
        if entry.Mode != ProposalOnly || len(entry.AllowedFields) > 1 {
            t.Fatalf("unsafe entry = %#v", entry)
        }
        got[entry.ActionType] = entry.IntentSchemaVersion
    }
    want := map[ActionType]string{
        K8SRolloutRestart: "k8s-rollout-restart-intent.v1",
        K8SScale: "k8s-scale-intent.v1",
        GitOpsRevert: "gitops-revert-intent.v1",
        AWXServiceRestart: "awx-service-restart-intent.v1",
    }
    if diff := cmp.Diff(want, got); diff != "" {
        t.Fatalf("catalog (-want +got):\n%s", diff)
    }
}

func TestOutcomeRequiresExactlyProposalOrHumanReviewFinding(t *testing.T) {
    proposal := validActionProposal(t)
    finding := HumanReviewFinding{Code: FindingUncertainIntent, ReviewReason: "EVIDENCE_INSUFFICIENT"}
    for name, outcome := range map[string]Outcome{
        "empty": {},
        "both": {ActionProposal: &proposal, Finding: &finding},
    } {
        if err := outcome.Validate(); !errors.Is(err, ErrInvalidOutcome) {
            t.Fatalf("%s Validate() = %v", name, err)
        }
    }
}
~~~

- [ ] **Step 2: 运行领域测试并确认失败**

Run: `go test ./internal/actionproposal -run 'Test(Catalog|Outcome|Intent)' -count=1`

Expected: FAIL，错误包含 `package .../internal/actionproposal is not in std` 或 `undefined: Catalog`。

- [ ] **Step 3: 实现固定类型、Catalog 与 Human Review Finding**

写入以下核心类型。`TrustedBinding` 不出现在模型请求 DTO；`ActorAttribution` 由 Model Router 返回的已持久 `model_call_id` 构造，不能从模型 JSON 解码。

~~~go
package actionproposal

type Mode string
const ProposalOnly Mode = "PROPOSAL_ONLY"

type ActionType string
const (
    K8SRolloutRestart ActionType = "K8S_ROLLOUT_RESTART"
    K8SScale ActionType = "K8S_SCALE"
    GitOpsRevert ActionType = "GITOPS_REVERT"
    AWXServiceRestart ActionType = "AWX_SERVICE_RESTART"
)

type CatalogEntry struct {
    ActionType ActionType `json:"action_type"`
    IntentSchemaVersion string `json:"intent_schema_version"`
    AllowedFields []string `json:"allowed_fields"`
    Mode Mode `json:"mode"`
}

type Catalog struct {
    Revision int64 `json:"revision"`
    Digest string `json:"digest"`
    Mode Mode `json:"mode"`
    Entries []CatalogEntry `json:"entries"`
}

type RestartIntent struct{}
type ScaleIntent struct { DesiredReplicas int16 `json:"desired_replicas"` }
type RevertIntent struct { ReasonCode string `json:"reason_code"` }
type ServiceRestartIntent struct { RestartScope string `json:"restart_scope"` }

type TrustedBinding struct {
    Scope investigationgrant.Scope
    ServiceID, IncidentID, InvestigationID string
    SnapshotID, SnapshotDigest, AssetID string
    AssetRevision int64
    EvidenceIDs []string
    EvidenceDigest string
    CatalogRevision int64
    CatalogDigest string
}

type ActorAttribution struct {
    Type string
    ModelCallID string
}

type FindingCode string
const (
    FindingNoCatalogMatch FindingCode = "NO_CATALOG_MATCH"
    FindingUncertainIntent FindingCode = "UNCERTAIN_INTENT"
    FindingModelOverreach FindingCode = "MODEL_OVERREACH"
    FindingCatalogDrift FindingCode = "CATALOG_DRIFT"
    FindingEvidenceDrift FindingCode = "EVIDENCE_DRIFT"
    FindingAmbiguousTarget FindingCode = "AMBIGUOUS_TARGET"
)
~~~

`HumanReviewFinding` 只允许 `Code/ReviewReason/EvidenceDigest/CatalogDigest/ActorAttribution/CreatedAt`，ReviewReason 必须来自固定枚举，不保存模型原文。`ActionProposal` 是带 `RestartIntent|ScaleIntent|RevertIntent|ServiceRestartIntent` exact-one 的 typed union；`Outcome` 的 `ActionProposal` 与 `Finding` 必须 exact-one；`Validate` 要求 `Mode=PROPOSAL_ONLY`、Binding 完整、Actor Type=`MODEL`、digest 为小写 SHA-256。Evidence IDs 只存在于 `TrustedBinding`，不进入模型输出 DTO。

- [ ] **Step 4: 实现内容寻址 Catalog Resolver**

Catalog Resolver 接受的请求只有可信 Investigation ID；在 Repository 事务中解析 Scope、Evidence、Snapshot Item、Asset kind 与当前 proposal-safe Capability。只有 Evidence 精确收敛到一个 Asset，Asset 为 `ACTIVE + EXACT`，对应 READ Runtime 仍 `PUBLISHED + AVAILABLE`，且固定 Action 映射存在时才返回 Entry。

~~~go
type ResolveRequest struct { InvestigationID string }

type CatalogResolver interface {
    Resolve(context.Context, ResolveRequest) (Catalog, error)
}

func NewCatalog(revision int64, entries []CatalogEntry) (Catalog, error) {
    normalized, err := normalizeEntries(entries)
    if err != nil || revision < 1 {
        return Catalog{}, ErrInvalidCatalog
    }
    digest, err := canonicalDigest("aiops.action-proposal-catalog.v1", struct {
        Revision int64 `json:"revision"`
        Mode Mode `json:"mode"`
        Entries []CatalogEntry `json:"entries"`
    }{revision, ProposalOnly, normalized})
    if err != nil { return Catalog{}, ErrInvalidCatalog }
    return Catalog{Revision: revision, Digest: digest, Mode: ProposalOnly, Entries: normalized}, nil
}
~~~

固定映射只决定“允许提议的意图形状”，不能携带可执行值：Kubernetes Deployment 可提议 restart/scale；有精确 GitOps binding 可提议 revert；有已发布 AWX READ inventory binding 可提议 service restart。当前 Capability 变更只影响新 Catalog；持久化前仍需重新解析并比较 digest。

- [ ] **Step 5: 写严格模型 Decoder 的越权与不确定失败测试**

表驱动测试覆盖未知 action、额外字段、Evidence 越界、空/多个结果、非整数 replicas、Catalog 未提供的类型、模型自报 Actor/Scope/requester/approval/queue/credential/window/verification/compensation。所有情形都返回 Finding，不能返回部分 ActionProposal。

~~~go
func TestDecoderTurnsModelOverreachIntoHumanReviewOnly(t *testing.T) {
    catalog := catalogWith(t, K8SScale)
    for _, field := range []string{
        "requester", "approval", "queue", "scope", "credential",
        "window", "verification", "compensation", "target", "evidence_ids", "endpoint", "command", "sql",
    } {
        response := []byte(fmt.Sprintf(
            `{"action_type":"K8S_SCALE","intent":{"desired_replicas":3},%q:"attacker-value"}`, field))
        outcome, err := decodeModelOutcome(response, catalog)
        if err != nil || outcome.ActionProposal != nil || outcome.Finding == nil ||
            outcome.Finding.Code != FindingModelOverreach {
            t.Fatalf("field %s outcome=%#v err=%v", field, outcome, err)
        }
    }
}

func TestDecoderNeverChoosesWhenCatalogOrIntentIsUncertain(t *testing.T) {
    outcome, err := decodeModelOutcome(
        []byte(`{"finding":{"reason_code":"EVIDENCE_INSUFFICIENT"}}`),
        catalogWith(t, K8SRolloutRestart))
    if err != nil || outcome.ActionProposal != nil || outcome.Finding.Code != FindingUncertainIntent {
        t.Fatalf("outcome=%#v err=%v", outcome, err)
    }
}
~~~

- [ ] **Step 6: 实现严格 Decoder 与服务端 attribution**

模型响应顶层只能是 action proposal candidate 或 finding exact-one；ActionProposal candidate 只含 `action_type`、`intent_schema_version`、`intent`。`evidence_ids` 与任何 Evidence selector 都属于越权字段。使用两层 `json.Decoder.DisallowUnknownFields()`，拒绝 trailing token、重复键、大小写别名、数字指数和 unknown union field。模型原始响应最多 16 KiB，验证后立即销毁，不进入日志或 Finding。

~~~go
type GenerateRequest struct { InvestigationID string }

type ModelGateway interface {
    GenerateActionProposal(context.Context, ModelInput) (ModelResult, error)
}

type ModelResult struct {
    ModelCallID string
    Response []byte
}

type Generator struct {
    resolver CatalogResolver
    evidence EvidenceReader
    model ModelGateway
    appender Appender
    findings FindingRecorder
}

func (g *Generator) Generate(ctx context.Context, request GenerateRequest) (Outcome, error) {
    catalog, binding, err := g.resolveTrustedInput(ctx, request)
    if err != nil { return g.recordResolutionFinding(ctx, request, err) }
    result, err := g.model.GenerateActionProposal(ctx, safeModelInput(catalog, binding))
    if err != nil { return g.recordUncertainFinding(ctx, binding, "MODEL_UNAVAILABLE") }
    defer clear(result.Response)
    decoded, err := decodeModelOutcome(result.Response, catalog)
    if err != nil { return Outcome{}, err }
    return g.persistTrustedOutcome(ctx, binding, catalog, result.ModelCallID, decoded)
}
~~~

`persistTrustedOutcome` 必须忽略模型中不存在的所有服务端字段，并构造 `ActorAttribution{Type:"MODEL", ModelCallID: result.ModelCallID}`。Model Router 的生产接口新增有界 `GenerateActionProposal`；若配置缺失、响应超限、panic 或 model call 未持久化，记录 `UNCERTAIN_INTENT/MODEL_UNAVAILABLE` Finding，不生成 ActionProposal。

- [ ] **Step 7: 运行领域、fuzz、race 与泄漏测试**

Run: `go test -race -shuffle=on -count=1 ./internal/actionproposal ./internal/model`

Expected: PASS；Fuzz seed 覆盖重复键、未知字段、Unicode key、超大数字、模型自报 Evidence/Scope、Catalog 越界和 16 KiB 边界；错误与日志不包含模型原文 canary。

- [ ] **Step 8: 提交 ActionProposal 领域与生成边界**

~~~bash
git add internal/actionproposal internal/model/router.go internal/model/router_test.go
git commit -m "feat: constrain evidence backed action proposals"
~~~

### Task 10: Append-only Repository、Human Review Finding 与只读 API

**Files:**
- Create: internal/actionproposal/repository.go
- Create: internal/actionproposal/postgres/repository.go
- Create: internal/actionproposal/postgres/repository_test.go
- Create: internal/actionproposal/postgres/repository_integration_test.go
- Create: internal/actionproposal/postgres/finding_recorder.go
- Create: internal/actionproposal/postgres/finding_recorder_test.go
- Create: internal/actionproposal/handoff.go
- Create: internal/actionproposal/handoff_test.go
- Create: internal/actionproposal/postgres/handoff.go
- Create: internal/actionproposal/postgres/handoff_integration_test.go
- Create: internal/httpapi/action_proposals.go
- Create: internal/httpapi/action_proposals_test.go
- Modify: internal/httpapi/router.go
- Modify: internal/httpapi/router_test.go
- Modify: internal/authz/authorizer.go
- Modify: internal/authz/authorizer_test.go
- Modify: api/openapi/control-plane-v1.yaml
- Create: api/openapi/control-plane-v1-action-proposals_test.go
- Modify: web/src/shared/api/schema.d.ts
- Modify: cmd/control-plane/main.go
- Modify: cmd/control-plane/main_test.go

**Interfaces:**
- Consumes: Task 9 的 Catalog/ActionProposal/Outcome；Task 2 创建的 `action_proposals`；现有 `audit_records`、authn Principal、Scope middleware、Cursor/RFC 9457/ETag 安全约定。
- Produces: `Appender.Append(context.Context, AppendRequest) (ActionProposal, error)`；`Reader.Get/ListByInvestigation/GetCatalog`；`FindingRecorder.Append(context.Context, HumanReviewFinding) error`；`HandoffLoader.LoadTrustedForActionPlanDerivation(context.Context, pgx.Tx, HandoffRequest) (TrustedDerivationSource, error)`；`ACTION_PROPOSAL_READ` 权限与三条只读 API。

- [ ] **Step 1: 写 Repository 事务重解析与 append-only 失败测试**

`repository_integration_test.go` 使用 PostgreSQL 18.4，先解析 Catalog/Evidence，再并发制造 Asset quarantine、Catalog revision 替换和跨 Scope Evidence。断言只要事务内当前 digest 不一致，就零 ActionProposal 行并有一条固定 Finding audit；合法 replay 按 `proposal_digest` 返回同一行。

~~~go
func TestAppendRevalidatesCatalogEvidenceAndAssetInOneTransaction(t *testing.T) {
    fixture := newProposalPostgresFixture(t)
    request := fixture.validAppendRequest(t)
    fixture.quarantineAssetAfterCatalogResolved(t, request.Binding.AssetID)

    _, err := fixture.repository.Append(context.Background(), request)
    if !errors.Is(err, actionproposal.ErrBindingDrift) {
        t.Fatalf("Append() error = %v", err)
    }
    fixture.assertProposalCount(t, 0)
    fixture.assertFinding(t, actionproposal.FindingCatalogDrift, "ASSET_BECAME_INELIGIBLE")
}

func TestDatabaseRejectsEveryActionProposalMutation(t *testing.T) {
    fixture := newProposalPostgresFixture(t)
    proposal := fixture.appendValid(t)
    for _, statement := range []string{
        "UPDATE action_proposals SET desired_replicas = 4 WHERE id = $1",
        "DELETE FROM action_proposals WHERE id = $1",
        "TRUNCATE action_proposals",
    } {
        if _, err := fixture.db.Exec(context.Background(), statement, proposal.ID); pgErrorCode(err) != "55000" {
            t.Fatalf("statement %q error = %v", statement, err)
        }
    }
}

func TestHandoffRequestRequiresAuthenticatedHumanAndFullTWESScope(t *testing.T)
func TestHandoffRequestRejectsMissingOrMismatchedServiceScope(t *testing.T)
func TestHandoffLoaderUsesCallerTransactionAndReloadsBeforeReturning(t *testing.T)
func TestHandoffLoaderRecomputesAndConstantTimeComparesExpectedProposalDigest(t *testing.T)
~~~

- [ ] **Step 2: 运行 PostgreSQL 测试并确认失败**

Run:

~~~bash
test -n "$AIOPS_TEST_POSTGRES_DSN"
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" \
  go test -race -count=1 ./internal/actionproposal/postgres -run 'Test(Append|Database|Finding|Handoff)'
~~~

Expected: FAIL only because `Repository`/`action_proposals` query or Handoff full-Scope/constant-time digest validation is not implemented yet. Missing PostgreSQL 18.4+ is a failed prerequisite, not the required Red result；Skip or a memory repository cannot satisfy this step.

- [ ] **Step 3: 实现锁序、幂等追加和 Finding 原子记录**

接口固定为以下形状。`AppendRequest.Binding` 只能由 Task 9 的生产 Resolver 创建；构造器不接受公共 DTO。

~~~go
type AppendRequest struct {
    Binding TrustedBinding
    ActionType ActionType
    Intent Intent
    Actor ActorAttribution
}

type Appender interface {
    Append(context.Context, AppendRequest) (ActionProposal, error)
}

type Reader interface {
    Get(context.Context, investigationgrant.Scope, string) (ActionProposal, error)
    ListByInvestigation(context.Context, investigationgrant.Scope, string, Page) (ActionProposalPage, error)
    GetCatalog(context.Context, investigationgrant.Scope, string) (Catalog, error)
}

type FindingRecorder interface {
    Append(context.Context, HumanReviewFinding) error
}

type HandoffRequest struct {
    scope                        investigationgrant.Scope
    actionProposalID             string
    expectedActionProposalDigest string
    initiator                    authn.Principal
}

func NewHandoffRequest(
    principal authn.Principal,
    scope investigationgrant.Scope,
    actionProposalID string,
    expectedActionProposalDigest string,
) (HandoffRequest, error)

type HandoffLoader interface {
    LoadTrustedForActionPlanDerivation(
        context.Context,
        pgx.Tx,
        HandoffRequest,
    ) (TrustedDerivationSource, error)
}
~~~

PostgreSQL 锁序固定为 Investigation → Incident → proactive_run/Grant → Snapshot/Item → Evidence UUID 升序 → Catalog facts → `pg_advisory_xact_lock(proposalDigestKey)`。在 INSERT 前重算 Evidence digest 与 Catalog digest，重验 Asset `ACTIVE + EXACT` 和 proposal-safe Capability。相同 digest replay 返回原行；不同 Actor、Intent 或 Evidence 得到不同 digest。Finding 追加到 `audit_records`，`action=ACTION_PROPOSAL_HUMAN_REVIEW_REQUIRED`，details 只含 finding_code、review_reason、Evidence/Catalog digest 和 model_call_id hash，不含原始响应。

`NewHandoffRequest` 只接受认证中间件建立的服务端 `authn.Principal`，要求主体类型为 `HUMAN`、认证会话仍有效，且 `investigationgrant.Scope` 的 Tenant/Workspace/Environment/Service 四项均非空并完全来自认证 Tenant + `/workspaces/{workspace_id}/environments/{environment_id}/services/{service_id}` path；Principal 必须有权在这个精确 Scope 发起派生。字段保持私有，HTTP body、模型或浏览器不能自行构造/覆盖 Scope 或 initiator；Proposal ID 与 expected digest 仅由 Phase 7 六字段 SealIntent 传入。`expectedActionProposalDigest` 只作为并发/漂移前置条件，绝不是可信事实源；Loader 必须从锁定的数据库事实重算 Proposal digest 后做固定长度恒时比较。

`TrustedDerivationSource` 只由 PostgreSQL Handoff Loader 构造，包含 ActionProposal ID/digest、typed intent、Catalog revision/digest、Evidence IDs/content hashes/digest、Snapshot ID/digest、Asset binding 与加载时刻。Loader 必须使用 Phase 7 封存 ActionPlan 的同一个 `pgx.Tx`，且它是 Proposal-related DB read 的首个入口；按固定锁序以完整 T/W/E/S Scope 重载可信 ActionProposal/Catalog/Evidence/Snapshot，从库重算全部摘要、恒时比较 expected Proposal digest 并复验当前资格，ActionProposal 必须仍为 `PROPOSAL_ONLY`。Phase 7 只能从返回的可信来源派生新的 Plan ID/hash、写入全部来源摘要并在同一事务提交前封存 ActionPlan；任一 Scope/digest/资格变化或摘要不一致都使整个事务回滚并升级人工。Loader 本身不创建 ActionPlan，也不接受 requester/approval/queue/credential/window/verification/compensation 或 Plan body。

- [ ] **Step 4: 写 RBAC、OpenAPI 安全形状和无 mutation 路由测试**

新增 `ACTION_PROPOSAL_READ`，VIEWER/OPERATOR/INCIDENT_COMMANDER 按现有显式矩阵获得只读权限；ADMIN 不因角色名自动获得 Incident 内容权限。OpenAPI 固定三条路由：

~~~text
GET /api/v1/workspaces/{workspace_id}/environments/{environment_id}/investigations/{investigation_id}/action-proposal-catalog
GET /api/v1/workspaces/{workspace_id}/environments/{environment_id}/investigations/{investigation_id}/action-proposals
GET /api/v1/workspaces/{workspace_id}/environments/{environment_id}/action-proposals/{proposal_id}
~~~

合同测试枚举 `/action-proposals` 的所有 path/method，断言 Phase 4 仅有 GET，且 OpenAPI 不新增创建 ActionPlan、接受 ActionProposal 或派生 Plan 的 POST；schema 使用 `additionalProperties:false`，ActionProposal 必须带 `mode: PROPOSAL_ONLY`、digest、safe typed intent、Actor type 和 `effective_actions`，不得出现 requester/approval/queue/credential/window/verification/compensation/target/endpoint。

~~~go
func TestActionProposalAPIIsReadOnlyAndNeverExposesExecutionFields(t *testing.T) {
    document := loadControlPlaneOpenAPI(t)
    operations := operationsContaining(document, "/action-proposals")
    for path, methods := range operations {
        if diff := cmp.Diff([]string{"get"}, methods); diff != "" {
            t.Fatalf("%s methods (-want +got): %s", path, diff)
        }
    }
    schema := schemaJSON(t, document, "ActionProposal")
    for _, forbidden := range []string{"requester", "approval", "queue", "credential", "window", "verification", "compensation", "endpoint"} {
        if bytes.Contains(bytes.ToLower(schema), []byte(forbidden)) {
            t.Fatalf("ActionProposal schema contains %q", forbidden)
        }
    }
}
~~~

- [ ] **Step 5: 运行 API 合同并确认失败**

Run: `go test ./api/openapi ./internal/authz ./internal/httpapi -run 'Test(ActionProposal|ProposalPermission)' -count=1`

Expected: FAIL，错误指出 OpenAPI path、Permission 或 Handler 缺失。

- [ ] **Step 6: 实现只读 HTTP Handler 和生成类型**

Handler 从认证 Principal 与 URL path 获取 Scope；Repository 永远不接受 body Scope。列表参数只允许 `cursor/limit`，limit 1..100；Catalog/ActionProposal 无匹配或跨 Scope 使用统一安全 404。Projection 将 typed intent 映射为 discriminator union；`effective_actions` 在本阶段最多包含 `ACTION_PROPOSAL_READ`，不得包含 create/accept/derive-plan/execute。

~~~go
type ActionProposalReader interface {
    GetCatalog(context.Context, investigationgrant.Scope, string) (actionproposal.Catalog, error)
    ListByInvestigation(context.Context, investigationgrant.Scope, string, actionproposal.Page) (actionproposal.ActionProposalPage, error)
    Get(context.Context, investigationgrant.Scope, string) (actionproposal.ActionProposal, error)
}

func (api *API) getActionProposal(w http.ResponseWriter, r *http.Request) {
    scope, principal, ok := api.requireEnvironmentScope(w, r, authz.PermissionActionProposalRead)
    if !ok { return }
    proposal, err := api.proposals.Get(r.Context(), scope, chi.URLParam(r, "proposal_id"))
    api.writeScopedRead(w, r, principal, proposalProjection(proposal), err)
}
~~~

运行唯一生成命令：

Run: `pnpm --dir web generate:api`

Expected: PASS；只更新 `web/src/shared/api/schema.d.ts`。随后运行 `pnpm --dir web generate:api:check`，Expected: PASS。

- [ ] **Step 7: 在生产装配中强制真实依赖**

`cmd/control-plane/main.go` 构造 PostgreSQL ActionProposal Repository/Catalog Resolver/Finding Recorder/Handoff Loader，注入现有真实 Model Router 与 HTTP API。`main_test.go` 架构扫描禁止 `memory.New`、test Catalog 或 nil ActionProposal dependency 出现在生产装配；缺模型、数据库、Audit 或 Handoff dependency 时启动失败。ActionProposal 生成作为 Investigation finalize 后的独立受控步骤，失败只影响 ActionProposal/Finding，不改写已完成 Evidence。

- [ ] **Step 8: 运行 Repository/API/race 与 secret scan**

Run: `go test -race -shuffle=on -count=1 ./internal/actionproposal/... ./internal/httpapi ./internal/authz ./api/openapi ./cmd/control-plane`

Expected: PASS；所有列表 Cursor 稳定，跨 Scope 不泄露，日志不含测试 canary。

Run: `rg -n '(BEGIN (RSA|OPENSSH|EC) PRIVATE KEY|postgres://[^ ]+:[^ ]+@|vault://|secret-canary|SELECT \*)' internal/actionproposal internal/httpapi api/openapi/control-plane-v1.yaml web/src/shared/api/schema.d.ts`

Expected: 除测试断言和明确拒绝清单外无匹配。

- [ ] **Step 9: 提交 Repository 与只读 API**

~~~bash
git add internal/actionproposal internal/httpapi internal/authz api/openapi/control-plane-v1.yaml api/openapi/control-plane-v1-action-proposals_test.go web/src/shared/api/schema.d.ts cmd/control-plane
git commit -m "feat: persist and expose safe action proposals"
~~~

### Task 11: Mutation、Overreach、Drift、Handoff 与真实 ActionProposal E2E

**Files:**
- Create: test/e2e/action_proposals_test.go
- Create: test/e2e/fixtures/action-proposal-model/main.go
- Create: test/e2e/fixtures/action-proposal-model/responses.go
- Create: test/e2e/fixtures/action-proposal-model/responses_test.go
- Create: test/e2e/compose.action-proposals.yaml
- Modify: Makefile

**Interfaces:**
- Consumes: Tasks 9–10 的生产 Control Plane、真实 000018 PostgreSQL、OIDC/JWKS 验证、真实 HTTP API；测试目录内确定性 model fixture。
- Produces: Evidence→Catalog→Model→ActionProposal/Finding→API 的端到端证据；Mutation、Overreach、Catalog/Evidence/Asset drift、Handoff 重载复验和跨 Scope 拒绝证据。

- [ ] **Step 1: 写完整 E2E 场景并确认红灯**

E2E 启动真实 PostgreSQL 18.4、Keycloak、Control Plane 与测试专用 HTTP model fixture。fixture 只能返回预置安全/攻击响应，不能链接进生产 binary。场景按以下表驱动：

| 场景 | 模型响应/竞争动作 | 必须结果 |
|---|---|---|
| 合法 K8S_SCALE | `desired_replicas=3` | 1 ActionProposal，`PROPOSAL_ONLY`，API 可读 |
| 无匹配 | Catalog 为空 | 0 ActionProposal，`NO_CATALOG_MATCH` Finding |
| 不确定 | finding reason | 0 ActionProposal，`UNCERTAIN_INTENT` Finding |
| 越权 | requester/approval/queue/credential 任一字段 | 0 ActionProposal，`MODEL_OVERREACH` Finding |
| Catalog 漂移 | 响应期间撤销 proposal-safe Capability | 0 ActionProposal，`CATALOG_DRIFT` Finding |
| Asset 漂移 | 响应期间 QUARANTINE Asset | 0 ActionProposal，`CATALOG_DRIFT` Finding |
| Scope 越界 | Workspace A token 请求 Workspace B ActionProposal | 安全 404，审计拒绝 |
| Phase 7 Handoff | 经认证的人通过完整 T/W/E/S path 请求 ActionProposal ID/expected digest，Phase 7 不预读 Proposal并传入其封存事务 | Handoff Loader 在同一事务按 full Scope 锁定、从库重算/恒时比较并重载复验后仅返回 TrustedDerivationSource；Phase 4 不创建 Plan |
| Handoff 漂移 | ActionProposal/Catalog/Evidence/Snapshot 任一 digest 或当前资格变化 | Phase 7 同一封存事务回滚，无 TrustedDerivationSource/Plan，Human Review Finding |
| SQL mutation | UPDATE/DELETE/TRUNCATE | SQLSTATE 55000，原行摘要不变 |

~~~go
func TestEvidenceBackedProposalClosedLoop(t *testing.T) {
    stack := StartActionProposalStack(t)
    investigation := stack.CompleteInvestigationWithEvidence(t, "k8s-scale-evidence")
    stack.Model().Respond(t, SafeScaleProposal(3))
    stack.TriggerProposalGeneration(t, investigation.ID)

    proposals := stack.API().ListActionProposals(t, investigation.Scope, investigation.ID)
    if len(proposals.Items) != 1 || proposals.Items[0].Mode != "PROPOSAL_ONLY" ||
        proposals.Items[0].Intent.DesiredReplicas != 3 {
        t.Fatalf("proposals = %#v", proposals)
    }
    stack.AssertNoActionPlanApprovalQueueCredentialOrExecution(t, proposals.Items[0].ID)
    stack.AssertAuditChainContains(t, "ACTION_PROPOSAL_APPENDED", proposals.Items[0].Digest)
}
~~~

- [ ] **Step 2: 运行 E2E 并确认失败**

Run: `AIOPS_E2E_ACTION_PROPOSALS=1 go test -count=1 ./test/e2e -run 'Test(EvidenceBackedProposal|ProposalOverreach|ProposalDrift|ProposalMutation|ProposalHandoff)'`

Expected: FAIL，缺少 compose stack、fixture、ActionProposal 生产路由或 Handoff Loader。

- [ ] **Step 3: 实现测试专用 model fixture 与真实栈启动**

compose 固定 digest-pinned PostgreSQL 18.4 与 Keycloak Server 26.6.3，构建当前 Control Plane；model fixture 独立容器只监听测试网络，接受带 Catalog digest 的请求并按 test case ID 返回最多 16 KiB JSON。Control Plane 使用与生产相同的 PostgreSQL Repository、authn、Catalog Resolver、Model Router、HTTP Handler；不能以 memory/MSW 代替。

- [ ] **Step 4: 实现竞争注入和数据库 mutation 证明**

Catalog/Asset drift 使用 model fixture 的 barrier：收到请求后阻塞，测试通过真实治理 Repository 撤销 Capability 或隔离 Asset，再释放响应。Evidence 行本身不可变；Evidence drift 用事务 A 解析后，事务 B 追加 superseding Evidence set 并使 Catalog revision 改变，断言 digest revalidation 拒绝。数据库 mutation 直接执行 SQL 并验证 SQLSTATE、行 digest 与 Audit chain 未变化。

- [ ] **Step 5: 运行真实 E2E、重复与 race 验收**

Run: `AIOPS_E2E_ACTION_PROPOSALS=1 go test -race -shuffle=on -count=3 ./test/e2e -run 'Test(EvidenceBackedProposal|ProposalOverreach|ProposalDrift|ProposalMutation|ProposalHandoff)'`

Expected: PASS；三次运行均无重复 ActionProposal；Phase 4 生成请求不直接/自动产生 ActionPlan/Approval/queue/credential/execution 行；无跨 Scope 泄露，Finding code 稳定。Handoff Loader 正向测试使用认证 Principal + full T/W/E/S URL Scope 构造的 request 和调用者传入的 Phase 7 封存事务，不存在 Loader 前 Proposal 预读；Loader 从库重算并恒时比较 expected Proposal digest，只返回复验后的 `TrustedDerivationSource`，不创建 Plan。Scope、摘要或资格漂移时返回 Human Review Required，回滚后无任何 Plan 或部分派生事实。

- [ ] **Step 6: 增加 Makefile 门并提交 E2E**

`Makefile` 新增 `test-action-proposals-e2e`，只封装上面的真实栈命令；任一必需依赖缺失或 required test Skip 都必须非零退出。运行：

Run: `make test-action-proposals-e2e`

Expected: PASS，输出合法、无匹配、越权、生成漂移、Scope、mutation、Handoff 正向与 Handoff 漂移八组通过摘要。

~~~bash
git add test/e2e/action_proposals_test.go test/e2e/fixtures/action-proposal-model test/e2e/compose.action-proposals.yaml Makefile
git commit -m "test: prove action proposal safety end to end"
~~~

## Execution Handoff

本包完成后继续执行 `05-web-experience.md`。ActionProposal 本身永无执行/审批/排队/凭据权，Phase 4 也没有创建 ActionPlan 的公共 API。Phase 7 的唯一合法交接是：经认证的人通过完整 T/W/E/S ActionPlan create path 明确发起，Phase 7 不预读 Proposal，开启封存事务，以 Principal + URL Scope + Proposal ID/expected digest 构造 HandoffRequest 并把同一个 `pgx.Tx` 传给 Handoff Loader；Loader 按 full Scope 锁定并重载可信 ActionProposal/Catalog/Evidence/Snapshot、从库重算/恒时比较摘要和复验当前门禁，Phase 7 从返回的可信来源派生并在该事务提交前封存新的 immutable ActionPlan。任一漂移整笔回滚并升级人工；成功后仍须经过策略、最近认证、人工审批、短期 WRITE credential、类型化 Runner、独立验证与审计闭环。
