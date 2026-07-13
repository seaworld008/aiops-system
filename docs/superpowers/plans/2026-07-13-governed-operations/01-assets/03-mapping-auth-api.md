# Mapping, Authorization, and Control Plane API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 实现资产关系、冲突决策、Service Binding、OIDC 作用域授权和浏览器 Control Plane API，形成可审计、可并发、可恢复的真实生产管理边界。

**Architecture:** 管理服务先用认证 Principal 与数据库 Scope 授权，再调用 PostgreSQL Repository；所有决定使用 Idempotency-Key 与 ETag/CAS。公开 HTTP 仅由闭合 OpenAPI 3.1 驱动，统一执行严格 JSON、不透明签名 Cursor、RFC 9457 Problem、安全 DTO 和 no-store。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4、pgx v5、chi v5、OIDC、OpenAPI 3.1。

## Global Constraints

- 前置任务：依次完成 [01-schema-domain.md](./01-schema-domain.md) 与 [02-repository-discovery.md](./02-repository-discovery.md)。
- 必须在仓库目录树之外的隔离 worktree 实施；不得删除用户已有 worktree。
- 生产实现只允许 PostgreSQL Repository、真实 OIDC verifier 和 HMAC Cursor；fake 只能位于 `_test.go`，不得通过生产配置启用。
- 所有读写强制 Tenant + Workspace + Environment 复合作用域；API 不接受 `tenant_id`。
- 写请求必须带 Idempotency-Key；修改、隔离、退役、删除 Binding、冲突决策必须带 If-Match。
- `ACTIVE` 仍由后续“来源有效 + 映射 EXACT + Connection Publication 复验”激活；本包不得提供 ACTIVE 操作，Capability Gate 保持独立。
- `effective_actions` 由服务端授权与对象状态共同计算；前端不得按角色推断。
- 所有 `/api/v1` 返回 `Cache-Control: no-store`、`X-Content-Type-Options: nosniff` 和 Trace ID。
- DTO/Problem/审计/Outbox/指标标签不得包含 Secret、Token、DSN、endpoint、Provider 原文、命令、SQL、任意 Header/Body 或高基数字段。
- 数据库写路径必须幂等、CAS、事务原子、可安全重试且 HA 友好；不得依赖进程内锁或单副本内存状态。
- 迁移保持向前/向后兼容；备份恢复演练必须覆盖 000015 数据，旧实例滚动期间 API 必须 fail closed。
- 暴露低基数 Prometheus 指标：请求结果、Repository 延迟/冲突、冲突队列年龄、Source Run 结果；不得用租户、资产、Subject、外部 ID 作标签。
- 当前阶段是完整生产闭环的基础，不是 demo 或 read-only pilot；后续计划会进入受治理生产写，但本包不得提前开放目标写执行。
- 每个任务严格按 Red → Green → Refactor；末尾提交步骤只包含本任务文件。
- 本包完成后进入 [04-web-foundation-assets.md](./04-web-foundation-assets.md)。

---


### Task 5: Asset relations, conflicts, and exact Service Binding decisions

**Files:**
- Modify: **internal/assetcatalog/types.go**
- Modify: **internal/assetcatalog/repository.go**
- Create: **internal/assetcatalog/postgres/mappings.go**
- Create: **internal/assetcatalog/postgres/mappings_test.go**
- Create: **internal/assetcatalog/postgres/mappings_integration_test.go**

**Interfaces:**
- Consumes: existing `services` facts and the conflict/asset rows created by Tasks 3–4.
- Produces: `MappingRepository` for relation reads, conflict queue/decision, binding list/create/delete.
- Safety rule: a binding can only become `ACTIVE` with `mapping_status=EXACT` after an explicit decision; a conflict decision and its audit/outbox side effects are atomic.

- [ ] **Step 1: Write failing mapping state and atomicity tests**

~~~go
func TestResolveConflictConfirmExactCreatesOnlyRequestedBinding(t *testing.T) {
	database := openAssetCatalogDatabase(t)
	fixture := seedOpenConflict(t, database)
	repository := newAssetRepository(t, database)

	decision := fixture.mappingDecision()
	decision.Resolution = assetcatalog.ResolutionConfirmExact
	result, err := repository.ResolveConflict(context.Background(), decision)
	if err != nil {
		t.Fatal(err)
	}
	if result.Binding == nil {
		t.Fatal("exact decision did not return a binding")
	}
	binding := *result.Binding
	if binding.ServiceID != decision.ServiceID || binding.AssetID != fixture.AssetID ||
		binding.MappingStatus != domain.MappingExact || binding.Status != "ACTIVE" {
		t.Fatalf("binding = %#v", binding)
	}
	if result.Receipt.AuditID == "" || result.Receipt.TraceID != decision.TraceID || result.Receipt.IdempotentReplay {
		t.Fatalf("mutation receipt = %#v", result.Receipt)
	}
	assertMappingSideEffects(t, database, fixture.ConflictID, 1, 1, 1)
}

func TestResolveConflictRejectsCrossScopeServiceAndRollsBack(t *testing.T) {
	database := openAssetCatalogDatabase(t)
	fixture := seedOpenConflict(t, database)
	repository := newAssetRepository(t, database)
	decision := fixture.mappingDecision()
	decision.ServiceID = fixture.OtherTenantServiceID

	if _, err := repository.ResolveConflict(context.Background(), decision); !errors.Is(err, assetcatalog.ErrScopeViolation) {
		t.Fatalf("ResolveConflict error = %v", err)
	}
	assertMappingSideEffects(t, database, fixture.ConflictID, 0, 0, 0)
}

func TestResolveConflictRejectsServiceWithoutEnvironmentBindingAndRollsBack(t *testing.T) {
	database := openAssetCatalogDatabase(t)
	fixture := seedOpenConflictWithSameWorkspaceUnboundService(t, database)
	repository := newAssetRepository(t, database)

	_, err := repository.ResolveConflict(context.Background(), fixture.mappingDecision())
	if !errors.Is(err, assetcatalog.ErrScopeViolation) {
		t.Fatalf("ResolveConflict error = %v", err)
	}
	assertMappingSideEffects(t, database, fixture.ConflictID, 0, 0, 0)
}
~~~

Run: `go test ./internal/assetcatalog/postgres -run 'TestResolveConflict' -count=1`

Expected: FAIL because mapping repository methods do not exist.

- [ ] **Step 2: Define complete mapping read/write contracts**

~~~go
type Relationship struct {
	ID                                string
	TenantID                          string
	WorkspaceID                       string
	SourceEnvironmentID               string
	TargetEnvironmentID               string
	SourceAssetID                      string
	TargetAssetID                      string
	Type                              RelationshipType
	Provenance                        Provenance
	ProvenanceSourceID                string
	CrossEnvironmentPolicyReferenceID string
	Status                            RelationshipStatus
	Version                           int64
	CreatedAt                         time.Time
	UpdatedAt                         time.Time
}

type Conflict struct {
	ID                string
	Scope             Scope
	SourceAssetID     string
	CandidateAssetID  string
	CandidateServiceID string
	Kind              string
	Status            string
	SummaryCode       string
	Version           int64
	CreatedAt         time.Time
	ResolvedAt        time.Time
}

type MappingRepository interface {
	ListRelationships(context.Context, ListRelationshipsRequest) (RelationshipPage, error)
	ListBindings(context.Context, ListBindingsRequest) (BindingPage, error)
	CreateBinding(context.Context, CreateBindingCommand) (BindingMutationResult, error)
	DeleteBinding(context.Context, DeleteBindingCommand) (MutationReceipt, error)
	ListConflicts(context.Context, ListConflictsRequest) (ConflictPage, error)
	ResolveConflict(context.Context, MappingDecision) (MappingDecisionResult, error)
}

type BindingMutationResult struct {
	Binding ServiceAssetBinding
	Receipt MutationReceipt
}

type MappingDecisionResult struct {
	Conflict Conflict
	Binding  *ServiceAssetBinding
	Receipt  MutationReceipt
}
~~~

The corresponding request/page types use the same `Scope`, maximum limit 100, and keyset cursors:

- relation order `(relationship_type, source_asset_id, target_asset_id, id)`;
- binding order `(service_id, binding_role, asset_id, id)`;
- conflict order `(created_at DESC, id DESC)`.

`Conflict` must expose only stable summary codes and IDs. Raw provider documents and fingerprint values never leave the repository.

- [ ] **Step 3: Implement compare-and-swap decisions**

`ResolveConflict` must:

1. Validate the action, binding role, service/asset UUIDs, reason, idempotency key/hash, expected conflict version, actor and UTC decision time.
2. Begin `SERIALIZABLE`, lock conflict, candidate asset, same-scope service and the exact `(service_id, environment_id)` legacy `service_bindings` eligibility row in deterministic UUID order. A same-Workspace Service without that Environment binding is a scope violation and the whole transaction rolls back.
3. A resolved replay returns its binding only if idempotency key and request hash match; otherwise return `ErrIdempotency`.
4. `CONFIRM_EXACT` requires a non-empty same-scope service and role plus the locked Environment eligibility edge, marks conflict `RESOLVED`, changes the asset mapping to `EXACT`, and inserts exactly one `ACTIVE` binding.
5. `REJECT_CANDIDATE` marks conflict `REJECTED`; no binding is created and the asset remains `UNRESOLVED` unless another open candidate exists, in which case it remains `AMBIGUOUS`.
6. `KEEP_UNRESOLVED` marks the conflict `RESOLVED` with that resolution and sets the asset `UNRESOLVED`.
7. `QUARANTINE_ASSET` closes the conflict, transitions the asset to `QUARANTINED`, and does not create a binding.
8. Increment conflict/asset versions, insert an audit event and an `asset.conflict.resolved.v1` outbox event containing only IDs/resolution/version, then commit and return the persisted receipt. Identical replay returns the original Audit ID with `IdempotentReplay=true`; a zero-value or synthesized receipt is invalid.

Standalone `CreateBinding` is permitted only for an already `EXACT` asset and the caller must provide the same explicit service, role, Idempotency-Key, request hash, and actor. It reuses and locks the same `(service_id,environment_id)` eligibility edge and must not infer a primary runtime. `CreateBinding` returns the Binding plus its durable receipt. `DeleteBinding` is a soft delete (`status=INACTIVE`, version+1), requires both Idempotency-Key and If-Match, persists delete idempotency/audit identity, preserves history, returns its durable receipt, and emits `service.asset.binding.removed.v1`.

Add integration assertions for standalone create, delete and all three identical replays: create/decision results contain the committed Audit ID/Trace ID; delete exposes that same persisted receipt to the HTTP 204 header path; replay returns the original Audit ID with `IdempotentReplay=true` and never writes a second audit/outbox row.

Use this composite-scope statement:

~~~sql
INSERT INTO service_asset_bindings (
    id, tenant_id, workspace_id, environment_id, service_id, asset_id,
    binding_role, mapping_status, provenance, status,
    idempotency_key, request_hash, version, created_at, updated_at
)
SELECT $1::uuid, a.tenant_id, a.workspace_id, a.environment_id,
       s.id, a.id, $7, 'EXACT', $8, 'ACTIVE', $9, $10, 1, $11, $11
FROM assets a
JOIN services s
  ON s.tenant_id = a.tenant_id AND s.workspace_id = a.workspace_id
JOIN service_bindings sb
  ON sb.tenant_id = s.tenant_id AND sb.workspace_id = s.workspace_id
 AND sb.service_id = s.id AND sb.environment_id = a.environment_id
WHERE a.tenant_id = $2::uuid AND a.workspace_id = $3::uuid
  AND a.environment_id = $4::uuid AND a.id = $5::uuid
  AND s.id = $6::uuid AND a.mapping_status = 'EXACT'
RETURNING id::text, version, created_at, updated_at;
~~~

- [ ] **Step 4: Verify scoping, cursor stability, idempotency, and concurrency**

Run:

~~~bash
gofmt -w internal/assetcatalog internal/assetcatalog/postgres
go test -race ./internal/assetcatalog ./internal/assetcatalog/postgres -count=1
TEST_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5432/aiops_test?sslmode=disable' \
  go test -race ./internal/assetcatalog/postgres -run 'TestMappingIntegration' -count=1
~~~

Expected: PASS. Concurrent decisions produce one committed decision and one version conflict; no cross-scope relationship/binding is visible; all list pages have stable, duplicate-free traversal.

- [ ] **Step 5: Commit**

~~~bash
git add internal/assetcatalog/types.go internal/assetcatalog/repository.go \
  internal/assetcatalog/postgres/mappings.go internal/assetcatalog/postgres/mappings_test.go \
  internal/assetcatalog/postgres/mappings_integration_test.go
git commit -m "feat(assetcatalog): govern mappings and service bindings"
~~~

### Task 6: Asset authorization, management boundary, and effective actions

**Files:**
- Modify: **internal/authn/authenticator.go**
- Modify: **internal/authn/authenticator_test.go**
- Modify: **internal/authz/authorizer.go**
- Modify: **internal/authz/authorizer_test.go**
- Create: **internal/assetcatalog/management.go**
- Create: **internal/assetcatalog/management_test.go**

**Interfaces:**
- Consumes: authenticated `authn.Principal` and the three repository groups from Tasks 3–5.
- Produces: separate `AssetManager`、`SourceManager`、`ConflictManager`、`BindingManager` interfaces for HTTP; management returns safe view models with `EffectiveActions`.
- Role policy: `VIEWER` read; `SRE` read; `SERVICE_OWNER` read and bind only owned services; `APPROVER` read; `AUDITOR` read; `ADMIN` read/manage/bind/resolve. No role receives live investigation from this slice.

- [ ] **Step 1: Write failing role-matrix tests**

~~~go
func TestAssetPermissionMatrix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		role       authn.Role
		permission Permission
		want       bool
	}{
		{authn.RoleViewer, PermissionAssetRead, true},
		{authn.RoleViewer, PermissionAssetManage, false},
		{authn.RoleSRE, PermissionAssetRead, true},
		{authn.RoleSRE, PermissionAssetBind, false},
		{authn.RoleServiceOwner, PermissionAssetRead, true},
		{authn.RoleServiceOwner, PermissionAssetBind, true},
		{authn.RoleApprover, PermissionAssetRead, true},
		{authn.RoleAuditor, PermissionAssetRead, true},
		{authn.RoleAdmin, PermissionAssetManage, true},
		{authn.RoleAdmin, PermissionAssetBind, true},
		{authn.RoleAdmin, PermissionAssetConflictResolve, true},
	}
	for _, test := range tests {
		got := roleAllows(test.role, test.permission)
		if got != test.want {
			t.Errorf("roleAllows(%s, %s) = %t, want %t", test.role, test.permission, got, test.want)
		}
	}
}
~~~

Run: `go test ./internal/authn ./internal/authz -count=1`

Expected: FAIL because `RoleViewer` and asset permissions do not exist.

- [ ] **Step 2: Extend roles and permissions without weakening existing policy**

Add `RoleViewer Role = "VIEWER"` to `authn`, accept it in `normalizeRoles`, and leave all scope/time normalization unchanged. Add:

~~~go
const (
	PermissionAssetRead            Permission = "ASSET_READ"
	PermissionAssetManage          Permission = "ASSET_MANAGE"
	PermissionAssetBind            Permission = "ASSET_BIND"
	PermissionAssetConflictResolve Permission = "ASSET_CONFLICT_RESOLVE"
)
~~~

Update `roleAllows` exactly as tested. `PermissionAssetBind` must set `requiresService=true`; `SERVICE_OWNER` still passes only when `request.ServiceID` is present in `principal.ServiceIDs`. `AssetManage` and `AssetConflictResolve` are ADMIN-only. Asset permissions do not require recent reauthentication in this slice; later Connection publication does.

- [ ] **Step 3: Write failing management authorization and projection tests**

~~~go
func TestManagementDoesNotCallRepositoryWhenUnauthorized(t *testing.T) {
	repository := &recordingRepository{}
	manager := mustManagement(repository, fixedAuthorizer())
	principal := principalWithRole(authn.RoleViewer)

	_, err := manager.CreateAsset(context.Background(), principal, validCreateRequest())
	if !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("CreateAsset error = %v", err)
	}
	if repository.calls != 0 {
		t.Fatalf("repository calls = %d", repository.calls)
	}
}

func TestEffectiveActionsComeFromAuthorizationAndObjectState(t *testing.T) {
	repository := &recordingRepository{asset: validAsset()}
	manager := mustManagement(repository, fixedAuthorizer())
	admin := principalWithRole(authn.RoleAdmin)

	view, err := manager.GetAsset(context.Background(), admin, validLocatorRequest())
	if err != nil {
		t.Fatal(err)
	}
	want := []EffectiveAction{ActionEditGovernance, ActionQuarantine, ActionRetire}
	if !slices.Equal(view.EffectiveActions, want) {
		t.Fatalf("effective actions = %v, want %v", view.EffectiveActions, want)
	}
}
~~~

Run: `go test ./internal/assetcatalog -run 'TestManagement|TestEffectiveActions' -count=1`

Expected: FAIL because the management service does not exist.

- [ ] **Step 4: Implement four narrow managers**

~~~go
type EffectiveAction string

const (
	ActionCreateAsset    EffectiveAction = "CREATE_ASSET"
	ActionEditGovernance EffectiveAction = "EDIT_GOVERNANCE"
	ActionQuarantine     EffectiveAction = "QUARANTINE"
	ActionRetire         EffectiveAction = "RETIRE"
	ActionCreateBinding  EffectiveAction = "CREATE_BINDING"
	ActionDeleteBinding  EffectiveAction = "DELETE_BINDING"
	ActionResolveConflict EffectiveAction = "RESOLVE_CONFLICT"
)

type AssetView struct {
	Asset            Asset
	EffectiveActions []EffectiveAction
}

type AssetMutationView struct {
	View    AssetView
	Receipt MutationReceipt
}

type AssetManager interface {
	ListAssets(context.Context, authn.Principal, ListAssetsRequest) (AssetViewPage, error)
	GetAsset(context.Context, authn.Principal, AssetLocator) (AssetView, error)
	CreateAsset(context.Context, authn.Principal, CreateAssetCommand) (AssetMutationView, error)
	UpdateAsset(context.Context, authn.Principal, UpdateGovernanceCommand) (AssetMutationView, error)
	QuarantineAsset(context.Context, authn.Principal, TransitionCommand) (AssetMutationView, error)
	RetireAsset(context.Context, authn.Principal, TransitionCommand) (AssetMutationView, error)
}
~~~

Implement equivalent narrow interfaces for source, conflict, relation, and binding operations. Every method must:

1. validate UUIDs/limits/request hashes before authorization;
2. resolve database scope and compare it with Principal workspace/environment scope;
3. call `authz.Authorize` for the exact permission and service ID;
4. call one repository method only after authorization succeeds;
5. derive sorted, duplicate-free `effective_actions` from both authorization and current object state;
6. remove `EDIT_GOVERNANCE` from RETIRED, remove `QUARANTINE` from QUARANTINED/RETIRED, remove `RETIRE` from RETIRED, and expose no mapping decision action on closed conflicts;
7. return domain errors without database/provider/credential text.

For a principal whose only applicable role is `SERVICE_OWNER`, list/get queries must be constrained to `principal.ServiceIDs` through an ACTIVE Service Binding, and bind operations require the requested Service ID in that same set. Perform this inside the scoped Repository query/transaction, not by filtering an already-loaded cross-service page. Unauthorized direct IDs return the same non-enumerating projection as not-found.

This pack's Source manager is read-only (`ListSources/GetSource/GetSourceRun`) and returns no Source mutation action. Stable Source creation must atomically create revision 1 from an installed server-owned `SourceProfile`; validation, publication and `RequestSync` all depend on the complete immutable binding and therefore belong exclusively to Tasks 13–14 in [05-source-ingestion-csv-api.md](./05-source-ingestion-csv-api.md). Pack 03 must not implement a reduced create/sync path or accept ProviderKind/Integration/sync fields directly.

- [ ] **Step 5: Run unit and race tests**

Run: `gofmt -w internal/authn internal/authz internal/assetcatalog && go test -race ./internal/authn ./internal/authz ./internal/assetcatalog -count=1`

Expected: PASS, including existing auth tests, service-owner ownership checks, forbidden-before-repository checks, deterministic effective actions, and fail-closed missing dependency tests.

- [ ] **Step 6: Commit**

~~~bash
git add internal/authn/authenticator.go internal/authn/authenticator_test.go \
  internal/authz/authorizer.go internal/authz/authorizer_test.go \
  internal/assetcatalog/management.go internal/assetcatalog/management_test.go
git commit -m "feat(assetcatalog): authorize governed asset operations"
~~~

### Task 7: Control Plane OpenAPI 3.1 contract and shared HTTP safety primitives

**Files:**
- Create: **api/openapi/control-plane-v1.yaml**
- Create: **api/openapi/control_plane_v1_test.go**
- Create: **internal/httpapi/control_plane_contract.go**
- Create: **internal/httpapi/control_plane_contract_test.go**
- Modify: **internal/httpapi/router.go**
- Modify: **internal/httpapi/router_test.go**

**Interfaces:**
- Produces: the sole browser contract at `api/openapi/control-plane-v1.yaml`; later frontend generation consumes this exact file.
- Produces these shared symbols for all Control Plane plans:
  - `parseIdempotencyKey(*http.Request) (string, error)`
  - `parseVersionETag(*http.Request, resourceType, resourceID string) (int64, error)`
  - `writeVersionETag(http.ResponseWriter, resourceType, resourceID string, version int64)`
  - `controlPlaneCursor{Kind, Sort, Value, ID string}` plus signed encode/decode
  - `decodeStrictJSON(http.ResponseWriter, *http.Request, any, int64) error`
  - `writeRequestProblem(http.ResponseWriter, *http.Request, int, string, string)`
- Produces `NewControlPlaneCursorCodec([]byte) (*ControlPlaneCursorCodec, error)`; `cmd/control-plane` constructs it from a dedicated 32-byte secret and injects it into `httpapi.Dependencies`.
- Consumers must not create a second cursor, ETag, Problem, or strict-JSON implementation.

- [ ] **Step 1: Write failing OpenAPI safety tests**

~~~go
package openapi_test

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestControlPlaneContractHasExactAssetRoutes(t *testing.T) {
	raw, document := readControlPlaneContract(t)
	required := []string{
		"/api/v1/workspaces/{workspace_id}/environments/{environment_id}/assets",
		"/api/v1/workspaces/{workspace_id}/environments/{environment_id}/assets/{asset_id}",
		"/api/v1/workspaces/{workspace_id}/environments/{environment_id}/assets/{asset_id}:quarantine",
		"/api/v1/workspaces/{workspace_id}/environments/{environment_id}/assets/{asset_id}:retire",
		"/api/v1/workspaces/{workspace_id}/environments/{environment_id}/asset-relations",
		"/api/v1/workspaces/{workspace_id}/environments/{environment_id}/service-asset-bindings",
		"/api/v1/workspaces/{workspace_id}/environments/{environment_id}/service-asset-bindings/{binding_id}",
		"/api/v1/workspaces/{workspace_id}/asset-sources",
		"/api/v1/workspaces/{workspace_id}/asset-sources/{source_id}",
		"/api/v1/workspaces/{workspace_id}/asset-source-runs/{run_id}",
		"/api/v1/workspaces/{workspace_id}/asset-conflicts",
		"/api/v1/workspaces/{workspace_id}/asset-conflicts/{conflict_id}:resolve",
	}
	paths := document["paths"].(map[string]any)
	for _, path := range required {
		if _, ok := paths[path]; !ok {
			t.Errorf("missing path %s", path)
		}
	}
	for _, forbidden := range []string{
		"secret", "password", "access_token", "refresh_token", "private_key",
		"dsn", "connection_string", "raw_payload", "normalized_document",
		"arbitrary_header", "command_text", "sql_text", "request_body",
	} {
		if strings.Contains(strings.ToLower(string(raw)), forbidden+":") {
			t.Errorf("browser contract contains forbidden field %s", forbidden)
		}
	}
}

func TestEveryObjectSchemaIsClosedAndEveryErrorReferencesProblem(t *testing.T) {
	_, document := readControlPlaneContract(t)
	assertClosedObjects(t, "#", document)
	assertErrorResponsesUseProblem(t, document)
}

func readControlPlaneContract(t *testing.T) ([]byte, map[string]any) {
	t.Helper()
	raw, err := os.ReadFile("control-plane-v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	return raw, document
}
~~~

Run: `go test ./api/openapi -run 'TestControlPlane' -count=1`

Expected: FAIL because `control-plane-v1.yaml` does not exist.

- [ ] **Step 2: Create the exact OpenAPI envelope**

Create a valid OpenAPI 3.1 document with `jsonSchemaDialect`, global OIDC security, UUID path parameters, signed Cursor/Limit, required Idempotency-Key/If-Match, RFC 9457 `Problem`, `PageMeta`, and the fixed `EffectiveAction` enum. Every object uses `additionalProperties: false`, explicit `required`, bounded strings/arrays, and no secret-bearing field.

The Phase 1 Pack 03 action enum is exactly `CREATE_ASSET`、`EDIT_GOVERNANCE`、`QUARANTINE`、`RETIRE`、`CREATE_BINDING`、`DELETE_BINDING`、`RESOLVE_CONFLICT`. Tasks 13–14 extend the same enum with governed Source/Revision actions only when their production mutation path exists.

Define closed schemas with explicit required arrays for:

- `AssetSummary`、`AssetDetail`、`AssetPage`、`CreateAssetRequest`、`PatchAssetRequest`、`TransitionAssetRequest`;
- `AssetRelationSummary`、`AssetRelationPage`;
- `ServiceAssetBindingSummary`、`ServiceAssetBindingPage`、`CreateServiceAssetBindingRequest`;
- `AssetSourceSummary`、`AssetSourceDetail`、`AssetSourcePage`;
- `AssetSourceRun`;
- `AssetConflictSummary`、`AssetConflictDetail`、`AssetConflictPage`、`ResolveAssetConflictRequest`;
- `Problem` and page metadata.

Every successful write body uses a resource-specific result schema containing the safe resource plus `mutation_receipt{audit_id,trace_id,idempotent_replay}`. Binding delete returns `204` with `X-Audit-ID` and `X-Idempotent-Replay`; all other write receipts are in JSON. Audit IDs are opaque UUIDs and reveal no payload.

The Assets list query defines `sort` as the closed enum `display_name_asc|last_observed_at_desc`; the signed cursor embeds that sort and cannot be replayed with another sort or endpoint.

Because the confirmed conflict route is Workspace-scoped, `GET .../asset-conflicts` requires an `environment_id` UUID query parameter. Resolve loads the conflict first by Tenant+Workspace+ID, obtains its Environment, then authorizes that Environment without revealing cross-scope existence. Source/source-run routes remain Workspace-scoped and return only environments allowed by the Principal.

`AssetSummary` includes only `id`、`environment_id`、`display_name`、`external_id`、`kind`、`provider_kind`、`source{id,name,kind}`、`service_summaries`、`mapping_status`、`lifecycle`、`owner_group`、`criticality`、`data_classification`、`labels`、`connection_summary.status`、`capability_summary.status/count`、`last_observed_at`、`version`、`effective_actions`. Until 000016/000017 are implemented, both summaries use the explicit neutral state `NOT_CONFIGURED`, never inferred health. `AssetDetail` adds safe field provenance and relation counts; it does not add Provider JSON.

`AssetPage` includes collection-level `effective_actions` so the frontend can gate `CREATE_ASSET` without role inference. Pack 03 returns an empty collection action list for `AssetSourcePage`; Tasks 13–14 add `CREATE_SOURCE` only with the complete Source+revision-1 transaction. `AssetConflictPage.items` uses the safe detail projection required by the mapping comparison (field name, source/revision/time, existing/candidate safe values, impact counts) but never returns raw documents or fingerprint values.

Every write operation references both Idempotency-Key and, for mutation/delete/decision, If-Match. Status codes are fixed:

- list/get `200`;
- asset/binding create `201`;
- patch/transition/decision `200`;
- binding delete `204`;
- malformed `400`, unauthenticated `401`, forbidden `403`, not found `404`, version/idempotency `409`, unsupported content type `415`, too large `413`, unavailable `503`.

Every response references `Problem` for error statuses and declares:

~~~yaml
headers:
  Cache-Control:
    schema: {type: string, const: no-store}
  X-Content-Type-Options:
    schema: {type: string, const: nosniff}
  X-Trace-ID:
    schema: {type: string, pattern: '^[a-f0-9]{32}$'}
~~~

- [ ] **Step 3: Write failing strict-body, ETag, cursor, and Problem tests**

~~~go
func TestDecodeStrictJSONRejectsDuplicateUnknownAndTrailingValues(t *testing.T) {
	cases := []string{
		`{"reason":"a","reason":"b"}`,
		`{"reason":"a","unknown":true}`,
		`{"reason":"a"}{"reason":"b"}`,
	}
	for _, body := range cases {
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		var target struct {
			Reason string `json:"reason"`
		}
		if err := decodeStrictJSON(recorder, request, &target, 1024); err == nil {
			t.Fatalf("body %q was accepted", body)
		}
	}
}

func TestVersionETagRejectsWeakWildcardAndWrongResource(t *testing.T) {
	for _, value := range []string{`W/"asset:a:v2"`, "*", `"source:a:v2"`, `"asset:b:v2"`, `"asset:a:v0"`} {
		request := httptest.NewRequest(http.MethodPatch, "/", nil)
		request.Header.Set("If-Match", value)
		if _, err := parseVersionETag(request, "asset", "a"); err == nil {
			t.Errorf("If-Match %s was accepted", value)
		}
	}
}

func TestCursorCodecRejectsTamperingAndKindConfusion(t *testing.T) {
	codec := mustCursorCodec([]byte("0123456789abcdef0123456789abcdef"))
	encoded := codec.encode(controlPlaneCursor{
		Kind: "assets", Sort: "display_name", Value: "api", ID: "11111111-1111-4111-8111-111111111111",
	})
	if _, err := codec.decode(encoded+"x", "assets"); err == nil {
		t.Fatal("tampered cursor was accepted")
	}
	if _, err := codec.decode(encoded, "conflicts"); err == nil {
		t.Fatal("cross-endpoint cursor was accepted")
	}
}
~~~

Run: `go test ./internal/httpapi -run 'Test(DecodeStrictJSON|VersionETag|CursorCodec)' -count=1`

Expected: FAIL because the shared helpers do not exist.

- [ ] **Step 4: Implement a single strict contract boundary**

~~~go
var idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$`)

func parseIdempotencyKey(request *http.Request) (string, error) {
	values := request.Header.Values("Idempotency-Key")
	if len(values) != 1 || !idempotencyKeyPattern.MatchString(values[0]) {
		return "", errInvalidControlPlaneRequest
	}
	return values[0], nil
}

func decodeStrictJSON(
	writer http.ResponseWriter,
	request *http.Request,
	target any,
	maxBytes int64,
) error {
	contentType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		return errUnsupportedControlPlaneMediaType
	}
	raw, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, maxBytes))
	if err != nil {
		return errControlPlaneBodyTooLarge
	}
	if len(raw) == 0 || rejectDuplicateJSONKeys(raw) != nil {
		return errInvalidControlPlaneRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errInvalidControlPlaneRequest
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errInvalidControlPlaneRequest
	}
	return nil
}
~~~

`rejectDuplicateJSONKeys` must recursively walk decoder tokens, maintain a key set per object, support nested objects/arrays, and reject depth greater than 32. Fuzz it with arbitrary bytes and assert it never panics. ETag format is exactly `"resourceType:resourceID:vN"`; reject weak, wildcard, comma-separated, mismatched and non-positive versions.

The cursor codec must encode canonical JSON followed by HMAC-SHA256 using a dedicated 32-byte configuration secret, then base64url without padding. Decode validates total length ≤2048, MAC using `hmac.Equal`, exact kind, allowed sort, canonical UUID, and bounded value.

`writeRequestProblem` obtains trace ID from `requestmeta`, uses `about:blank`, stable public detail, and never interpolates an internal error. Add an API middleware:

~~~go
func controlPlaneResponseHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.URL.Path, "/api/v1/") {
			writer.Header().Set("Cache-Control", "no-store")
			writer.Header().Set("Pragma", "no-cache")
			writer.Header().Set("X-Content-Type-Options", "nosniff")
			writer.Header().Set("Referrer-Policy", "no-referrer")
		}
		next.ServeHTTP(writer, request)
	})
}
~~~

Register it after request ID middleware and before routing, replacing the credential-only header middleware with this general one while preserving all existing tests.

- [ ] **Step 5: Validate the contract and helper fuzz/race tests**

Run:

~~~bash
gofmt -w api/openapi internal/httpapi
go test -race ./api/openapi ./internal/httpapi -count=1
go test ./internal/httpapi -run Fuzz -fuzz FuzzRejectDuplicateJSONKeys -fuzztime 5s
~~~

Expected: PASS; malformed JSON never reaches a manager, all Problems contain the request trace ID, all `/api/v1` success/error responses are no-store/nosniff, and existing health/webhook/session/revocation tests remain green.

- [ ] **Step 6: Commit**

~~~bash
git add api/openapi/control-plane-v1.yaml api/openapi/control_plane_v1_test.go \
  internal/httpapi/control_plane_contract.go internal/httpapi/control_plane_contract_test.go \
  internal/httpapi/router.go internal/httpapi/router_test.go
git commit -m "feat(api): define safe control plane contract"
~~~

### Task 8: Asset, discovery, conflict, relation, and binding HTTP handlers

**Files:**
- Create: **internal/httpapi/assets.go**
- Create: **internal/httpapi/assets_test.go**
- Create: **internal/httpapi/asset_sources.go**
- Create: **internal/httpapi/asset_sources_test.go**
- Create: **internal/httpapi/asset_conflicts.go**
- Create: **internal/httpapi/asset_conflicts_test.go**
- Create: **internal/httpapi/service_asset_bindings.go**
- Create: **internal/httpapi/service_asset_bindings_test.go**
- Modify: **internal/httpapi/router.go**
- Modify: **internal/httpapi/router_test.go**
- Modify: **cmd/control-plane/main.go**
- Create: **cmd/control-plane/main_test.go**

**Interfaces:**
- Consumes: manager interfaces from Task 6 and shared HTTP helpers from Task 7.
- Produces: every route listed in OpenAPI Task 7, with no alternate unscoped route; Source routes in this pack are GET-only.
- Assembly: `httpapi.Dependencies` gains `Assets`、`AssetSources`、`AssetConflicts`、`ServiceAssetBindings`; nil managers fail closed with `503`, never panic and never silently expose a partial write route.

- [ ] **Step 1: Write failing route/authentication/DTO tests**

~~~go
func TestAssetRoutesRequireAuthenticationAndPreserveScope(t *testing.T) {
	manager := &recordingAssetManager{page: safeAssetPage()}
	router := NewRouter(Dependencies{
		Version: "test", Authenticator: acceptingAuthenticator(),
		Assets: manager,
	})
	path := "/api/v1/workspaces/33333333-3333-4333-8333-333333333333/" +
		"environments/44444444-4444-4444-8444-444444444444/assets?limit=25"

	unauthenticated := httptest.NewRecorder()
	router.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, path, nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", unauthenticated.Code)
	}

	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("Authorization", "Bearer test")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if manager.request.Scope.WorkspaceID != "33333333-3333-4333-8333-333333333333" ||
		manager.request.Scope.EnvironmentID != "44444444-4444-4444-8444-444444444444" {
		t.Fatalf("scope = %#v", manager.request.Scope)
	}
}

func TestAssetDTOContainsNoRuntimeOrCredentialMaterial(t *testing.T) {
	raw, err := json.Marshal(toAssetDetailDTO(safeAssetView()))
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(raw))
	for _, forbidden := range []string{
		"secret", "token", "password", "private_key", "dsn", "endpoint",
		"normalized_document", "raw_payload", "command", "sql", "header", "request_body",
	} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("asset DTO contains %q: %s", forbidden, lower)
		}
	}
}
~~~

Run: `go test ./internal/httpapi -run 'TestAssetRoutes|TestAssetDTO' -count=1`

Expected: FAIL because route dependencies, handlers, and DTOs do not exist.

- [ ] **Step 2: Implement typed DTO conversion and error mapping**

Define private HTTP DTO structs matching OpenAPI names exactly. Do not JSON-marshal domain structs. The core asset conversion has this shape:

~~~go
type assetSummaryDTO struct {
	ID                 string                   `json:"id"`
	EnvironmentID      string                   `json:"environment_id"`
	DisplayName        string                   `json:"display_name"`
	ExternalID         string                   `json:"external_id"`
	Kind               string                   `json:"kind"`
	ProviderKind       string                   `json:"provider_kind"`
	Source             sourceReferenceDTO       `json:"source"`
	Services           []serviceReferenceDTO    `json:"service_summaries"`
	MappingStatus      string                   `json:"mapping_status"`
	Lifecycle          string                   `json:"lifecycle"`
	OwnerGroup         string                   `json:"owner_group"`
	Criticality        string                   `json:"criticality"`
	DataClassification string                   `json:"data_classification"`
	Labels             map[string]string        `json:"labels"`
	LastObservedAt     time.Time                `json:"last_observed_at"`
	Version            int64                    `json:"version"`
	EffectiveActions   []string                 `json:"effective_actions"`
}
~~~

Clone maps/slices, normalize empty collections to `[]`/`{}`, and express absent optional values as JSON `null` only where OpenAPI allows null.

Write handlers convert typed manager mutation results to `{resource,mutation_receipt}` and never synthesize an audit ID. `mutation_receipt.trace_id` must equal the request trace; replay returns the original audit ID with `idempotent_replay=true`.

One `writeAssetCatalogError` maps:

- invalid/cursor/body/idempotency/ETag syntax → `400 invalid_request`;
- unauthenticated → `401 authentication_required`;
- authorization/scope violation → `403 asset_scope_forbidden`;
- not found → `404 asset_not_found` or resource-specific stable code;
- version conflict → `409 version_conflict`;
- idempotency hash mismatch → `409 idempotency_conflict`;
- state conflict → `409 invalid_asset_state`;
- unavailable manager/database → `503 asset_catalog_unavailable`;
- all other errors → `500 asset_catalog_failed`.

It logs the internal error with trace ID server-side and passes only stable detail to `writeRequestProblem`.

- [ ] **Step 3: Implement exact asset and relation handlers**

Register under one authenticated route group:

~~~go
router.Route("/api/v1", func(api chi.Router) {
	api.Use(authenticationMiddleware(deps.Authenticator))
	api.Get("/workspaces/{workspaceID}/environments/{environmentID}/assets", listAssetsHandler(deps.Assets, cursorCodec))
	api.Post("/workspaces/{workspaceID}/environments/{environmentID}/assets", createAssetHandler(deps.Assets))
	api.Get("/workspaces/{workspaceID}/environments/{environmentID}/assets/{assetID}", getAssetHandler(deps.Assets))
	api.Patch("/workspaces/{workspaceID}/environments/{environmentID}/assets/{assetID}", patchAssetHandler(deps.Assets))
	api.Post("/workspaces/{workspaceID}/environments/{environmentID}/assets/{assetID}:quarantine", quarantineAssetHandler(deps.Assets))
	api.Post("/workspaces/{workspaceID}/environments/{environmentID}/assets/{assetID}:retire", retireAssetHandler(deps.Assets))
	api.Get("/workspaces/{workspaceID}/environments/{environmentID}/asset-relations", listAssetRelationsHandler(deps.ServiceAssetBindings, cursorCodec))
})
~~~

Handlers validate all UUIDs before manager calls. List supports only OpenAPI filters and signed cursor; duplicate query keys are rejected. POST/PATCH accept a maximum 64 KiB strict JSON body and compute request hash over canonical typed input plus scoped path. PATCH/quarantine/retire parse If-Match. Create and every state-changing POST parse Idempotency-Key. Successful create emits `Location`; all versioned object responses emit strong ETag.

Manual create body contains an existing `source_id` plus `kind`、`external_id`、`display_name`、governance fields and bounded labels. Management locks the Source and exact published revision and requires same Workspace、`source_kind=MANUAL`、`provider_kind=MANUAL`、`ACTIVE + PUBLISHED + AVAILABLE` and exact gate/revision/binding digests before creating the Asset. Because `MANUAL_V1` is `SINGLE_ENVIRONMENT`, the path/command Environment must also equal the revision's sole locked `AuthorityEnvironmentID`；same Workspace is not sufficient. ProviderKind is derived from that Source and is not caller-controlled. Repository then performs the private fenced `MANUAL_MUTATION`/`CATALOG_SEQUENCE` transaction defined by Pack 02；the handler never constructs or accepts Observation JSON, Source revision, freshness/time, Run/fence/checkpoint, endpoint, credential reference, provider payload, service binding, lifecycle, mapping status or version. Add a negative handler/integration test proving Env-A's eligible MANUAL Source is invisible/ineligible on Env-B and cannot allocate a mutation Run.

Pack 03 does not bootstrap or silently insert a MANUAL Source. Tests may seed one only in an isolated test database. In production, `CREATE_ASSET` is absent from an Environment collection's `effective_actions` unless an already provisioned MANUAL Source has that exact eligible state **and** its sole authority Environment equals the path Environment；the eligible-source lookup applies the same filter server-side. Task 13/16's complete profile/revision/validation/publication path is the first in-project way to provision it. Before then, the POST route remains fail-closed and the Web UI explains that no eligible MANUAL Source exists rather than inventing a reduced source path.

- [ ] **Step 4: Implement read-only source/run handlers without premature mutation paths**

Register only `GET /asset-sources`、`GET /asset-sources/{source_id}` and `GET /asset-source-runs/{run_id}`. They expose safe metadata, orthogonal Source/Revision/Gate status, checkpoint hash/version/age, exact last-success/last-complete Run pointers, Run status `QUEUED|DELAYED|RUNNING|FINALIZING|SUCCEEDED|PARTIAL|FAILED|CANCELLED`, stable stage `WAITING|DELAYED|VALIDATING|READING|NORMALIZING|APPLYING|CLEANING_UP|COMPLETED`, final/effective-complete-snapshot flags, cleanup status and exact count set. Source list `last_run_counts` is bound only to `last_success_run_id`（therefore only `SUCCEEDED`）；`current_run_counts` is bound only to the single current nonterminal Run when present；neither is an aggregate, and a `PARTIAL` Run is visible in history but does not replace `last_run_counts`. They never expose canonical bytes, checkpoint ciphertext/key ID, cleanup attempt ID/digest, lease identity/token hash or Provider text. Optional closed query `usage=manual_asset_create&environment_id=<path-environment>` is evaluated server-side and returns only exact eligible MANUAL Sources whose sole authority Environment matches, with `CREATE_ASSET` in their `effective_actions`；it is not a browser status inference. There is no POST Source or sync handler, no mutation method in the manager, and no DNS/HTTP/TCP/provider SDK/credential/Runner dependency in this pack. Tasks 13–14 add the complete Source+revision create and sync routes atomically；`MANUAL` never receives `SYNC_SOURCE` and manual assets continue to use the governed Asset API.

- [ ] **Step 5: Implement conflict decisions and Service Binding handlers**

Conflict resolution body is a closed discriminated request:

~~~go
type resolveAssetConflictRequest struct {
	Resolution  string `json:"resolution"`
	ServiceID   string `json:"service_id"`
	BindingRole string `json:"binding_role"`
	Reason      string `json:"reason"`
}
~~~

For `REJECT_CANDIDATE`、`KEEP_UNRESOLVED` and `QUARANTINE_ASSET`, service/role must be empty; for `CONFIRM_EXACT`, both are required. Resolution requires Idempotency-Key and If-Match, and returns conflict plus optional binding and their ETags in the body; the primary `ETag` is the conflict ETag.

Binding create requires Idempotency-Key and body `{service_id, asset_id, role, reason}`. Binding delete requires Idempotency-Key plus If-Match, accepts no body, and returns `204` only after server confirmation or an identical replay.

- [ ] **Step 6: Assemble only real dependencies in the Control Plane**

In `cmd/control-plane/main.go`:

1. build the PostgreSQL asset repository after the existing pool is ready;
2. build `authz.Authorizer` with existing recent-auth configuration;
3. build asset/source/conflict/binding managers with the repository;
4. load a dedicated 32-byte cursor HMAC secret from environment/config as a secret reference, never log its value;
5. inject all managers and cursor codec into `httpapi.Dependencies`;
6. if OIDC verifier, pool, authorizer, or cursor secret is absent/invalid, keep `/healthz` available but asset API requests return fail-closed `503`; startup must not install unauthenticated fallbacks;
7. do not start a source connector or target network client in the Control Plane.

Add an assembly test that calls a real router with in-memory fakes and proves dependency omission returns `503` for every asset write route.

- [ ] **Step 7: Run handler, router, assembly, and contract conformance tests**

Run:

~~~bash
gofmt -w internal/httpapi cmd/control-plane
go test -race ./internal/httpapi ./cmd/control-plane ./api/openapi -count=1
go test ./internal/httpapi -run 'TestAsset.*(CrossScope|Duplicate|Unknown|ETag|Idempotency|NoStore)' -count=1
~~~

Expected: PASS. Every OpenAPI operation has a router test; body/request/response examples validate against the OpenAPI schemas; deep links outside Principal scope return a non-enumerating 403/404 projection; no safe DTO test finds forbidden fields.

- [ ] **Step 8: Commit**

~~~bash
git add internal/httpapi/assets.go internal/httpapi/assets_test.go \
  internal/httpapi/asset_sources.go internal/httpapi/asset_sources_test.go \
  internal/httpapi/asset_conflicts.go internal/httpapi/asset_conflicts_test.go \
  internal/httpapi/service_asset_bindings.go internal/httpapi/service_asset_bindings_test.go \
  internal/httpapi/router.go internal/httpapi/router_test.go \
  cmd/control-plane/main.go cmd/control-plane/main_test.go
git commit -m "feat(api): expose governed asset control plane"
~~~
