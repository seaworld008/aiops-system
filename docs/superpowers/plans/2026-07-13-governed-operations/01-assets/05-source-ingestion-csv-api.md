# Asset Source Revisions, CSV Import, and Control Plane API Ingestion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把发现来源从枚举和手工触发补齐为不可变 Source Revision、隔离验证、发布门、签名 CSV 导入与 mTLS Control Plane API 增量写入的生产入口。

**Architecture:** `asset_sources` 只保存稳定身份、已发布修订指针、checkpoint 和 gate；`asset_source_revisions` 保存 server-canonical、content-addressed、发布后不可变的安全配置。CSV 与 API 先通过来源专属 parser/schema、身份、签名、DLP 和限额，再产生相同的 fenced `assetdiscovery.Batch`；浏览器和调用方都不能提交 endpoint、Secret、任意 Header/Body 或原始 Provider 配置。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4、pgx v5、OpenAPI 3.1、chi v5、mTLS/JWS SHA-256、RFC 4180 CSV、React 19.2.7、TypeScript 7.0.2、Playwright 1.61.1。

## Global Constraints

- 前置依次为 [01-schema-domain.md](./01-schema-domain.md)、[02-repository-discovery.md](./02-repository-discovery.md)、[03-mapping-auth-api.md](./03-mapping-auth-api.md) 和 [04-web-foundation-assets.md](./04-web-foundation-assets.md)。
- `asset_source_revisions` 属于 `000015_assets_catalog`；本包不得创建 `000016` 或平行修订表。
- Source 状态、Revision 状态、Validation/Discovery Run 状态与 per-provider Gate 状态正交，前端不得合并成一个绿色状态。
- 仅 exact `PUBLISHED` revision 且 source `ACTIVE + AVAILABLE` 可创建 Discovery Run；修订、引用、作用域、身份、checkpoint 或 gate 漂移立即停止。
- 每个 revision 只保存 opaque `CredentialReferenceID`、`TrustReferenceID`、`NetworkPolicyReferenceID` 和 server-owned canonical `ProfileCode`；输入 `SourceProfileID` 只用于 Registry 解析，并将解析结果的 immutable canonical code 持久为 `profile_code`、纳入 `BindingDigest`。不保存 Secret、Token、私钥、PEM、完整 endpoint 或任意 JSON。
- `MANUAL` 由已有受治理 `POST .../assets` 提供，不进入 Discovery Worker；`KUBERNETES_OPERATOR` 仅由 Phase 3 提供，在此保持 `UNAVAILABLE`。
- CSV/API 都必须产生 field-level provenance、显式 tombstone、增量 cursor/checkpoint，且恢复只能 `STALE→STALE(pending revalidation)`，不能自动 `ACTIVE`。
- 写请求需 `Idempotency-Key`，修订转换需 `If-Match`，发布/禁用需服务器校验最近 OIDC 认证；workload ingestion 只用 mTLS 身份，不接受浏览器 Token。
- API 只返回安全摘要、稳定 error code、Trace ID 和 `effective_actions`；不返回原始 CSV 行、JWS、cursor、Provider 错误或上游响应。
- 每个 Task 严格 Red → Green → Refactor；生产实现不得使用 memory repository、MSW 或测试身份。
- 完成后进入 [06-source-external-cmdb.md](./06-source-external-cmdb.md)。

---

### Task 13: Immutable source revision repository, validation request, publication, and disable gate

**Files:**
- Modify: `internal/assetcatalog/types.go`
- Modify: `internal/assetcatalog/repository.go`
- Create: `internal/assetcatalog/source_revision.go`
- Create: `internal/assetcatalog/source_revision_test.go`
- Create: `internal/discoverysource/contracts.go`
- Create: `internal/discoverysource/contracts_test.go`
- Create: `internal/assetcatalog/postgres/source_revisions.go`
- Create: `internal/assetcatalog/postgres/source_revisions_test.go`
- Create: `internal/assetcatalog/postgres/source_revisions_integration_test.go`

**Interfaces:**
- Consumes: `asset_sources`, `asset_source_revisions`, `asset_source_runs` schema plus scoped audit/outbox/idempotency ledger from Tasks 1–4; an existing stable Source is required only for subsequent revisions.
- Produces: `SourceRevisionRepository.CreateSource/CreateRevision/RequestValidation/Publish/Disable/RequestSync` and exact source/revision `ETag` versions. `CreateSource` is the sole production owner of atomic stable Source + immutable revision 1 creation.
- Produces events: `asset.source.revision.created.v1`, `asset.source.validation.requested.v1`, `asset.source.revision.published.v1`, `asset.source.disabled.v1`, `asset.source.sync.requested.v1`.
- Produces the only Provider data-plane contract consumed by every later source pack:

~~~go
type Provider interface {
	Kind() assetcatalog.SourceKind
	ProviderKind() string
	Validate(context.Context, BoundRuntime, ValidationRequest) (ValidationProof, error)
	Discover(context.Context, BoundRuntime, DiscoverRequest) (Page, error)
}

type DiscoverRequest struct {
	Locator              SourceLocator
	SourceRevision       int64
	SourceRevisionDigest string
	Fence                LeaseFence
	Checkpoint           Checkpoint
	Limits               Limits
}

type Page struct {
	Items          []assetdiscovery.NormalizedItem
	NextCheckpoint Checkpoint
	Complete       bool
	RetryAfter     time.Duration
}
~~~

`BoundRuntime` is created only inside `cmd/discovery-worker` from the exact published revision/profile and workload secret binding; it is deliberately non-serializable and implements `Close/Clear`. `DiscoverRequest`, queue payload, Temporal history, audit and logs contain no endpoint, credential, CA, header or Provider request body.

- [ ] **Step 1: Write failing revision immutability and publication-gate tests**

~~~go
func TestPublishSourceRevisionRequiresMatchingSuccessfulValidation(t *testing.T) {
	db := openAssetCatalogDatabase(t)
	fixture := seedSourceWithDraftRevision(t, db)
	repository := newAssetRepository(t, db)

	_, err := repository.PublishSourceRevision(context.Background(), assetcatalog.PublishSourceRevisionCommand{
		TenantID: fixture.TenantID, WorkspaceID: fixture.WorkspaceID,
		SourceID: fixture.SourceID, Revision: 2, ExpectedSourceVersion: 1,
		ExpectedRevisionVersion: 1, ActorID: fixture.AdminSubject,
		IdempotencyKey: fixture.IdempotencyKey, RequestHash: fixture.RequestHash,
	})
	if !errors.Is(err, assetcatalog.ErrSourceRevisionNotValidated) {
		t.Fatalf("PublishSourceRevision error = %v", err)
	}
	assertPublishedRevision(t, db, fixture.SourceID, 0)
}

func TestPublishedSourceRevisionContentCannotChange(t *testing.T) {
	db := openAssetCatalogDatabase(t)
	fixture := seedPublishedSourceRevision(t, db)
	expectSQLState(t, db, "55000", `
		UPDATE asset_source_revisions SET credential_reference_id='other'
		WHERE tenant_id=$1 AND workspace_id=$2 AND source_id=$3 AND revision=$4`,
		fixture.TenantID, fixture.WorkspaceID, fixture.SourceID, fixture.Revision)
}

func TestCreateSourceAtomicallyCreatesRevisionOneAndReceipt(t *testing.T) {
	db := openAssetCatalogDatabase(t)
	repository := newAssetRepository(t, db)
	command := validCreateSourceCommand()

	result, err := repository.CreateSource(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if result.Source.ID == "" || result.Revision.Revision != 1 ||
		result.Revision.CanonicalRevisionDigest != result.Revision.BindingDigest() ||
		result.Receipt.AuditID == "" || result.Receipt.IdempotentReplay {
		t.Fatalf("source creation result = %#v", result)
	}
	assertSourceRevisionCreateSideEffects(t, db, result.Source.ID, 1, 1, 1, 1)
}

func TestCreateSourceRollsBackStableIdentityWhenRevisionBindingIsInvalid(t *testing.T) {
	db := openAssetCatalogDatabase(t)
	repository := newAssetRepository(t, db)
	command := validCreateSourceCommand()
	command.SourceProfileID = "incompatible-profile"

	if _, err := repository.CreateSource(context.Background(), command); !errors.Is(err, assetcatalog.ErrInvalidRequest) {
		t.Fatalf("CreateSource error = %v", err)
	}
	assertSourceRevisionCreateSideEffectsByKey(t, db, command.IdempotencyKey, 0, 0, 0, 0)
}

func TestCreateSourceReplayReturnsOriginalReceiptAndRejectsHashDrift(t *testing.T) {
	db := openAssetCatalogDatabase(t)
	repository := newAssetRepository(t, db)
	command := validCreateSourceCommand()

	first, err := repository.CreateSource(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := repository.CreateSource(context.Background(), command)
	if err != nil || replay.Source.ID != first.Source.ID ||
		replay.Receipt.AuditID != first.Receipt.AuditID || !replay.Receipt.IdempotentReplay {
		t.Fatalf("replay = (%#v, %v), first = %#v", replay, err, first)
	}
	command.RequestHash = strings.Repeat("f", 64)
	if _, err := repository.CreateSource(context.Background(), command); !errors.Is(err, assetcatalog.ErrIdempotency) {
		t.Fatalf("hash-drift replay error = %v", err)
	}
	assertSourceRevisionCreateSideEffects(t, db, first.Source.ID, 1, 1, 1, 1)
}
~~~

Run: `go test ./internal/assetcatalog ./internal/assetcatalog/postgres -run 'Test(CreateSource|Publish|PublishedSource)' -count=1`

Expected: FAIL because source-revision repository and guards do not exist.

- [ ] **Step 2: Define closed commands and safe projections**

~~~go
type SourceRevisionRepository interface {
	CreateSource(context.Context, CreateSourceCommand) (SourceRevisionMutation, error)
	CreateRevision(context.Context, CreateSourceRevisionCommand) (SourceRevisionMutation, error)
	RequestValidation(context.Context, ValidateSourceRevisionCommand) (SourceRun, error)
	PublishSourceRevision(context.Context, PublishSourceRevisionCommand) (SourceRevisionMutation, error)
	DisableSource(context.Context, DisableSourceCommand) (SourceMutation, error)
	RequestSync(context.Context, RequestSyncCommand) (SourceRun, error)
}

type CreateSourceCommand struct {
	TenantID, WorkspaceID          string
	Name                           string
	SourceProfileID                string
	CredentialReferenceID          string
	TrustReferenceID               string
	NetworkPolicyReferenceID       string
	AuthorityEnvironmentIDs        []string
	SyncMode, ScheduleExpression   string
	ActorID, TraceID               string
	IdempotencyKey, RequestHash    string
}

type CreateSourceRevisionCommand struct {
	TenantID, WorkspaceID, SourceID string
	SourceProfileID                 string
	CredentialReferenceID          string
	TrustReferenceID               string
	NetworkPolicyReferenceID       string
	AuthorityEnvironmentIDs        []string
	SyncMode, ScheduleExpression   string
	ExpectedSourceVersion          int64
	ActorID, TraceID               string
	IdempotencyKey, RequestHash    string
}

type SourceRevisionMutation struct {
	Source   Source
	Revision SourceRevision
	Receipt  MutationReceipt
}
~~~

The client never supplies `provider_kind`, canonical definition, revision number, Integration ID, rate/backpressure numbers, profile code, binding digest or revision digest. `SourceProfileRegistry.Resolve(SourceProfileID)` returns one installed discriminated profile, provider kind, Integration ID, allowed SourceKind, network zone, credential purpose, trust mode, parser schema, fixed rate/backpressure fields, immutable canonical `ProfileCode`, hard page/byte limits and compatibility class. `SourceProfileID` is only a lookup selector and is not persisted; the resolved `ProfileCode` is persisted in `asset_source_revisions.profile_code` and is the exact profile identity hashed by `BindingDigest`. The server validates every environment against the source Workspace, sorts it, constructs canonical bytes, allocates `max(revision)+1` under a source row lock, and computes `CanonicalRevisionDigest = SourceRevision.BindingDigest()` across the complete immutable binding. `source_definition_digest` remains a separate digest of the Provider definition only.

- [ ] **Step 3: Implement serializable revision state transitions**

`CreateSource` begins `SERIALIZABLE`, validates Scope/Idempotency/Profile and all opaque references before mutation, locks the Workspace/Profile facts, inserts the stable Source and revision 1, computes and verifies the complete binding digest, writes one audit/outbox pair and returns their persisted receipt in the same transaction. Any invalid Environment/reference/profile/digest or side-effect failure rolls back the Source identity as well as the revision. Matching replay returns the original Source/revision/Audit ID; a changed hash returns `ErrIdempotency`.

`CreateRevision` inserts one `DRAFT` immutable content row for an existing Source. `RequestValidation` CAS-transitions `DRAFT|REJECTED→VALIDATING`, creates a new append-only `VALIDATION` run bound to the exact revision and canonical binding digest, and closes the source gate. A rejected revision's canonical content remains immutable, and it can never transition directly to `PUBLISHED`. A Worker completion may transition only that exact revision/run to `VALIDATED` or `REJECTED`; safe proof fields are identity/TLS-or-signature/network/credential-open+cleanup/fixed-probe/schema/DLP/budget result codes and a proof digest.

`PublishSourceRevision` must require:

1. same Tenant/Workspace, current source/revision versions and a fresh Idempotency-Key;
2. revision `VALIDATED`, terminal successful validation run, matching revision/binding/proof digests and current profile compatibility;
3. current opaque credential/trust/network references are resolvable and not revoked; no secret value is loaded by Control Plane;
4. recent OIDC authentication and `ASSET_SOURCE_PUBLISH` are already attested by management layer;
5. atomically supersede the previous published revision, update source pointer/digest, set source gate `UNAVAILABLE` until publication reconciliation, reset an incompatible checkpoint, audit and emit one event.

`DisableSource` CAS-sets stable source `DISABLED`, gate `SUSPENDED`, increments fence epoch for live runs and emits a stop event. It never deletes source, revision, Observation, Asset, relation or checkpoint history. `RequestSync` accepts only `ACTIVE + PUBLISHED + AVAILABLE`, binds the exact revision/gate/checkpoint hashes, and returns the same run on an identical replay.

- [ ] **Step 4: Verify Scope, concurrency, replay, recovery, and refactor**

Run:

~~~bash
gofmt -w internal/assetcatalog internal/assetcatalog/postgres
go test -race ./internal/assetcatalog ./internal/assetcatalog/postgres -count=1
TEST_DATABASE_URL="$TEST_DATABASE_URL" \
  go test -race ./internal/assetcatalog/postgres -run SourceRevisionIntegration -count=1
~~~

Expected: PASS; two concurrent publishes yield one winner, cross-Workspace revisions/runs fail, replay is stable, disabling fences active runs, restoring PostgreSQL preserves published pointers/digests and no raw credential/cursor/fence appears in rows, audit or outbox.

- [ ] **Step 5: Commit**

~~~bash
git add internal/assetcatalog/types.go internal/assetcatalog/repository.go \
  internal/assetcatalog/source_revision.go internal/assetcatalog/source_revision_test.go \
  internal/discoverysource/contracts.go internal/discoverysource/contracts_test.go \
  internal/assetcatalog/postgres/source_revisions.go \
  internal/assetcatalog/postgres/source_revisions_test.go \
  internal/assetcatalog/postgres/source_revisions_integration_test.go
git commit -m "feat(assetcatalog): govern immutable source revisions"
~~~

### Task 14: Source authorization, OpenAPI, strict HTTP, and effective actions

**Files:**
- Modify: `internal/authz/authorizer.go`
- Modify: `internal/authz/authorizer_test.go`
- Modify: `internal/assetcatalog/management.go`
- Modify: `internal/assetcatalog/management_test.go`
- Modify: `api/openapi/control-plane-v1.yaml`
- Modify: `api/openapi/control_plane_v1_test.go`
- Modify: `internal/httpapi/asset_sources.go`
- Modify: `internal/httpapi/asset_sources_test.go`
- Modify: `internal/httpapi/router.go`
- Modify: `web/src/shared/api/schema.d.ts` (generated only)

**Interfaces:**
- Consumes exact public endpoints and permissions from the approved specification.
- Produces `ASSET_SOURCE_READ|MANAGE|VALIDATE|PUBLISH|SYNC`, safe Source/Revision/Run DTOs and server-owned `effective_actions`.
- Adds workload-only `POST /api/v1/workspaces/{workspace_id}/asset-sources/{source_id}/ingestion-batches` with OpenAPI `mutualTLS`; browser OIDC is rejected on that operation.

- [ ] **Step 1: Write failing permission and route-contract tests**

~~~go
func TestSourcePermissionMatrix(t *testing.T) {
	readers := []authn.Role{authn.RoleViewer, authn.RoleSRE, authn.RoleServiceOwner,
		authn.RoleApprover, authn.RoleAuditor, authn.RoleAdmin}
	for _, role := range readers {
		if !roleAllows(role, PermissionAssetSourceRead) {
			t.Errorf("%s cannot read safe source projection", role)
		}
	}
	for _, permission := range []Permission{
		PermissionAssetSourceManage, PermissionAssetSourceValidate,
		PermissionAssetSourcePublish, PermissionAssetSourceSync,
	} {
		if !roleAllows(authn.RoleAdmin, permission) || roleAllows(authn.RoleSRE, permission) {
			t.Errorf("unexpected source permission %s", permission)
		}
	}
}

func TestSourcePublishRejectsCallerSuppliedDigestOrCredentialValue(t *testing.T) {
	response := performOIDCJSON(t, sourceRouter(t), http.MethodPost,
		"/api/v1/workspaces/"+workspaceID+"/asset-sources/"+sourceID+"/revisions/2:publish",
		`{"revision_digest":"caller","credential":"secret"}`)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", response.Code)
	}
}
~~~

Run: `go test ./internal/authz ./internal/assetcatalog ./internal/httpapi ./api/openapi -run Source -count=1`

Expected: FAIL because source permissions/revision operations are incomplete.

- [ ] **Step 2: Implement the exact public source contract**

Keep these routes in `control-plane-v1.yaml`:

~~~text
GET  /api/v1/workspaces/{workspace_id}/asset-sources
POST /api/v1/workspaces/{workspace_id}/asset-sources
GET  /api/v1/workspaces/{workspace_id}/asset-sources/{source_id}
POST /api/v1/workspaces/{workspace_id}/asset-sources/{source_id}/revisions
POST /api/v1/workspaces/{workspace_id}/asset-sources/{source_id}/revisions/{revision}:validate
POST /api/v1/workspaces/{workspace_id}/asset-sources/{source_id}/revisions/{revision}:publish
POST /api/v1/workspaces/{workspace_id}/asset-sources/{source_id}:disable
POST /api/v1/workspaces/{workspace_id}/asset-sources/{source_id}:sync
GET  /api/v1/workspaces/{workspace_id}/asset-source-runs/{run_id}
POST /api/v1/workspaces/{workspace_id}/asset-sources/{source_id}/imports
POST /api/v1/workspaces/{workspace_id}/asset-sources/{source_id}/ingestion-batches
~~~

Every schema is closed with `additionalProperties: false`. Source create makes stable identity plus revision 1; subsequent edits always create a new revision. Validate/sync/import/ingestion return `202` with durable `operation_id/run_id`; publish/disable require `If-Match`, Idempotency-Key, reason and server-verified recent auth. Errors use RFC 9457 and stable codes `SOURCE_REVISION_NOT_VALIDATED`, `SOURCE_BINDING_DRIFT`, `SOURCE_GATE_UNAVAILABLE`, `SOURCE_BACKPRESSURE`, `SOURCE_WORKLOAD_IDENTITY_MISMATCH`, `SOURCE_PAYLOAD_REJECTED`.

This task is the sole owner of Source mutation routes deferred by Packs 03–04. Create accepts a server-returned `source_profile_id`, name, opaque Credential/Trust/Network references, allowed Environment IDs, sync mode and schedule; it derives ProviderKind, Integration ID, definition and fixed rate/backpressure/profile fields, then creates the stable Source and immutable revision 1 in one `SERIALIZABLE` transaction. No reduced ProviderKind/Integration form or stable-Source-only insert is permitted.

Safe DTOs expose reference IDs, revision/digests, gate dimensions, checkpoint hash/version/age, counts and Trace IDs. They exclude endpoint, plaintext cursor, source canonical bytes, checkpoint ciphertext/key ID, lease owner/token hash, credential value, PEM, JWS and upstream text.

- [ ] **Step 3: Compute object-state-aware effective actions and strict transport**

Collection actions are `CREATE_SOURCE`; object/revision actions are exactly `CREATE_SOURCE_REVISION`, `VALIDATE_SOURCE_REVISION`, `PUBLISH_SOURCE_REVISION`, `DISABLE_SOURCE`, `SYNC_SOURCE`, `IMPORT_CSV`. Map them only from server permissions and state:

~~~go
func sourceActions(principal authn.Principal, source assetcatalog.Source, revision *assetcatalog.SourceRevision) []string {
	if source.Status == assetcatalog.SourceStatusDisabled {
		return []string{}
	}
	actions := []string{}
	if allows(principal, authz.PermissionAssetSourceManage) {
		actions = append(actions, "CREATE_SOURCE_REVISION", "DISABLE_SOURCE")
	}
	if revision != nil && revision.Status.CanValidate() && allows(principal, authz.PermissionAssetSourceValidate) {
		actions = append(actions, "VALIDATE_SOURCE_REVISION")
	}
	if revision != nil && revision.Status == assetcatalog.SourceRevisionValidated && allows(principal, authz.PermissionAssetSourcePublish) {
		actions = append(actions, "PUBLISH_SOURCE_REVISION")
	}
	if source.SourceKind != assetcatalog.SourceKindManual && source.AvailablePublishedRevision() && allows(principal, authz.PermissionAssetSourceSync) {
		actions = append(actions, "SYNC_SOURCE")
	}
	if source.SourceKind == assetcatalog.SourceKindCSVImport && source.AvailablePublishedRevision() && allows(principal, authz.PermissionAssetSourceManage) {
		actions = append(actions, "IMPORT_CSV")
	}
	return slices.Sorted(slices.Values(actions))
}
~~~

Add permission/state table tests proving disabled sources expose no mutate/disable/import/sync action, non-CSV sources never expose `IMPORT_CSV`, unavailable or non-published CSV revisions cannot import, MANUAL never syncs, and unauthorized principals receive none of these actions. `PUBLISH_SOURCE_REVISION` and `DISABLE_SOURCE` may be visible from authorization/object state, but execution still requires the server-verified recent authentication contract.

The handler ignores no unknown field, resolves Tenant from OIDC/workload identity plus Workspace DB scope, validates UUID/ETag/idempotency, applies `no-store`, and never logs a request body. Workload ingestion must pass an mTLS SAN binding `(tenant,workspace,source,provider)` and cannot call human revision/publish routes.

- [ ] **Step 4: Generate and verify the single client contract**

Run:

~~~bash
go test -race ./internal/authz ./internal/assetcatalog ./internal/httpapi ./api/openapi -count=1
corepack pnpm@10.34.0 --dir web generate:api
corepack pnpm@10.34.0 --dir web generate:api:check
git diff --exit-code -- web/src/shared/api/schema.d.ts
~~~

Expected: Go/OpenAPI tests PASS; generated-type check has no drift after the generated file is staged; unsafe fields and OIDC-to-workload route confusion are rejected.

- [ ] **Step 5: Commit**

~~~bash
git add internal/authz/authorizer.go internal/authz/authorizer_test.go \
  internal/assetcatalog/management.go internal/assetcatalog/management_test.go \
  api/openapi/control-plane-v1.yaml api/openapi/control_plane_v1_test.go \
  internal/httpapi/asset_sources.go internal/httpapi/asset_sources_test.go \
  internal/httpapi/router.go web/src/shared/api/schema.d.ts
git commit -m "feat(api): publish governed asset source revisions"
~~~

### Task 15: Signed RFC 4180 CSV import with bounded streaming and provenance

**Files:**
- Create: `internal/assetsource/csvimport/parser.go`
- Create: `internal/assetsource/csvimport/schema.go`
- Create: `internal/assetsource/csvimport/parser_test.go`
- Create: `internal/assetsource/csvimport/importer.go`
- Create: `internal/assetsource/csvimport/importer_test.go`
- Create: `internal/httpapi/asset_source_imports.go`
- Create: `internal/httpapi/asset_source_imports_test.go`
- Create: `testdata/asset-source/csv/valid-v1.csv`
- Create: `testdata/asset-source/csv/tombstone-v1.csv`

**Interfaces:**
- Consumes: exact `CSV_IMPORT` published revision, opaque `CredentialReferenceID` with purpose `IMPORT_SIGNATURE_VERIFY`, fenced Source Run and `assetdiscovery.Reconciler`.
- Produces: `csvimport.Parse(io.Reader, Limits) (Page, error)` and resumable checkpoint `(file_sha256,row_number,schema_version)` sealed by the common checkpoint codec.
- CSV header is fixed: `environment_id,provider_kind,external_id,kind,display_name,source_revision,deleted,tombstone_reason,relation_type,relation_target_external_id`.

- [ ] **Step 1: Write failing parser, DLP, tombstone, and resume tests**

~~~go
func TestCSVImportResumesWithoutDuplicatingRows(t *testing.T) {
	page1, err := Parse(strings.NewReader(validCSV(3000)), Limits{MaxRowsPerPage: 2000, MaxBytes: 32 << 20})
	if err != nil || len(page1.Items) != 2000 || page1.Next.RowNumber != 2001 {
		t.Fatalf("page1 = (%#v, %v)", page1, err)
	}
	page2, err := Resume(strings.NewReader(validCSV(3000)), page1.Next, Limits{MaxRowsPerPage: 2000, MaxBytes: 32 << 20})
	if err != nil || len(page2.Items) != 1000 || page2.Items[0].ExternalID != "vm-2001" {
		t.Fatalf("page2 = (%#v, %v)", page2, err)
	}
}

func TestCSVImportRejectsSecretAndSpreadsheetFormulaFields(t *testing.T) {
	for _, value := range []string{"password=hidden", "=WEBSERVICE(\"https://x\")", "+cmd|' /C calc'!A0"} {
		_, err := Parse(strings.NewReader(oneRowCSV(value)), Limits{MaxRowsPerPage: 10, MaxBytes: 4096})
		if !errors.Is(err, ErrUnsafeField) {
			t.Errorf("value %q error = %v", value, err)
		}
	}
}
~~~

Run: `go test ./internal/assetsource/csvimport ./internal/httpapi -run CSV -count=1`

Expected: FAIL because CSV source adapter does not exist.

- [ ] **Step 2: Implement the exact bounded parser and field provenance**

Use `encoding/csv` with `FieldsPerRecord=10`, `ReuseRecord=false`, UTF-8 without BOM after the first byte sequence, max file 32 MiB, max 100,000 rows, max field 512 bytes and page 2,000 rows. Reject duplicate headers, blank/duplicate `(environment_id,provider_kind,external_id,source_revision)`, NUL/CR in a field, formula-leading display/external values, unknown enum, secret-shaped token and governance fields not in the schema.

Each normalized source-owned field receives a closed provenance code such as `CSV_V1_EXTERNAL_ID_COLUMN`; values are never copied into provenance. `deleted=true` requires blank display/relation, non-empty allow-listed tombstone reason and creates a tombstone Observation; it never hard-deletes. File SHA and next row are sealed as checkpoint; a changed file SHA cannot resume and returns `CSV_CHECKPOINT_MISMATCH`.

- [ ] **Step 3: Stream upload to quarantine storage and reconcile under a fence**

`POST .../imports` accepts `multipart/form-data` parts `file` and `detached_signature`, streams once through SHA/DLP into an encrypted quarantine object store, verifies signature through the source's opaque CredentialReference, and returns `202`. The database stores only object reference ID, SHA, byte/row counts and expiry; object credentials never enter the browser or run payload. The Worker claims the Import Run, rechecks source revision/gate/fence, parses pages and atomically reconciles each page/checkpoint. Quarantine objects are deleted after terminal success/failure; cleanup uncertainty sets run `FAILED` with `SOURCE_IMPORT_CLEANUP_UNCERTAIN` and gate `DEGRADED`.

Backpressure is fixed at one active CSV run per source, four per Workspace, 100,000 pending rows per Workspace; excess returns `429` plus bounded `Retry-After`. A partial file never performs missing-asset stale detection; only a signed `complete_snapshot=true` manifest may do so.

- [ ] **Step 4: Verify real streaming, replay, Scope, and cleanup**

Run:

~~~bash
gofmt -w internal/assetsource/csvimport internal/httpapi
go test -race ./internal/assetsource/csvimport ./internal/httpapi -count=1
TEST_DATABASE_URL="$TEST_DATABASE_URL" go test -race ./internal/assetcatalog/postgres -run CSVImport -count=1
~~~

Expected: PASS for actual multipart streaming, signature verification, UTF-8/RFC 4180 parsing, DLP, cursor resume, tombstone/recovery, cross-Scope denial, duplicate replay, rate limit, Worker crash resume and quarantine cleanup.

- [ ] **Step 5: Commit**

~~~bash
git add internal/assetsource/csvimport internal/httpapi/asset_source_imports.go \
  internal/httpapi/asset_source_imports_test.go testdata/asset-source/csv
git commit -m "feat(assetdiscovery): ingest signed csv sources"
~~~

### Task 16: mTLS API ingestion and six-step high-fidelity Source workspace

**Files:**
- Create: `internal/assetsource/controlplaneapi/handler.go`
- Create: `internal/assetsource/controlplaneapi/identity.go`
- Create: `internal/assetsource/controlplaneapi/schema.go`
- Create: `internal/assetsource/controlplaneapi/handler_test.go`
- Create: `internal/assetsource/controlplaneapi/protocol_integration_test.go`
- Modify: `web/src/features/asset-sources/api.ts`
- Modify: `web/src/features/asset-sources/AssetSourcesPage.tsx`
- Create: `web/src/features/asset-sources/SourceRevisionWizard.tsx`
- Create: `web/src/features/asset-sources/SourceRevisionWizard.module.css`
- Create: `web/src/features/asset-sources/SourceRevisionWizard.test.tsx`
- Create: `web/src/features/asset-sources/CSVImportDialog.tsx`
- Modify: `web/src/features/asset-sources/SourceRunTimeline.tsx`
- Modify: `web/src/app/router.tsx`
- Create: `web/e2e/source-revisions.spec.ts`
- Create: `web/e2e/source-csv-import.spec.ts`
- Create: `docs/design/frontend/asset-sources.md`

**Interfaces:**
- Consumes: mutual-TLS workload identity, published `CONTROL_PLANE_API` revision, opaque JWS verification CredentialReference, common fenced run/checkpoint and generated OpenAPI types.
- Produces: closed `IngestionBatchV1`, monotonic sequence checkpoint, TanStack route `/asset-sources/$sourceId/revisions/$revision` and safe Source Gate/Run views.
- Does not expose a general webhook, arbitrary endpoint, arbitrary Header or arbitrary JSON ingestion path.

- [ ] **Step 1: Write failing workload-identity and UI-state tests**

~~~go
func TestAPIIngestionDerivesScopeFromWorkloadIdentity(t *testing.T) {
	server := newMutualTLSSourceServer(t)
	client := newSourceClient(t, server, workloadIdentityFor(sourceID, workspaceID))
	response := client.PostBatch(t, workspaceID, sourceID, signedBatch(sequence(41), environmentID))
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d", response.StatusCode)
	}
	wrong := newSourceClient(t, server, workloadIdentityFor(otherSourceID, workspaceID))
	if got := wrong.PostBatch(t, workspaceID, sourceID, signedBatch(sequence(42), environmentID)).StatusCode; got != http.StatusNotFound {
		t.Fatalf("cross-source status = %d", got)
	}
}
~~~

~~~tsx
it("keeps validation and publication as separate governed steps", async () => {
  renderSourceWizard("/asset-sources/s/revisions/2?workspace=w&step=validate");
  expect(await screen.findByText("5. 受控验证")).toBeVisible();
  expect(screen.getByText("UNAVAILABLE")).toBeVisible();
  expect(screen.queryByLabelText(/Token|Secret|Endpoint|JSON/)).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "发布" })).not.toBeInTheDocument();
});
~~~

Run: `go test ./internal/assetsource/controlplaneapi -count=1 && corepack pnpm@10.34.0 --dir web test -- SourceRevisionWizard.test.tsx`

Expected: FAIL because workload protocol and revision wizard do not exist.

- [ ] **Step 2: Implement closed signed batch protocol**

`IngestionBatchV1` contains only `schema_version`, `sequence`, `previous_batch_digest`, `complete_snapshot`, `observed_at`, `environment_id`, max 1,000 typed items and detached `signature_key_id/signature`. The server derives Tenant/Workspace/Source/Provider from SAN and published revision; verifies signature through the opaque reference; requires sequence exactly `checkpoint+1`, previous digest equality, UTC microsecond time within 5 minutes and authority-scope membership. It canonicalizes and DLP-checks before creating a run; 429/503 are safe to retry because no Observation exists before durable run acceptance.

One source accepts at most two in-flight API batches, eight per Workspace and 20 requests/second with burst 40. Persist `not_before`/queue depth so replica changes do not reset the limit. A valid tombstone creates `STALE`; a later observation records recovery but remains `STALE`. Unknown field, bad signature, replay, sequence gap, oversized page, source/revision/gate drift and wrong client certificate fail before reconciliation.

- [ ] **Step 3: Implement Source creation and the six-step Source revision workspace**

`CREATE_SOURCE` opens this workspace without a `sourceId`; Step 1 submits the complete safe create command and receives the stable Source plus revision 1 and a durable mutation receipt. Existing Sources enter the same workspace with `sourceId/revision`. The vertical steps are exact:

1. **Scope and installed Provider** — Workspace plus server-returned Source Profile; `KUBERNETES_OPERATOR` says Phase 3/UNAVAILABLE.
2. **Authority and identity** — allowed Environments and provider-owned identity rules; no endpoint editor.
3. **Opaque references** — Credential, Trust and Network Policy IDs with safe health metadata only.
4. **Sync and limits** — on-demand/schedule, page/rate/backpressure profile and deletion semantics.
5. **Controlled validation** — durable run timeline for identity, trust, network, credential open/cleanup, fixed probe, schema/DLP/budget; stable codes only.
6. **Review and publish** — immutable diff, full revision/binding/proof digests, checkpoint compatibility, affected assets/runs, reason, recent OIDC and publish.

The list shows Source/Revision/Gate separately, checkpoint hash/version/age, queue pressure and last safe counts. `effective_actions` alone controls buttons. CSV import shows filename locally, SHA/counts and rejected-row codes but never raw rejected rows. URL persists `workspace,sourceId,revision,step,runId`; refresh/back restores the exact safe state. Use the locked dense light console, 38–40px rows, 4–6px radius, no cards-as-layout, chat, AI avatar, gradient, glow or terminal.

Persist the complete contract in `docs/design/frontend/asset-sources.md`: IA and `/asset-sources` plus revision-wizard URL schema; six-step component hierarchy and field ownership; list/detail/run/import layouts; Source/Revision/Gate/Checkpoint/Run orthogonal state matrix; loading/empty/partial/stale/forbidden/validation-failed/backpressure/cleanup-uncertain interactions; 1440/1024/768/390 breakpoints; locked tokens from `foundation-assets.md`; keyboard/focus/WCAG rules; real Keycloak/OIDC reauthentication and `effective_actions`; safe copy rules; and forbidden endpoint/Secret/raw JSON/chat/terminal/AI decoration patterns. This file is the unique durable Source UI design source for later sessions.

- [ ] **Step 4: Run real protocol, Keycloak, accessibility, and secret scans**

Run:

~~~bash
go test -race ./internal/assetsource/controlplaneapi ./internal/httpapi -count=1
corepack pnpm@10.34.0 --dir web check
corepack pnpm@10.34.0 --dir web test:e2e -- --grep "source revision|CSV import"
rg -n 'access_token|client_secret|private_key|checkpoint_ciphertext|fence_token' \
  web/e2e/test-results web/playwright-report
~~~

Expected: real TLS sockets and client certificates are used; positive/negative ingestion, CSV upload, six-step validation/publication, reauth, URL restore, 1440/1024/390 layouts and axe pass; final scan exits `1` with no secret-bearing output.

- [ ] **Step 5: Commit**

~~~bash
git add internal/assetsource/controlplaneapi web/src/features/asset-sources \
  web/src/app/router.tsx web/e2e/source-revisions.spec.ts web/e2e/source-csv-import.spec.ts \
  docs/design/frontend/asset-sources.md
git commit -m "feat(assetdiscovery): ship governed source ingestion"
~~~
