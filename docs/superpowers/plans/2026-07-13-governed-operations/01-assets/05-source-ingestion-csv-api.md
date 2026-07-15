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
- Create: `internal/assetcatalog/source_extension.go`
- Create: `internal/assetcatalog/source_extension_test.go`
- Create: `internal/assetcatalog/source_extension_architecture_test.go`
- Create: `internal/assetcatalog/internal/revisioncap/session.go`
- Create: `internal/assetcatalog/internal/revisioncap/session_test.go`
- Create: `internal/assetcatalog/postgres/source_revisions.go`
- Create: `internal/assetcatalog/postgres/extension_procedures.go`
- Create: `internal/assetcatalog/postgres/extension_procedures_test.go`
- Modify: `internal/assetcatalog/postgres/manual_run.go`
- Create: `internal/assetcatalog/postgres/source_revisions_test.go`
- Modify: `internal/assetcatalog/postgres/manual_run_test.go`
- Create: `internal/assetcatalog/postgres/source_revisions_integration_test.go`
- Modify: `internal/store/postgres/database_role_admission.go`
- Modify: `internal/store/postgres/database_role_admission_test.go`

**Interfaces:**
- Consumes: `asset_sources`, `asset_source_revisions`, immutable `asset_source_revision_authorities`, `asset_source_runs` schema plus scoped audit/outbox/idempotency ledger from Tasks 1–4; an existing stable Source is required only for subsequent revisions.
- Produces: `SourceRevisionRepository.CreateSource/CreateRevision/RequestValidation/Publish/Disable/RequestSync` and exact source/revision `ETag` versions. `CreateSource` is the sole production owner of atomic stable Source + immutable revision 1 creation.
- Produces `TypedSourceExtensionRegistry`；later phases may extend a revision only through its in-transaction `ValidateAndDigestInTx → PreparedExtension.CreateInTx` hook, never through a parallel lifecycle/transaction.
- Produces events: `asset.source.revision.created.v1`, `asset.source.validation.requested.v1`, `asset.source.revision.published.v1`, `asset.source.disabled.v1`, `asset.source.sync.requested.v1`.
- Produces the only Provider data-plane contract consumed by every later source pack:

~~~go
type Provider interface {
	Kind() assetcatalog.SourceKind
	ProviderKind() string
	Validate(context.Context, BoundRuntime, ValidationRequest) (ValidationProof, error)
	Discover(context.Context, BoundRuntime, DiscoverRequest) (DiscoverOutcome, error)
}

type DiscoverRequest struct {
	Locator              SourceLocator
	SourceRevision       int64
	SourceRevisionDigest string
	Checkpoint           Checkpoint
	Limits               Limits
}

type Page struct {
	Items            []assetdiscovery.NormalizedItem
	Relations        []assetdiscovery.ObservedRelation
	NextCheckpoint   Checkpoint
	FinalPage        bool
	CompleteSnapshot bool
}

type Delay struct {
	Reason     DelayReason // PROVIDER_RETRY_AFTER only; Worker owns TRANSPORT_BACKOFF
	RetryAfter time.Duration
}

type DiscoverOutcome interface { isDiscoverOutcome() } // closed Page | Delay

func (Page) isDiscoverOutcome()  {}
func (Delay) isDiscoverOutcome() {}
~~~

Additional RED tests are mandatory：`TestDatabaseRoleAdmissionRequiresExactSeparatedRoles`、`TestRuntimeRoleCannotCreateSchemaOrWriteTypedExtensionTable`、`TestExtensionProcedureOwnerCannotReadBaseAuditOrOutbox`、`TestMigrationAndRuntimeConnectionsAreDistinct`。The disposable PostgreSQL integration fixture bootstraps the reviewed roles before migrations and proves direct runtime INSERT/UPDATE/DELETE/TRUNCATE fails while exact procedure EXECUTE succeeds；missing membership、owner inheritance、PUBLIC CREATE/EXECUTE or a runtime owner connection must fail startup admission.

`FinalPage` means the bounded Provider run has ended；`CompleteSnapshot` additionally proves authoritative asset **and relation** membership closure and may be true only with `FinalPage=true`. A final incremental/delta page uses `FinalPage=true, CompleteSnapshot=false`；intermediate pages set both false. Provider adapters never infer missing assets/relations from `FinalPage` alone. `Delay` and `Page` are mutually exclusive concrete outcomes: Provider `RetryAfter` must be in `(0,60s]` and a `Delay` has no Items、Relations、checkpoint or final flags by type；transport backoff is created only by the Worker. A `Page` may be relation-only under Pack 02 endpoint-readiness rules but has no retry field.

The return pair is also exact XOR：`err != nil` requires `outcome == nil`，and a non-nil outcome requires `err == nil`；`nil,nil` and outcome+error are both `SOURCE_PROVIDER_CONTRACT_VIOLATION`. A successful dynamic value must be exactly non-pointer `Page` or `Delay`（typed-nil pointers/aliases are rejected）so interface nil tricks cannot bypass the sum type. The Worker discards any violating outcome, never calls `ApplyPage`, prepares a stable failure intent, cleans the attempt and suspends that Source gate. Contract tests cover all four XOR combinations plus typed-nil/pointer rejection for every registered Provider.

`BoundRuntime` is created only inside `cmd/discovery-worker` from the exact published revision/profile and workload secret binding；it is deliberately non-serializable and implements `Close/Clear`. `DiscoverRequest` intentionally contains no `LeaseFence`；the Worker revalidates its fence around the call and only `PageCommitter/Reconciler` consumes the sealed fence. `DiscoverRequest`, queue payload, Temporal history, audit and logs contain no endpoint, credential, CA, header or Provider request body. Every installed Profile fixes one `FreshnessKind` plus `EnvironmentMappingMode`：`EXPLICIT_ITEM_ENVIRONMENT` only for CSV/API inputs that carry a validated Environment ID, or `SINGLE_ENVIRONMENT` for fixed infrastructure adapters. The latter requires exactly one same-Workspace `AuthorityEnvironmentID`；the former validates every item/relation endpoint against the immutable sorted allow-list. Only the sorted Environment allow-list is membership input to `authority_scope_digest`；freshness kind and mapping mode are immutable semantics of the versioned Profile canonical bytes. `BindingDigest` binds that Profile through `source_definition_digest/profile_code` and independently binds `authority_scope_digest`，so changing either semantic requires a new versioned Profile/revision and complete digest closure；Provider wire data can never choose another kind or invent/remap a Catalog Environment.

- [ ] **Step 1: Write failing revision immutability and publication-gate tests**

~~~go
func TestPublishSourceRevisionRequiresMatchingSuccessfulValidation(t *testing.T) {
	db := openAssetCatalogDatabase(t)
	fixture := seedSourceWithDraftRevision(t, db)
	repository := newAssetRepository(t, db)

	_, err := repository.PublishSourceRevision(context.Background(), assetcatalog.PublishSourceRevisionCommand{
		Context: fixture.MutationContext,
		SourceID: fixture.SourceID, Revision: 2, ExpectedSourceVersion: 1,
		ExpectedRevisionVersion: 1,
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
	assertSourceRevisionCreateSideEffectsByKey(t, db, command.Context.IdempotencyKey(), 0, 0, 0, 0)
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
	conflict := validCreateSourceCommandWithSameKeyAndDifferentCanonicalInput(command)
	if _, err := repository.CreateSource(context.Background(), conflict); !errors.Is(err, assetcatalog.ErrIdempotency) {
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
	Context                        MutationContext
	Name                           string
	SourceProfileID                string
	CredentialReferenceID          string
	TrustReferenceID               string
	NetworkPolicyReferenceID       string
	AuthorityEnvironmentIDs        []string
	SyncMode, ScheduleExpression   string
}

type CreateSourceRevisionCommand struct {
	Context                         MutationContext
	SourceID                        string
	SourceProfileID                 string
	CredentialReferenceID          string
	TrustReferenceID               string
	NetworkPolicyReferenceID       string
	AuthorityEnvironmentIDs        []string
	SyncMode, ScheduleExpression   string
	ExpectedSourceVersion          int64
}

type SourceRevisionMutation struct {
	Source   Source
	Revision SourceRevision
	Receipt  MutationReceipt
}

type ExtensionFactRequest = revisioncap.FactRequest
type ExtensionFact = revisioncap.Fact
type ExtensionDocument = revisioncap.ExtensionDocument

type SourceRevisionTx interface {
	LookupFact(context.Context, ExtensionFactRequest) (ExtensionFact, error)
	ReadOwnExtension(context.Context) (ExtensionDocument, bool, error)
	CreateOwnExtension(context.Context, ExtensionDocument) error
}

type TypedSourceExtension interface {
	ValidateAndDigestInTx(context.Context, SourceRevisionTx, SourceRevisionDraft) (PreparedExtension, error)
}

type PreparedExtension interface {
	Digest() string
	CreateInTx(context.Context, SourceRevisionTx, SourceRevision) error
}

type TypedSourceExtensionRegistry interface {
	Resolve(extensionCode string) (TypedSourceExtension, error)
}
~~~

`SourceRevisionTx` is the narrow root facade presented to extensions. The concrete nested-internal `revisioncap.Session` implements exactly those three methods and has no controller methods；there is no SQL string、`...any`、pgx type、raw row/connection or transaction-control method. `FactRequest.Kind` is a closed allow-list and Session injects exact Tenant/Workspace/Source/Revision binding. `revisioncap.NewValidationSession` returns a Session plus a separate shared-state `Controller`. Because Go `internal` visibility alone permits the parent subtree, an AST/import allow-list permits `internal/assetcatalog/source_extension.go` to import only the three facade aliases and permits the PostgreSQL owner files to import Session/Controller construction；every other production file, especially later extension packages, is forbidden from importing `revisioncap`. Extensions receive the root interface and cannot type-assert the Session to any controller operation because those methods exist only on the separate Controller type. `ExtensionDocument` contains canonical typed content only and has no extension code、procedure name、manifest selector or SQL selector；Session is already bound to the registry-resolved extension code and its fixed procedure.

The client never supplies `provider_kind`, canonical definition, revision number, Integration ID, rate/backpressure numbers, profile/freshness/typed-extension code, binding digest or revision digest. It also cannot supply `MutationContext` fields：Task 6 management constructs that context from verified Principal、resolved route Scope、server Trace/Header/reauth facts and canonical request hashing. Registry bootstrap first installs the exact immutable Task 2 `ManualProfileV1()` value and rejects any same-code semantic difference；Task 3 therefore has no reverse dependency on this Task 13 registry. `SourceProfileRegistry.Resolve(SourceProfileID)` then returns one installed discriminated profile, provider kind, Integration ID, allowed SourceKind, network zone, credential purpose, trust mode, parser schema, fixed rate/backpressure fields, immutable canonical `ProfileCode`, optional server-owned `TypedExtensionCode`, hard page/byte limits, compatibility class, exact `FreshnessKind` and `EnvironmentMappingMode`. `SourceProfileID` is only a lookup selector and is not persisted；the resolved `ProfileCode` is persisted in `asset_source_revisions.profile_code` and is the exact profile identity hashed by `BindingDigest`. Registry startup canonicalizes the complete Profile semantics and rejects two definitions that reuse one `ProfileCode` with a different freshness kind、mapping mode/allow-list contract、credential/trust/network mode、limits、Provider schema or extension code；semantic changes require a new versioned code. The server validates every Environment against the Source Workspace, enforces the mode's one-or-explicit-list cardinality, sorts it, computes the Task 2 authority and Source-definition digests, allocates `max(revision)+1` under a Source row lock, and computes `CanonicalRevisionDigest = SourceRevision.BindingDigest()` using the fixed 20-frame contract, including the prepared extension code/digest as independent final frames. It inserts one authority child row per sorted Environment with contiguous ordinal in the same outer transaction；PostgreSQL deferred closure independently reloads and recomputes all three digests. With no extension, both final frames are still NULL. Tests use the fixed Task 2 golden digests, reject same-code semantic drift、a candidate freshness kind different from the installed Profile, zero/multiple Environments for a `SINGLE_ENVIRONMENT` profile, absent/late/reordered/duplicate/cross-Scope authority children, out-of-list CSV/API item/relation Environments, unknown/half-present extension binding and any mapping/extension change without a newly validated/published canonical revision plus its required checkpoint transition.

- [ ] **Step 3: Implement serializable revision state transitions**

`CreateSource` begins `SERIALIZABLE`, validates the trusted MutationContext/Idempotency/Profile and resolves every opaque reference before mutation, and locks Workspace/Profile facts. If the resolved Profile has a typed extension, the Repository creates one `(revisioncap.Session, revisioncap.Controller)` pair bound to the outer transaction and passes only the Session as `SourceRevisionTx` to `ValidateAndDigestInTx` while it is `VALIDATING`；only closed trusted-fact reads are then legal. It obtains the immutable prepared digest, places code/digest into the final two BindingDigest frames, inserts the stable Source、base revision and all ordered authority child rows, then the PostgreSQL owner calls `Controller.ArmCreate`. The exact prepared object may call `Session.CreateOwnExtension` once；no new trusted reads are legal. `Controller.VerifyCreated` reloads that exact 1:1 row and constant-time compares its digest before audit/outbox, then `Controller.Close` invalidates every retained Session copy and clears captured transaction closures. The outer Repository alone retries/commits/rolls back；the deferred database closure rechecks authority、definition and BindingDigest immediately before commit。For `KUBERNETES_OPERATOR/AWX_INVENTORY`, the separate deferred Source INSERT closure also requires the currently installed 000017/000019 hook creation branch；without its owned successor or exact provider facts, the entire stable Source/revision/audit/outbox transaction rolls back. `CreateRevision` uses the same order under the existing Source lock. Any invalid Environment/reference/profile/extension/digest or side-effect failure rolls back base identity/revision、authority children、extension、audit and outbox. A later phase cannot obtain the controller/transaction, write after commit or own a second Create/Publish lifecycle.

This Task consumes the Task 1-owned base database-role ABI and bootstrap/admission files；it neither creates roles nor names a future Provider owner。It extends the initially empty typed manifest with generic `ExtensionProcedureSpec` validation（exact `regprocedure`、definition digest、NOLOGIN owner、typed-table ACL、runtime EXECUTE and no PUBLIC/schema-owner/runtime table write），so later owned migrations can register their concrete role only in their own phase。The application still receives only `AIOPS_DATABASE_URL` for a workload login that is not a member of migrator/schema/extension owners；migration jobs use a separate privileged DSN and reviewed `SET ROLE` path。

Every later owned migration consumes the base checks and, when its manifest is nonempty, additionally checks that concrete extension role before DDL；failure is `55000` and migrations still never `CREATE ROLE`. It explicitly sets object owners, revokes PUBLIC/runtime direct table and routine privileges, and grants only reviewed runtime methods. The PostgreSQL adapter invokes only frozen per-extension procedures selected from the immutable manifest；startup verifies exact `regprocedure` signature、NOLOGIN owner、runtime grantee、ACL with no PUBLIC execute、fixed search path and function-definition SHA-256. An extension procedure is fixed-search-path `SECURITY DEFINER`, uses only schema-qualified SQL, and its owner has no rights on base Source/Audit/Outbox. Architecture/integration tests use adversarial extensions to prove SQL/pgx/transaction symbols are absent, validation-time writes and create-time reads fail, a second write/use-after-close fails, procedure drift closes assembly, and no extension can mutate base/audit rows. Matching replay is returned only after current Principal/Scope/state/profile authorization is rechecked；a changed hash returns `ErrIdempotency`.

`CreateRevision` inserts one `DRAFT` immutable content row for an existing Source. `RequestValidation` CAS-transitions `DRAFT|REJECTED→VALIDATING`, creates a new append-only `VALIDATION` Run bound to the exact revision and canonical binding digest, gives it an empty checkpoint input, and closes the Source gate. A rejected revision's canonical content remains immutable, and it can never transition directly to `PUBLISHED`. The Worker must call fenced `ProposeValidationResult` to persist a `VALIDATION_PROOF` and enter `FINALIZING`, then Broker cleanup and `Complete|Fail` atomically transition only that exact revision/run to `VALIDATED|REJECTED`. Safe proof fields are identity/TLS-or-signature/network/credential-open+cleanup/fixed-probe/schema/DLP/budget result codes and a proof digest. Cancellation、drift、reaper or cleanup uncertainty likewise writes the still-bound `VALIDATING` revision to `REJECTED` with a stable proof/code, so no revision can remain stranded and it can be explicitly revalidated.

The installed `MANUAL_V1` profile is the only no-Adapter validation specialization. It is `SINGLE_ENVIRONMENT` and declares explicit `CredentialPurpose=NONE/TrustMode=NONE/NetworkMode=NONE`; its revision must resolve exactly one same-Workspace authority Environment, and every governed MANUAL Asset create must use that exact `AuthorityEnvironmentID` rather than a caller-selected Environment. Creation rejects zero/multiple authority Environments, any different Asset `environment_id` and non-empty external references. The fixed 20-frame BindingDigest binds the unique Environment through `authority_scope_digest`，binds the versioned `MANUAL_V1` Profile through `source_definition_digest/profile_code`，and encodes Credential/Trust/Network references as three SQL-NULL frames；the Profile's `NONE` semantics are not literal sentinel strings in those frames. `RequestValidation` synchronously creates, privately claims, finalizes and completes an exact `VALIDATION` Run with `NO_CREDENTIAL`, proving only installed profile digest、Scope/Environment、closed MANUAL schema、DLP/budgets and binding equality—no network/runtime/credential call exists. Every MANUAL mutation uses `CATALOG_SEQUENCE{OrderSequence=n,ProviderVersionSHA256=SHA256(FramedTupleV1("manual-catalog-version.v1",tenant_id,workspace_id,source_id,checkpoint_revision,n))}` with the Pack 01 byte encoding, where `n` is the positive `accepted_checkpoint_version` allocated and CASed by that same transaction; neither client input nor Catalog time participates in the Provider-version digest. On `PublishSourceRevision`, the same transaction revalidates that exact terminal proof and current installed profile and may set this MANUAL Source directly to `AVAILABLE`; it sets `checkpoint_version=0` and `checkpoint_revision` to the exact newly published revision while all checkpoint ciphertext/key/hash fields remain `NULL`. Before the first publication both numeric fields are zero. Every non-MANUAL profile still requires its independent publication reconciliation/canary. This is the sole path that makes a MANUAL Source eligible for Pack 02 create.

`PublishSourceRevision` must require:

1. same Tenant/Workspace, current source/revision versions and a fresh Idempotency-Key;
2. revision `VALIDATED`, terminal successful validation run, matching revision/binding/proof digests and current profile compatibility;
3. current opaque credential/trust/network references are resolvable and not revoked; no secret value is loaded by Control Plane;
4. recent OIDC authentication and `ASSET_SOURCE_PUBLISH` are already attested by management layer;
5. atomically supersede the previous published revision, update source pointer/digest, set source gate `UNAVAILABLE` until publication reconciliation, clear the prior non-MANUAL sealed checkpoint because canonical-revision-bound AAD changes, audit and emit one event. The `MANUAL_V1` exception has no sealed checkpoint: publication sets `checkpoint_version=0` and `checkpoint_revision` to the newly published revision as specified above.

`DisableSource` CAS-sets stable Source `DISABLED`, gate `SUSPENDED`, atomically `CANCELLED`s its `QUEUED|DELAYED` Runs through `CancelIneligible`, rejects any exact still-bound `VALIDATING` Revision with stable cancellation proof, and emits a stop event. It does not arbitrarily bump a current `RUNNING|FINALIZING` fence：the holder detects drift, stops Provider work and records cleanup/failure before expiry；an expired holder is replaced only by the cleanup-aware reaper. It never deletes Source, revision, Observation, Asset, relation or checkpoint history. Publication/reference/gate drift invokes the same serializable ineligible-run cancellation so a queued/delayed row cannot permanently occupy the per-Source nonterminal slot. `RequestSync` accepts only `ACTIVE + PUBLISHED + AVAILABLE`, binds the exact revision/gate/checkpoint hashes, and returns the same Run on an identical replay.

- [ ] **Step 4: Verify Scope, concurrency, replay, recovery, and refactor**

Run:

~~~bash
gofmt -w $(rg --files internal/assetcatalog -g '*.go')
go test -race ./internal/assetcatalog ./internal/assetcatalog/postgres -count=1
TEST_DATABASE_URL="$TEST_DATABASE_URL" \
  go test -race ./internal/assetcatalog/postgres -run SourceRevisionIntegration -count=1
~~~

Expected: PASS; two concurrent publishes yield one winner, cross-Workspace revisions/runs fail, replay is stable, MANUAL synchronous validation/publication reaches AVAILABLE without external refs, disabling cancels queued/delayed work and causes active work to stop/clean up, drift cannot strand the unique nonterminal slot, restoring PostgreSQL preserves published pointers/digests and no raw credential/cursor/fence appears in rows, audit or outbox.

- [ ] **Step 5: Commit**

~~~bash
git add internal/assetcatalog/types.go internal/assetcatalog/repository.go \
  internal/assetcatalog/source_revision.go internal/assetcatalog/source_revision_test.go \
  internal/assetcatalog/source_extension.go internal/assetcatalog/source_extension_test.go \
  internal/assetcatalog/source_extension_architecture_test.go \
  internal/assetcatalog/internal/revisioncap \
  internal/discoverysource/contracts.go internal/discoverysource/contracts_test.go \
  internal/assetcatalog/postgres/manual_run.go internal/assetcatalog/postgres/manual_run_test.go \
  internal/assetcatalog/postgres/source_revisions.go internal/assetcatalog/postgres/extension_procedures.go \
  internal/assetcatalog/postgres/extension_procedures_test.go \
  internal/assetcatalog/postgres/source_revisions_test.go \
  internal/assetcatalog/postgres/source_revisions_integration_test.go \
  internal/store/postgres/database_role_admission.go \
  internal/store/postgres/database_role_admission_test.go
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

Every schema is closed with `additionalProperties: false`. Source create makes stable identity plus revision 1; subsequent edits always create a new revision. The validate route resolves the installed profile before choosing its closed response: `MANUAL_V1` completes synchronously and returns `200` with the already-terminal durable Run/validation receipt, while every non-MANUAL validation returns `202` with its queued durable `operation_id/run_id`; sync/import/ingestion return `202`. Publish/disable require `If-Match`, Idempotency-Key, reason and server-verified recent auth. Errors use RFC 9457 and stable codes `SOURCE_REVISION_NOT_VALIDATED`, `SOURCE_BINDING_DRIFT`, `SOURCE_GATE_UNAVAILABLE`, `SOURCE_BACKPRESSURE`, `SOURCE_WORKLOAD_IDENTITY_MISMATCH`, `SOURCE_PAYLOAD_REJECTED`.

This task is the sole owner of Source mutation routes deferred by Packs 03–04. Create accepts a server-returned `source_profile_id`, name, opaque Credential/Trust/Network references, allowed Environment IDs, sync mode and schedule; it derives ProviderKind, Integration ID, definition and fixed rate/backpressure/profile fields, then creates the stable Source and immutable revision 1 in one `SERIALIZABLE` transaction. No reduced ProviderKind/Integration form or stable-Source-only insert is permitted.

Safe DTOs expose reference IDs, revision/digests, gate dimensions, checkpoint hash/version/age, counts and Trace IDs. They exclude endpoint, plaintext cursor, source canonical bytes, checkpoint ciphertext/key ID, lease owner/token hash, credential value, PEM, JWS and upstream text.

- [ ] **Step 3: Compute object-state-aware effective actions and strict transport**

Collection actions are `CREATE_SOURCE`; object/revision actions are exactly `CREATE_SOURCE_REVISION`, `VALIDATE_SOURCE_REVISION`, `PUBLISH_SOURCE_REVISION`, `DISABLE_SOURCE`, `SYNC_SOURCE`, `IMPORT_CSV`. Map them only from server permissions and state:

~~~go
type SourceActionAdmission struct { // server-built after exact Profile/fact resolution
	CanValidate bool
	CanPublish  bool
	CanSync     bool
	CanImport   bool
}

func sourceActions(principal authn.Principal, source assetcatalog.Source, admission SourceActionAdmission) []string {
	if source.Status == assetcatalog.SourceStatusDisabled {
		return []string{}
	}
	actions := []string{}
	if allows(principal, authz.PermissionAssetSourceManage) {
		actions = append(actions, "CREATE_SOURCE_REVISION", "DISABLE_SOURCE")
	}
	if admission.CanValidate && allows(principal, authz.PermissionAssetSourceValidate) {
		actions = append(actions, "VALIDATE_SOURCE_REVISION")
	}
	if admission.CanPublish && allows(principal, authz.PermissionAssetSourcePublish) {
		actions = append(actions, "PUBLISH_SOURCE_REVISION")
	}
	if admission.CanSync && allows(principal, authz.PermissionAssetSourceSync) {
		actions = append(actions, "SYNC_SOURCE")
	}
	if admission.CanImport && allows(principal, authz.PermissionAssetSourceManage) {
		actions = append(actions, "IMPORT_CSV")
	}
	return slices.Sorted(slices.Values(actions))
}
~~~

`SourceActionAdmission` is not a transport input. Management builds it only after reloading the exact scoped Source/Revision, resolving the installed Profile/Adapter and its required trusted facts, and applying current object state；unknown Source enum or missing Profile yields all false. Add permission/state table tests proving disabled sources expose no mutate/disable/import/sync action, non-CSV sources never expose `IMPORT_CSV`, unavailable or non-published CSV revisions cannot import, MANUAL never syncs, enum-without-installed-Profile exposes no runtime action, and unauthorized principals receive none of these actions. `PUBLISH_SOURCE_REVISION` and `DISABLE_SOURCE` may be visible from authorization/object state, but execution still requires the server-verified recent authentication contract.

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
- CSV header is fixed: `environment_id,provider_kind,external_id,kind,display_name,object_version,deleted,tombstone_reason,relation_type,relation_target_environment_id,relation_target_external_id`. `object_version` is the CSV Adapter's positive decimal record version and is never mapped to persisted `source_revision`; the server derives the exact Source definition revision from the published Run. A relation row must supply both target fields, and `relation_target_environment_id` must be a same-Workspace Environment in the exact published revision's immutable authority allow-list; a row without a relation must leave both target fields empty.

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

Use `encoding/csv` with `FieldsPerRecord=11`, `ReuseRecord=false`, UTF-8 without BOM after the first byte sequence, max file 32 MiB, max 100,000 rows, max field 512 bytes and page 2,000 rows. Reject duplicate headers, blank or duplicate `(provider_kind,external_id)` anywhere in the whole file/Run even when Environment or object version differs, non-positive/non-canonical decimal `object_version`, NUL/CR in a field, formula-leading display/external values, unknown enum, secret-shaped token and governance fields not in the schema. Require both source and relation-target Environments to pass the exact revision authority check described above. Each row emits one top-level `Page.Items` entry with `OBJECT_SEQUENCE{OrderSequence=object_version,ProviderVersionSHA256=SHA256(FramedTupleV1("csv-object-version.v1",object_version))}`. If its three relation fields are present, it additionally emits one top-level `Page.Relations` entry—not an embedded Item field—with the same order sequence and `ProviderVersionSHA256=SHA256(FramedTupleV1("csv-relation-version.v1",object_version,relation_type,relation_target_environment_id,relation_target_external_id))`. Repository compares each independent fact with its locked prior projection and injects Source definition revision/Catalog time into asset provenance. Regression/collision fails the whole page/file checkpoint rather than skipping a row.

Each normalized source-owned field receives a closed provenance code such as `CSV_V1_EXTERNAL_ID_COLUMN`; values are never copied into provenance. `deleted=true` requires blank `display_name`、`relation_type`、`relation_target_environment_id` and `relation_target_external_id`, plus a non-empty allow-listed tombstone reason, and creates a tombstone Observation; it never hard-deletes. File SHA and next row are sealed as checkpoint; a changed file SHA cannot resume and returns `CSV_CHECKPOINT_MISMATCH`.

- [ ] **Step 3: Stream upload to quarantine storage and reconcile under a fence**

`POST .../imports` accepts `multipart/form-data` parts `file` and `detached_signature`, streams once through SHA/DLP into an encrypted quarantine object store, verifies signature through the source's opaque CredentialReference, and returns `202`. The database stores only object reference ID, SHA, byte/row counts and expiry；object credentials never enter the browser or Run payload. The Worker claims the Import Run, rechecks source revision/gate/fence, parses pages and atomically reconciles each page/checkpoint. Quarantine objects are deleted after terminal success/failure；cleanup uncertainty sets Run `FAILED` with `SOURCE_IMPORT_CLEANUP_UNCERTAIN` and gate `SUSPENDED`.

Backpressure is fixed at one active CSV run per source, four per Workspace, 100,000 pending rows per Workspace; excess returns `429` plus bounded `Retry-After`. A partial file never performs missing-asset stale detection; only a signed `complete_snapshot=true` manifest may do so.

- [ ] **Step 4: Verify real streaming, replay, Scope, and cleanup**

Run:

~~~bash
gofmt -w $(rg --files internal/assetsource/csvimport internal/httpapi -g '*.go')
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

`IngestionBatchV1` contains only `schema_version`, `sequence`, `previous_batch_digest`, `complete_snapshot`, Provider `observed_at`, `environment_id`, max 1,000 typed items and detached `signature_key_id/signature`. The server derives Tenant/Workspace/Source/Provider from SAN and published revision；verifies signature through the opaque reference；requires sequence exactly `checkpoint+1`, previous digest equality, finite UTC microsecond Provider time within 5 minutes and authority-scope membership. Before signature verification it computes `signed_payload_sha256` over RFC 8785 canonical unsigned fields（everything except `signature_key_id/signature`）；the accepted checkpoint digest is that same value. Every item maps to `OBJECT_SEQUENCE{OrderSequence=sequence,ProviderVersionSHA256=SHA256(FramedTupleV1("control-plane-api-object-version.v1",sequence,previous_batch_digest,observed_at,environment_id,signed_payload_sha256))}` using the Pack 01 byte encoding and decoded digest bytes. Thus signed Provider time/lineage/payload are indirectly bound into every Observation chain, while semantic `provider_fact_sha256` and Catalog `asset_observations.observed_at` remain time-independent/server-owned. It canonicalizes and DLP-checks before creating a Run；429/503 are safe to retry because no Observation exists before durable Run acceptance.

One Source accepts at most one durable nonterminal API ingestion Run/batch across `QUEUED|DELAYED|RUNNING|FINALIZING`; an identical idempotent retry returns that original Run, while a distinct second batch returns `429 SOURCE_BACKPRESSURE` with `Retry-After` capped at 60 seconds and creates no second queue row. The Workspace cap remains eight nonterminal batches and 20 requests/second with burst 40. Persist `not_before`/queue depth so replica changes do not reset the limit. A valid tombstone creates `STALE`; a later observation records recovery but remains `STALE`. Unknown field, bad signature, replay, sequence gap, oversized page, source/revision/gate drift and wrong client certificate fail before reconciliation.

- [ ] **Step 3: Implement Source creation and the six-step Source revision workspace**

`CREATE_SOURCE` opens this workspace without a `sourceId`; Step 1 submits the complete safe create command and receives the stable Source plus revision 1 and a durable mutation receipt. Existing Sources enter the same workspace with `sourceId/revision`. The vertical steps are exact:

1. **Scope and installed Provider** — Workspace plus server-returned Source Profile; `KUBERNETES_OPERATOR` says Phase 3/UNAVAILABLE.
2. **Authority and identity** — allowed Environments and provider-owned identity rules; no endpoint editor.
3. **Opaque references** — Credential, Trust and Network Policy IDs with safe health metadata only.
4. **Sync and limits** — on-demand/schedule, page/rate/backpressure profile and deletion semantics.
5. **Controlled validation** — durable run timeline for identity, trust, network, credential open/cleanup, fixed probe, schema/DLP/budget; stable codes only.
6. **Review and publish** — immutable diff, full revision/binding/proof digests, mandatory checkpoint-transition impact, affected assets/runs, reason, recent OIDC and publish.

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
