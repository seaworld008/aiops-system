# Connection Repository, Compiler, and Runtime Publication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 持久化 Connection/Credential/Operation，编译经验证的 Target/Capability closure，并以可并发、可恢复、可回滚的方式发布不可变 Runtime Bundle。

**Architecture:** PostgreSQL transaction 统一幂等记录、Revision 状态和队列；compiler 复用现有 typed read-path builders 并只接收 digest-resolved inputs；publication 以 immutable artifacts 和 deployment attestation 驱动滚动切换与回滚。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、pgx v5/pgxmock、JCS、SHA-256、现有 readtarget/readconnector/readexecutor/readruntime/readassembly。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- 生产闭环必须支持多 Control Plane 副本和多部署 worker；正确性只依赖 PostgreSQL lock、optimistic version、idempotency record、lease/fencing，不依赖单进程 mutex。
- 当前阶段只发布只读 Target/Capability Runtime；它为后续受治理写执行提供不可变 Connection/Realm 基础，但不得提前生成 write action。
- 编译输入必须来自 `VALIDATED` Revision、成功 Validation、确定 Credential cleanup，以及来源有效、映射 `EXACT`、生命周期为 `DISCOVERED|STALE|ACTIVE` 的同 Scope Asset；任一事实漂移都 fail closed。只有 Runtime 精确 `APPLIED` 后才可激活 Asset，调查 admission 仍要求 `ACTIVE+EXACT`。
- Published Target、Capability Set、Artifact、Bundle 不原地更新；活动调查固定原 Bundle digest，滚动发布不会改变在途执行。
- 生产路径不得使用 memory repository 或 fake compiler/deployer；测试 fake 只在 `*_test.go`。
- 公开对象和错误只含低敏摘要；Artifact bytes 不可由 String/JSON/日志暴露。
- 每个任务先写失败测试并确认预期失败，再实现，最后运行 race/真实 PostgreSQL 相关测试并 commit。

### Task 3: Implement scoped repositories and idempotent Connection service

**Files:**
- Create: `internal/connectionprofile/repository.go`
- Create: `internal/connectionprofile/postgres/repository.go`
- Create: `internal/connectionprofile/postgres/repository_test.go`
- Create: `internal/connectionprofile/service.go`
- Create: `internal/connectionprofile/service_test.go`
- Create: `internal/credentialreference/repository.go`
- Create: `internal/credentialreference/postgres/repository.go`
- Create: `internal/credentialreference/postgres/repository_test.go`
- Create: `internal/operation/repository.go`
- Create: `internal/operation/postgres/repository.go`
- Create: `internal/operation/postgres/repository_test.go`

**Interfaces:**
- Consumes: package 01 domains；`assetcatalog.Reader.Get`；`authz.Authorizer.Authorize`；caller-provided ID source and UTC clock。
- Produces:

```go
type Repository interface {
    CreateProfile(
        context.Context,
        Profile,
        Revision,
        string,
        string,
    ) (Profile, Revision, bool, error)
    CreateRevision(
        context.Context,
        Revision,
        string,
        string,
    ) (Revision, bool, error)
    Get(context.Context, assetcatalog.Scope, string) (Profile, []Revision, error)
    List(context.Context, ListRequest) (Page, error)
    ReplayValidation(
        context.Context,
        assetcatalog.Scope,
        string,
        string,
    ) (operation.Operation, bool, error)
    BeginValidation(
        context.Context,
        Revision,
        operation.Operation,
        int64,
    ) (operation.Operation, bool, error)
    TransitionRevision(context.Context, Revision, int64) (Revision, error)
}

type CredentialReader interface {
    Get(
        context.Context,
        assetcatalog.Scope,
        string,
        int64,
    ) (credentialreference.Reference, error)
    List(context.Context, credentialreference.ListRequest) (
        credentialreference.Page,
        error,
    )
}

type OperationRepository interface {
    Get(context.Context, assetcatalog.Scope, string) (operation.Operation, error)
    Update(context.Context, operation.Operation, int64) (operation.Operation, error)
}
```

- [ ] **Step 1: Write failing pgxmock and service tests**

Required cases:

```go
func TestCreateProfileReturnsStoredReplayBeforeMutableAdmission(t *testing.T)
func TestCreateProfileRejectsIdempotencyHashMismatch(t *testing.T)
func TestBeginValidationCommitsRevisionOperationAndQueueAtomically(t *testing.T)
func TestConcurrentBeginValidationCreatesOneOperation(t *testing.T)
func TestRepositoryAlwaysScopesConnectionQueries(t *testing.T)
func TestValidateRequiresActiveMatchingCredentialReference(t *testing.T)
func TestValidateReauthorizesBeforeReturningReplay(t *testing.T)
```

Every pgxmock expectation includes Tenant/Workspace/Environment. Simulate zero-row optimistic UPDATE and map it to stable version conflict. Simulate error after Operation insert and prove transaction rollback leaves no Revision transition or queue row.

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
go test ./internal/connectionprofile/... ./internal/credentialreference/... ./internal/operation/... -count=1
```

Expected: FAIL because repository constructors and service are absent.

- [ ] **Step 3: Implement transaction and replay order**

For each mutation:

1. authorize current Principal;
2. look up immutable replay by Scope + operation kind + Idempotency-Key;
3. same request hash returns stored response; different hash returns conflict;
4. for a new request lock `Asset → Profile → Revision → Operation`;
5. recheck source-valid、`EXACT`、`DISCOVERED|STALE|ACTIVE` Asset and exact Credential provider/scope/revision/usage role;
6. write Revision children, Operation, queue and response snapshot in one transaction;
7. use `WHERE version = expected_version` and require one row;
8. canonicalize/hash response snapshot before store and verify again on read.

`BeginValidation` performs the replay recheck inside the same transaction to close races. `Validate` never separately commits Operation before queue. Constructor rejects typed-nil dependencies. Public errors never contain SQL or stored documents.

- [ ] **Step 4: Run focused and race tests**

Run:

```bash
go test ./internal/connectionprofile/... ./internal/credentialreference/... ./internal/operation/... -count=1
go test -race ./internal/connectionprofile/... ./internal/credentialreference/... ./internal/operation/... -count=1
```

Expected: both PASS；100 concurrent identical calls return one Operation ID；hash mismatch, cross-Scope and stale version are stable failures.

- [ ] **Step 5: Commit**

```bash
git add internal/connectionprofile internal/credentialreference internal/operation
git commit -m "feat: persist scoped connection operations"
```

### Task 4: Compile validated revisions into typed Target and Capability artifacts

**Files:**
- Modify: `internal/readtarget/contract.go`
- Modify: `internal/readtarget/manifest_test.go`
- Modify: `internal/readconnector/manifest.go`
- Modify: `internal/readconnector/manifest_test.go`
- Modify: `internal/readexecutor/egress_manifest.go`
- Modify: `internal/readexecutor/egress_manifest_test.go`
- Modify: `internal/readassembly/snapshot.go`
- Modify: `internal/readassembly/snapshot_test.go`
- Create: `internal/capability/compiler.go`
- Create: `internal/capability/compiler_test.go`

**Interfaces:**
- Consumes: validated Connection Revision and digest-resolved trust/network/credential/realm closures；existing typed manifest constructors。
- Produces:

```go
type CompileInput struct {
    Scope assetcatalog.Scope
    Asset assetcatalog.Asset
    Revision connectionprofile.Revision
    ValidationResultDigest string
    CredentialCleanup connectionprofile.CredentialCleanup
    ConnectorManifest readconnector.Manifest
    EgressManifest readexecutor.EgressManifest
    ExecutorProfile readexecutor.Profile
}

type CompiledTarget struct {
    TargetRef string
    TargetDigest string
    ConnectorManifest []byte
    TargetManifest []byte
    EgressManifest []byte
    ExecutorProfileDigest string
}

type CompiledCapability struct {
    ID string
    DefinitionRevision int64
    TargetRef string
    ActionClass string
    ParameterSchemaDigest string
    ResultPolicyDigest string
    MaxDurationSeconds int
    MaxResultItems int
    MaxResultBytes int
    ManifestDigest string
}
```

- [ ] **Step 1: Write failing compiler and boundary tests**

```go
func TestCompileTargetBindsAllValidatedInputs(t *testing.T)
func TestCompileTargetRejectsDigestOrScopeDrift(t *testing.T)
func TestCompileCapabilityAllowsReadOnlyTypedDefinitions(t *testing.T)
func TestCompileCapabilityRejectsUnknownOrWriteAction(t *testing.T)
func TestCompileProducesDeterministicCanonicalBytes(t *testing.T)
func TestOnlyReadAssemblyMayCompileCapturedManifest(t *testing.T)
```

- [ ] **Step 2: Verify failure**

Run:

```bash
go test ./internal/readtarget ./internal/readconnector ./internal/readexecutor ./internal/readassembly ./internal/capability -count=1
```

Expected: FAIL because safe encoders and Capability compiler do not exist.

- [ ] **Step 3: Add safe builders and encoders**

Add:

```go
func BuildCapturedTargetRef(
    provider string,
    endpointIdentityDigest string,
    trustDigest string,
    credentialReferenceDigest string,
    networkPolicyDigest string,
    realmDigest string,
    validationResultDigest string,
) (string, error)

func EncodeManifest(readconnector.Manifest) ([]byte, error)
func EncodeEgressManifest(readexecutor.EgressManifest) ([]byte, error)
func CompileValidated(CompileInput) (CompiledTarget, []CompiledCapability, error)
```

`CompileValidated` rechecks Scope, Asset status/mapping, Revision `VALIDATED`, cleanup, all input digests and exact capability revisions. It uses existing `BuildConnectorID`, `BuildTargetRef`, `BuildEgressPolicyRef` and canonical encoders; it cannot accept caller-supplied manifest JSON. Capability action class is fixed `OBSERVABILITY_READ`; unknown Provider or write-like action fails.

- [ ] **Step 4: Run focused and architecture tests**

Run:

```bash
go test ./internal/readtarget ./internal/readconnector ./internal/readexecutor ./internal/readassembly ./internal/capability -count=1
go test ./internal/architecture -count=1
```

Expected: PASS；same input is byte-identical，any digest mutation changes reference or rejects；architecture allowlist has no new bypass caller.

- [ ] **Step 5: Commit**

```bash
git add internal/readtarget internal/readconnector internal/readexecutor internal/readassembly internal/capability
git commit -m "feat: compile validated connection targets"
```

### Task 5: Persist and roll out immutable Runtime Publications

**Files:**
- Create: `internal/runtimepublication/publication.go`
- Create: `internal/runtimepublication/publication_test.go`
- Create: `internal/runtimepublication/repository.go`
- Create: `internal/runtimepublication/postgres/repository.go`
- Create: `internal/runtimepublication/postgres/repository_test.go`
- Create: `internal/runtimepublication/service.go`
- Create: `internal/runtimepublication/service_test.go`
- Create: `internal/runtimepublication/worker.go`
- Create: `internal/runtimepublication/worker_test.go`
- Create: `internal/assetcatalog/connection_activation.go`
- Create: `internal/assetcatalog/connection_activation_test.go`
- Create: `internal/assetcatalog/postgres/connection_activation.go`
- Create: `internal/assetcatalog/postgres/connection_activation_integration_test.go`
- Modify: `internal/readruntime/bundle.go`
- Modify: `internal/readruntime/bundle_test.go`

**Interfaces:**
- Consumes: 本文件 Task 4 compiler；validated Revision repository；deployment distributor/attestor；current active Runtime bundle reader；Phase 1 Asset/source/mapping lifecycle repository。
- Produces:

```go
type Repository interface {
    ReplayPublish(
        context.Context,
        assetcatalog.Scope,
        string,
        string,
    ) (operation.Operation, bool, error)
    Publish(
        context.Context,
        PublishTransaction,
    ) (Publication, operation.Operation, bool, error)
    MarkApplying(
        context.Context,
        assetcatalog.Scope,
        string,
        int64,
    ) (Publication, error)
    AttestApplied(
        context.Context,
        DeploymentAttestation,
    ) (Publication, error)
    MarkFailed(
        context.Context,
        assetcatalog.Scope,
        string,
        int64,
        string,
    ) (Publication, error)
    Get(
        context.Context,
        assetcatalog.Scope,
        string,
    ) (Publication, []Artifact, error)
    List(context.Context, ListRequest) (Page, error)
}

type Distributor interface {
    Stage(
        context.Context,
        assetcatalog.Scope,
        string,
        string,
        []Artifact,
    ) (deploymentID string, error)
    Rollout(
        context.Context,
        assetcatalog.Scope,
        string,
        string,
        int,
    ) error
    Observe(
        context.Context,
        assetcatalog.Scope,
        string,
    ) (DeploymentObservation, error)
    Rollback(
        context.Context,
        assetcatalog.Scope,
        string,
        string,
    ) error
}

type AssetLifecycleActivator interface {
    ActivateAfterPublishedConnection(
        context.Context,
        assetcatalog.ActivateAfterConnectionCommand,
    ) (assetcatalog.Asset, error)
}
```

`assetcatalog.ActivateAfterConnectionCommand` carries only Scope、Asset ID/expected version、Connection ID/revision、Runtime Publication ID/digest and activation time. Its PostgreSQL implementation locks the Asset and joins the current source/mapping/Connection/Validation cleanup/Runtime publication facts in the same transaction; it permits only `DISCOVERED|STALE|ACTIVE → ACTIVE`, emits one audit/outbox record, and returns an idempotent replay for the same publication digest.

Publication statuses are `PENDING/APPLYING/APPLIED/FAILED/DRIFTED/ROLLED_BACK`. Artifacts include canonical Connector/Target/Egress manifests and captured trust closure. `Artifact.String`, `GoString` and `MarshalJSON` return only kind/schema/digest/size.

- [ ] **Step 1: Write failing atomicity, HA, rollout and rollback tests**

```go
func TestPublishCommitsClosureRevisionAndOperationAtomically(t *testing.T)
func TestConcurrentPublishCreatesOneImmutableClosure(t *testing.T)
func TestPublishRejectsValidationOrAssetDrift(t *testing.T)
func TestWrongDeploymentDigestMarksPublicationDrifted(t *testing.T)
func TestRollingPublicationKeepsInFlightBundlePinned(t *testing.T)
func TestRolloutFailureRollsBackToLastAttestedBundle(t *testing.T)
func TestWorkerRestartResumesPendingOrApplyingPublication(t *testing.T)
func TestAppliedPublicationActivatesDiscoveredOrStaleExactAsset(t *testing.T)
func TestActivationRejectsSourceMappingConnectionOrCleanupDrift(t *testing.T)
func TestArtifactFormattingNeverReturnsBytes(t *testing.T)
```

Use a real PostgreSQL integration case for competing publishers and worker takeover. Fake distributor is test-only and records stage/rollout/observe/rollback calls; production constructor rejects nil or in-memory substitutes.

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
go test ./internal/runtimepublication ./internal/runtimepublication/postgres ./internal/readruntime -count=1
```

Expected: FAIL because publication model, repository and worker are absent.

- [ ] **Step 3: Implement the atomic publication transaction**

Inside one transaction:

1. reauthorize publish and require recent authentication, nonempty 1–512-byte change reason, If-Match and Idempotency-Key;
2. lock Asset、Profile、target Revision、successful Validation Operation/checks/cleanup;
3. recheck source-valid + `EXACT` + `DISCOVERED|STALE|ACTIVE` + `VALIDATED`, expected versions and validation digest;
4. recheck replay; same hash returns prior Operation, different hash conflicts;
5. compile Target/Capability and canonical Runtime Bundle;
6. insert immutable PublishedTarget、CapabilitySet/items、RuntimePublication/artifacts;
7. mark old published Revision `SUPERSEDED` and new Revision `PUBLISHED`;
8. start Publication as `PENDING` with capabilities `CLOSED_BY_GATE`;
9. complete Operation and store safe response/audit reference.

Any failure rolls back all rows. Old publications and artifacts are never updated/deleted.

- [ ] **Step 4: Implement resumable rolling deployment and rollback**

`worker.go` claims `PENDING/APPLYING` work with durable short lease and fencing. It stages artifacts, rolls out in bounded batches, observes exact bundle digest, then sends internal deployment attestation. Defaults:

- development batch 100%;
- production batches 10%, 25%, 50%, 100%;
- each batch needs all healthy instances reporting exact bundle digest for two consecutive observations;
- timeout or mismatch stops rollout and calls `Rollback` with last `APPLIED` digest;
- successful exact attestation and terminal validation-credential cleanup use the PostgreSQL transaction coordinator to call `ActivateAfterPublishedConnection`; only after the Asset is `ACTIVE` may `APPLYING→APPLIED` open the compiled capability gate;
- activation rechecks source validity、mapping、Asset version、Connection/Runtime publication digest and is idempotent; a crash resumes it, while drift keeps the gate closed and rolls back or marks the publication `DRIFTED`;
- wrong digest changes to `DRIFTED`, keeps gate closed, emits stable audit/metric, then rolls back;
- process restart or lease expiry resumes from persisted phase and completed batch;
- in-flight investigations retain their captured old bundle digest until completion.

Low-sensitivity metrics:

```text
aiops_runtime_publication_total{status,provider}
aiops_runtime_publication_duration_seconds{provider}
aiops_runtime_rollout_batch_total{result}
aiops_runtime_rollback_total{reason_code}
aiops_runtime_bundle_drift_total{provider}
```

Labels never include tenant, URL, connection ID, credential ID, error text or digest.

- [ ] **Step 5: Run focused, race and PostgreSQL tests**

Run:

```bash
go test ./internal/runtimepublication/... ./internal/readruntime -count=1
go test -race ./internal/runtimepublication/... -count=1
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/runtimepublication/postgres -run 'Concurrent|Resume|Rollback' -count=1
```

Expected: all PASS；100 concurrent publishes yield one closure；restart resumes；drift never opens gates；rollback restores last attested digest without changing in-flight bundle references.

- [ ] **Step 6: Commit**

```bash
git add internal/runtimepublication internal/assetcatalog internal/readruntime
git commit -m "feat: publish and roll back immutable runtime bundles"
```
