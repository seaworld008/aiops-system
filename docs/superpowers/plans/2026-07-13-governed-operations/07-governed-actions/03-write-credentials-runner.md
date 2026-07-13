# Isolated WRITE Credentials and Runner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为已授权 Action 创建独立 WRITE Realm、单 Attempt 短期不可续租凭据、持久 fenced queue/admission 和只执行四种固定 mutation 的真实 mTLS WRITE Runner。

**Architecture:** Control Plane 在 PostgreSQL transaction 中提交 Authorization Bundle 和 queue；Gateway 在 claim/start/credential/pre-mutation 边界复验 Runner identity、Realm、Gate、Plan、policy 和 drift。Credential issuer/revoker 与 READ/VALIDATION 完全隔离，Runner 通过 typed adapter 生成固定请求，Executor/Runner 均不能接受任意 command、URL 或 payload。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、mTLS/SPIFFE、Vault/Kubernetes/AWX/Git provider dynamic credentials、chi v5、pgx v5、TLS 1.3、existing `execution/credential/runnergateway/runnerclient/isolatedexec`。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- READ、VALIDATION、WRITE 使用不同 Root、SPIFFE Pool、Realm、issuer profile、queue operation and credential；cross-pool 双向拒绝。
- WRITE credential binds one Tenant/Workspace/Environment、Action ID、Asset ID、Attempt、lease epoch、permission、exact resource and expiry；TTL ≤300s，single delivery，no Renew method。
- Raw credential exists only in issuer response and locked Runner/Executor memory, is zeroed immediately after use, and never enters DB/Temporal/API/log/trace/audit。
- Production claim requires Gate `AVAILABLE` or exact supervised `CANARY_RUNNING` decision；global one-active-production-write ceiling remains。
- Claim/Start/Heartbeat/Complete/credential phases all use mTLS identity + persisted registration/Realm + hashed lease token + epoch fencing。
- Admission immediately before credential issue re-resolves exact target/snapshot/runtime/policy/kill switch and provider preconditions。
- Queue submission、claim、admission、credential issue and pre-mutation each revalidate the Phase 6 handoff/READ baseline/current READ admission plus the exact ACCEPTED Action platform successor and Action manifest；missing or drifted dual-platform closure stops before provider access。
- Pre-mutation check occurs after credential issue but before first network write; denial revokes without mutation。
- Runner adapters generate fixed method/path/body from typed Envelope. Proxy、redirect、cookie jar、generic headers、generic body and arbitrary retry are disabled。
- Every catalog-declared mutation step is sent at most once per Attempt. Kubernetes/AWX have one step；GitOps has the fixed commit/revert step followed by fixed change-request creation. A step is never repeated, and uncertainty stops the remaining graph and enters reconciliation。
- Production constructors reject memory queue/fake issuer/fake adapter/test CA/MSW。

---

### Task 1: Add WRITE Realm and single-attempt credential isolation

**Files:**
- Create: `internal/writecredential/types.go`
- Create: `internal/writecredential/types_test.go`
- Create: `internal/writecredential/issuer_registry.go`
- Create: `internal/writecredential/issuer_registry_test.go`
- Create: `internal/writecredential/broker.go`
- Create: `internal/writecredential/broker_test.go`
- Create: `internal/writecredential/postgres/repository.go`
- Create: `internal/writecredential/postgres/repository_test.go`
- Create: `internal/writeexecution/realm.go`
- Create: `internal/writeexecution/postgres/realm.go`
- Create: `internal/writeexecution/postgres/realm_test.go`
- Modify: `internal/runneridentity/identity.go`
- Modify: `internal/runneridentity/identity_test.go`

**Interfaces:**
- Consumes: `write_runner_realms`、`action_attempts`、existing durable credential protector/revoker、package 02 credential-stage policy。
- Produces:

```go
type Issuer interface {
    Issue(
        context.Context,
        writecredential.IssueRequest,
    ) (writecredential.IssuedLease, error)
    Revoke(context.Context, string) error
}

type Broker interface {
    Prepare(
        context.Context,
        writecredential.PrepareCommand,
    ) (writecredential.PreparedGrant, bool, error)
    IssueOnce(
        context.Context,
        writecredential.IssueCommand,
    ) (writecredential.Delivery, error)
    RequestRevocation(
        context.Context,
        writecredential.RevokeCommand,
    ) error
}

type RealmReader interface {
    Resolve(
        context.Context,
        writeexecution.ResolveRealmRequest,
    ) (writeexecution.Realm, error)
}
```

- [ ] **Step 1: Write failing issuer/Realm/single-delivery tests**

```go
func TestWriteRealmRejectsReadValidationAndWrongWriteRoot(t *testing.T)
func TestIssuerRegistryCannotRegisterReadOrValidationProfile(t *testing.T)
func TestPreparedGrantBindsActionAssetAttemptEpochAndExactResource(t *testing.T)
func TestIssueOnceCannotRenewReplayOrCrossAttempt(t *testing.T)
func TestUnsafeTTLOrScopeRevokesIssuerLeaseImmediately(t *testing.T)
func TestKubernetesIssuerUsesPreprovisionedExactRBACAndCannotCreateRBAC(t *testing.T)
func TestGitAndAWXIssuerCapabilitiesMatchExactDefinition(t *testing.T)
func TestCredentialDeliveryCannotMarshalLogOrCopySecret(t *testing.T)
func TestCleanupPersistsBeforeAttemptCanBecomeTerminal(t *testing.T)
func TestCredentialIssueRejectsClosedReadAdmissionOrActionPlatformDrift(t *testing.T)
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/writecredential/... ./internal/writeexecution/... ./internal/runneridentity -run 'Write|Issuer|Credential|Realm' -count=1
```

Expected: FAIL because isolated Realm/issuer/broker types do not exist.

- [ ] **Step 3: Implement exact grant and delivery contracts**

```go
type PrepareCommand struct {
    Scope assetcatalog.Scope
    ActionID string
    PlanID string
    PlanHash string
    ActionType action.ActionType
    AssetID string
    AssetRevision int64
    AttemptID string
    Attempt int64
    LeaseEpoch int64
    RunnerID string
    WriteRealmID string
    IssuerProfileID string
    IssuerRevision string
    ConnectorID string
    Permission string
    Resource string
    RequestedTTL time.Duration
    AuthorizationExpiresAt time.Time
    AdmissionDigest string
    Platform action.PlatformBinding
}

type Delivery struct {
    GrantID string
    AttemptID string
    ExpiresAt time.Time
    secret []byte
}

func (delivery *Delivery) Consume(
    use func([]byte) error,
) error
```

`Prepare` requires ADMITTED attempt, current credential-stage ALLOW decision, exact Definition permission, matching Realm issuer binding, current dual-platform closure and TTL = min(300s, plan/auth/lease/admission/platform-evidence deadline). It inserts PREPARED revocation anchor idempotently. `IssueOnce` locks Attempt/Grant, revalidates the same closure before calling one WRITE issuer, validates lease, persists protected accessor, marks one delivery, invokes an in-process callback and clears bytes; a second call returns `ErrAlreadyDelivered`, never the secret. `Delivery` implements failing `MarshalJSON/String/GoString` and cannot expose a `Secret()` method.

- [ ] **Step 4: Implement Realm/issuer registration and cleanup**

Realm resolution matches Tenant/Workspace/Environment、WRITE SPIFFE registration、root digest、Realm revision、Action type、adapter family、issuer profile/revision and network policy digest in one transaction. READ/VALIDATION issuer IDs are rejected by prefix and stored profile kind. Kubernetes issuance uses a pre-provisioned per-Asset ServiceAccount and exact `resourceNames` Role digest, issues only a bounded TokenRequest, and never creates/updates RBAC. Git credentials are repository/project scoped and cannot merge; AWX principals are restricted to the sealed Job Template/Inventory and cannot edit templates, inventories or credentials. Shared admin credentials and static long-lived provider tokens are invalid production profiles.

Completion、cancel、timeout、Runner crash and uncertainty call existing durable revocation queue. Attempt terminal status requires `REVOKED|NO_CREDENTIAL` receipt. Failed revocation moves Attempt to `HUMAN_REQUIRED` and blocks target/action Gate until resolved.

- [ ] **Step 5: Run focused, race and PostgreSQL tests**

Run:

```bash
go test ./internal/writecredential/... ./internal/writeexecution/... ./internal/runneridentity -count=1
go test -race ./internal/writecredential/... ./internal/writeexecution/... -count=1
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/writecredential/postgres ./internal/writeexecution/postgres -run 'Scope|Attempt|Delivery|Cleanup' -count=1
```

Expected: all PASS；cross-pool denied；single delivery/revocation durable；no raw credential projection.

- [ ] **Step 6: Commit**

```bash
git add internal/writecredential internal/writeexecution internal/runneridentity
git commit -m "feat: isolate production write credentials"
```

### Task 2: Gate production queue claim and pre-mutation admission

**Files:**
- Modify: `internal/execution/action_queue.go`
- Modify: `internal/execution/action_queue_test.go`
- Modify: `internal/execution/postgres/repository.go`
- Modify: `internal/execution/postgres/repository_test.go`
- Modify: `internal/execution/service.go`
- Modify: `internal/execution/service_test.go`
- Create: `internal/writeexecution/admission.go`
- Create: `internal/writeexecution/admission_test.go`
- Modify: `internal/runnergateway/types.go`
- Modify: `internal/runnergateway/validate.go`
- Modify: `internal/runnergateway/router.go`
- Modify: `internal/runnergateway/router_test.go`
- Modify: `internal/runnergateway/postgres/backend.go`
- Modify: `internal/runnergateway/postgres/backend_test.go`
- Modify: `internal/runnerclient/grant.go`
- Modify: `internal/runnerclient/grant_internal_test.go`
- Modify: `api/openapi/runner-v1.json`
- Modify: `api/openapi/runner_v1_test.go`

**Interfaces:**
- Consumes: package 02 Authorization Bundle/evaluator；Phase 6 live READ admission；package 01 accepted Action platform successor；Task 1 Realm/Broker；existing ActionQueue/fencing protocol。
- Produces:

```go
type ProductionQueue interface {
    SubmitAuthorized(
        context.Context,
        execution.AuthorizedSubmission,
    ) (executionlease.Execution, bool, error)
    ClaimAuthorized(
        context.Context,
        execution.ActionClaimRequest,
    ) (execution.ClaimedAction, error)
    AdmitAndStart(
        context.Context,
        writeexecution.AdmitCommand,
    ) (writeexecution.AdmittedAttempt, error)
}

type AdmissionGate interface {
    Admit(
        context.Context,
        writeexecution.AdmitRequest,
    ) (writeexecution.Admission, error)
    CheckPreMutation(
        context.Context,
        writeexecution.PreMutationRequest,
    ) (writeexecution.PreMutationPermit, error)
}
```

- [ ] **Step 1: Write failing production-open, duplicate and drift tests**

```go
func TestProductionSubmitRequiresExactAuthorizationBundle(t *testing.T)
func TestClosedTypeOrExpiredBundleCannotBeClaimed(t *testing.T)
func TestClaimRequiresMatchingWriteCertificateRealmAndScopeRevision(t *testing.T)
func TestConcurrentDuplicateClaimHasOneLeaseAndOneAttempt(t *testing.T)
func TestStaleEpochCannotStartHeartbeatCompleteOrPrepareCredential(t *testing.T)
func TestAdmissionRejectsAnyPlanTargetRuntimePolicyKillOrApprovalDrift(t *testing.T)
func TestAdmissionRejectsHandoffReadAdmissionOrActionPlatformDriftAtEveryBoundary(t *testing.T)
func TestUnauthorizedWriteSurfaceClosesQueueClaimAdmissionAndPreMutation(t *testing.T)
func TestPreMutationDenialRevokesCredentialWithoutCallingAdapter(t *testing.T)
func TestProductionDescriptorContainsV2BindingsButNoCredentialOrEndpoint(t *testing.T)
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/execution/... ./internal/writeexecution/... ./internal/runnergateway/... ./internal/runnerclient ./api/openapi -run 'Production|Authorized|Admission|Duplicate|Stale' -count=1
```

Expected: FAIL because existing queue/client/backend deliberately reject every production WRITE.

- [ ] **Step 3: Implement authorized submission and claim transaction**

```go
type AuthorizedSubmission struct {
    Envelope action.Envelope
    PlanID string
    PlanHash string
    AuthorizationBundle actionauthorization.AuthorizationBundle
    Phase6HandoffID string
    Phase6HandoffDigest string
    ReadBaselineDigest string
    ReadAdmissionRevision int64
    ReadAdmissionDigest string
    ActionPlatformID string
    ActionPlatformRevision int64
    ActionPlatformManifestDigest string
    ActionManifestDigest string
    TargetKey string
    EnvironmentRevision string
    DefinitionRevision int64
    GateRevision int64
    WriteRealmID string
    Production bool
}

type AdmittedAttempt struct {
    AttemptID string
    ActionID string
    Attempt int64
    LeaseEpoch int64
    RunnerID string
    WriteRealmID string
    AdmissionDecisionID string
    AdmissionDigest string
    AuthorizationBundleDigest string
    Phase6HandoffDigest string
    ReadBaselineDigest string
    ReadAdmissionDigest string
    ActionPlatformManifestDigest string
    CredentialGrantID string
    CredentialExpiresAt time.Time
    StartedAt time.Time
}
```

`SubmitAuthorized` rechecks Bundle semantic hash and exact handoff/baseline/READ-admission/successor fields, then inserts queue metadata/idempotency atomically. `ClaimAuthorized` locks candidate、Phase 6 readiness/handoff、current READ admission、Action platform successor、current gate、Plan/binding、Bundle、Runner registration/Realm and target-active index in that order. It requires the live READ admission open, successor ACCEPTED, manifests exact and `UNAUTHORIZED_WRITE_SURFACE_ABSENT=PASS`; then it permits production only for exact AVAILABLE or supervised CANARY_RUNNING gate, increments epoch, creates one `action_attempts` ADMITTING row and returns one lease token. Same semantic submit replays; active lease never replays token; duplicate claim gets no work.

`AdmitAndStart` verifies mTLS identity again inside transaction, evaluates CLAIM then ADMISSION, re-resolves both platform revisions/current READ admission and provider preconditions, changes Attempt to ADMITTED/RUNNING and calls Task 1 `Prepare`. Any mismatch rejects Attempt, requests cleanup if needed and never starts.

- [ ] **Step 4: Extend the existing Runner protocol without adding generic fields**

Keep routes `/runner/v1/jobs:lease` and `/{job_id}:start|heartbeat|credential-anchor|release|complete`. V2 start response adds only `attempt_id`、`attempt`、`admission_digest`、`authorization_bundle_digest`、`phase6_handoff_digest`、`read_baseline_digest`、`read_admission_digest`、`action_platform_manifest_digest`、`write_realm_revision`. Job Descriptor contains signed V2 Envelope and digest identities, never endpoint/credential/approval claims documents.

`runnerclient.validExecutorGrant` accepts `Production=true` only when Envelope V2 validates, descriptor/bundle/admission/Realm and dual-platform digests match the private lease, the Gateway has just re-read live READ admission/current successor/unauthorized-surface gate, credential phase is ACTIVE and pre-mutation permit was just obtained. V1 production remains rejected. Strict JSON forbids endpoint、credential、claims and unknown properties.

The existing child-create permit remains one-time. Runner creates the dynamic child through its WRITE issuer client, records only protected revoke accessor through `credential-anchor`, activates it, then binds Executor. Gateway never returns raw child credential.

- [ ] **Step 5: Run queue, protocol, race and PostgreSQL tests**

Run:

```bash
go test ./internal/execution/... ./internal/writeexecution/... ./internal/runnergateway/... ./internal/runnerclient ./api/openapi -count=1
go test -race ./internal/execution/... ./internal/writeexecution/... ./internal/runnergateway/... -count=1
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/execution/postgres ./internal/runnergateway/postgres -run 'Production|Concurrent|Fence|Admission' -count=1
```

Expected: all PASS；one concurrent claimant/attempt/credential authorization；all stale/cross-Realm/drift paths stop before adapter.

- [ ] **Step 6: Commit**

```bash
git add internal/execution internal/writeexecution internal/runnergateway internal/runnerclient api/openapi/runner-v1.json api/openapi/runner_v1_test.go
git commit -m "feat: admit fenced production write actions"
```

### Task 3: Implement fixed write adapters and production WRITE Runner assembly

**Files:**
- Create: `internal/writeadapter/result.go`
- Create: `internal/writeadapter/result_test.go`
- Create: `internal/writeadapter/transport.go`
- Create: `internal/writeadapter/transport_test.go`
- Create: `internal/writeadapter/kubernetes/adapter.go`
- Create: `internal/writeadapter/kubernetes/adapter_test.go`
- Create: `internal/writeadapter/gitops/adapter.go`
- Create: `internal/writeadapter/gitops/adapter_test.go`
- Create: `internal/writeadapter/awx/adapter.go`
- Create: `internal/writeadapter/awx/adapter_test.go`
- Create: `internal/writeadapter/architecture_boundary_test.go`
- Modify: `internal/executoripc/protocol.go`
- Modify: `internal/executoripc/protocol_test.go`
- Modify: `internal/isolatedexec/session.go`
- Modify: `internal/isolatedexec/session_linux_test.go`
- Modify: `cmd/executor/main.go`
- Modify: `cmd/executor/main_test.go`
- Modify: `cmd/write-runner/main.go`
- Modify: `cmd/write-runner/main_test.go`
- Modify: `build/package/write-runner/Dockerfile`

**Interfaces:**
- Consumes: admitted V2 Envelope、single-use local Credential、pre-mutation permit、trusted connector transport。
- Produces:

```go
type Adapter interface {
    ExecuteOnce(
        context.Context,
        writeadapter.Command,
    ) (writeadapter.MutationReceipt, error)
}

type MutationReceipt struct {
    SchemaVersion string
    ActionID string
    AttemptID string
    ActionType action.ActionType
    RequestDigest string
    ExternalOperationID string
    Outcome string
    AppliedStateDigest string
    FailureCode string
    StepLedgerDigest string
    SentAt time.Time
    ReceivedAt time.Time
    ReceiptDigest string
}
```

Outcome is `APPLIED|NO_CHANGE|FAILED|UNKNOWN`. Receipt has no raw response, credential, endpoint or request body.

- [ ] **Step 1: Write failing fixed-request and one-send tests**

```go
func TestKubernetesRestartBuildsOnlyExactDeploymentPatch(t *testing.T)
func TestKubernetesScaleUsesScaleSubresourceAndResourceVersion(t *testing.T)
func TestGitOpsRevertBuildsDeterministicBranchAndChangeRequest(t *testing.T)
func TestAWXRestartUsesExactTemplateInventoryHostsAndSerialOne(t *testing.T)
func TestAdaptersRejectProxyRedirectCookiesAndUnknownFields(t *testing.T)
func TestTransportUncertaintyReturnsUnknownWithoutSecondWrite(t *testing.T)
func TestExecutorRejectsV1PlanWrongPermitOrBindingDigest(t *testing.T)
func TestWriteRunnerDependencyGraphHasNoReadGrantOrGenericShell(t *testing.T)
func TestProductionWriteRunnerRejectsFakeOrMissingDependencies(t *testing.T)
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/writeadapter/... ./internal/executoripc ./internal/isolatedexec ./cmd/executor ./cmd/write-runner -count=1
```

Expected: FAIL because typed production adapters and production Runner assembly do not exist.

- [ ] **Step 3: Implement deterministic provider mutations**

Kubernetes restart sends one `PATCH application/merge-patch+json` to the exact apps/v1 Deployment. Body is generated only from sealed Action ID/PlanHash/NotBefore; there is no caller-owned map or raw JSON input:

```go
patch := restartPatch{
    Metadata: restartMetadata{
        ResourceVersion: command.ExpectedResourceVersion,
    },
    Spec: restartSpec{
        Template: restartTemplate{
            Metadata: restartTemplateMetadata{
                Annotations: map[string]string{
                    "aiops.openai.com/action-id":          command.ActionID,
                    "aiops.openai.com/plan-hash":          command.PlanHash,
                    "kubectl.kubernetes.io/restartedAt": command.NotBefore.UTC().Format(time.RFC3339Nano),
                },
            },
        },
    },
}
body, err := json.Marshal(patch)
if err != nil {
    return MutationReceipt{}, fmt.Errorf("encode fixed restart patch: %w", err)
}
```

Kubernetes scale sends one PUT/PATCH to exact `/scale` with signed resourceVersion and replicas only. It never writes Pod、Service、Secret、ConfigMap、RBAC、CRD or arbitrary patch paths.

GitOps adapter derives `aiops/revert/<action-id>`, verifies exact current head, creates the signed revert commit/tree, then opens one MR/PR against the trusted default branch with fixed title/body labels. Provider choice is only GITLAB/GITHUB. It cannot accept repository URL, arbitrary file path beyond signed path, arbitrary commit contents or auto-merge.

AWX adapter launches one exact snapshotted Job Template, exact Inventory and sorted Host IDs, `serial=1`. Generated launch body has only fixed `limit` and sealed `aiops_action_id/service_name` fields reconstructed from the Asset Snapshot and Definition revision；`service_name` is never caller-owned. It rejects surveys, ask-on-launch overrides, arbitrary extra vars, credentials, tags, forks or verbosity.

- [ ] **Step 4: Enforce one-send ledger and isolated process boundary**

Before each catalog-declared network step, persist `(attempt_id, step_ordinal, request_digest, SEND_INTENT)` under Attempt fencing. After headers are sent, that ordinal is never retried. Kubernetes/AWX define ordinal 1 only；GitOps defines ordinal 1 exact revert commit and ordinal 2 exact MR/PR creation, and ordinal 2 is reachable only after ordinal 1 is definitely applied. Definite 4xx/schema denial returns FAILED; definite idempotent no-change returns NO_CHANGE; timeout/reset/ambiguous 5xx after send returns UNKNOWN and no later ordinal runs. External operation ID is stored when safely available.

Executor IPC READY/RESULT binds Action/Attempt/Plan/Admission/Bundle/Realm/lease/pre-mutation permit digests. Executor receives credential through inherited locked memory/pipe exactly once, clears it, and has no DB/OIDC/Vault general client. WRITE Runner handles claim→start/admit→child create/anchor/activate→pre-mutation permit→one ExecuteOnce→complete→revocation.

Production config requires WRITE cert/key/root、Realm、Gateway、issuer profile and isolated executor path. Docker image runs non-root, read-only rootfs compatible, no shell/package manager and only the Gateway plus allowlisted provider egress.

- [ ] **Step 5: Run adapter, IPC, race and build tests**

Run:

```bash
go test ./internal/writeadapter/... ./internal/executoripc ./internal/isolatedexec ./cmd/executor ./cmd/write-runner -count=1
go test -race ./internal/writeadapter/... ./internal/executoripc ./internal/isolatedexec -count=1
go build ./cmd/write-runner ./cmd/executor
```

Expected: all PASS；each fixed step ordinal is sent at most once；GitOps can execute only its two-step graph；uncertain is UNKNOWN；dependency graph has no generic execution path.

- [ ] **Step 6: Commit**

```bash
git add internal/writeadapter internal/executoripc internal/isolatedexec cmd/executor cmd/write-runner build/package/write-runner/Dockerfile
git commit -m "feat: execute fixed governed write actions"
```
