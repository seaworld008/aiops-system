# Production Backup Recovery and DR Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为生产只读平台建立加密、不可变、可验证的 PostgreSQL/Temporal/Keycloak/Vault/evidence/audit 备份与 clean-room restore，实测 RPO `<=5m`、RTO `<=30m`，并以跨站 fence 防止灾备 split brain。

**Architecture:** 独立 backup identity 调用固定 driver 生成内容寻址 manifest；PostgreSQL/Temporal/Keycloak 数据通过 base backup + continuous WAL/PITR，Vault 使用加密 Raft snapshot，evidence/audit store 使用 versioning/Object Lock 与复制，chart/image/config 来自已签名 revision。备份写者无读取/恢复/删除权限，恢复者无生产写权限。离线 `platform-recovery` 在隔离 namespace 按固定状态机恢复并保持 Global/Environment Kill Switch 与生产 READ Admission 关闭；DR coordinator 必须取得外部 quorum fence 才能提升站点。

**Tech Stack:** PostgreSQL 18.4 continuous archiving/PITR、Vault Raft snapshot/PKI、S3 versioning/Object Lock、external KMS envelope encryption、Kubernetes VolumeSnapshot/Jobs、Go 1.26.5、pgx/v5、OpenTelemetry、sha256/JCS。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- RPO/RTO 只由真实带 marker 的 clean-room restore 计算，不以“备份命令成功”或配置推断。
- Backup manifest 只保存 source kind、platform revision、时间、LSN/version/snapshot/audit safe digest、加密 object reference；不保存数据、endpoint、bucket URL、credential、key ID path 或 PEM。
- Backup writer、verifier、restore operator、DR coordinator 使用四个独立 workload identities/Vault/KMS policies；writer 不能 read/delete/restore，restore 不能写生产源。
- Backup objects 使用 envelope encryption、versioning、retention lock、跨故障域复制和 digest；未知/未加密/可变 object 不进入 manifest。
- Base backup 至少每日一次；WAL/archive/audit/evidence replication lag 必须持续 `<=5m`，超过立即使 RPO gate FAIL。
- Vault/PKI snapshot、Keycloak/Temporal persistence 和 platform database 都必须在同一 recovery cut 或有明确 dependency ordering；不允许部分恢复后开放 admission。
- Clean-room 与 production 网络/identity/DNS/ServiceAccount 隔离；恢复期间没有目标 egress、Runner claim 或 human mutation API。
- Restore begins with admission closed and all Kill Switches closed；只有验证完成也仍不得自动切生产流量，需人工 DR decision。
- 恢复后全部 workload cert、Keycloak client secret（若存在 confidential backchannel）、DB/Vault session、READ credential accessor 都轮换；旧凭据撤销不确定则 NO_GO。
- Audit chain hash、Scope FK、migration revision、platform/runtime/policy/grant/receipt/evidence digest 必须验证；坏一条即失败。
- Split brain prevention uses external quorum/fencing generation independent from the failed primary database；both sites cannot be ACTIVE.
- Backup/restore/DR 是平台运维，不是 Agent capability/Action；不出现在 investigation Grant、Runner capability 或浏览器执行按钮中。
- 不使用 arbitrary shell/SQL/API payload；driver 和 recovery step 是固定类型化 registry。
- 恢复演练不能覆盖/删除生产备份或写生产 DNS；测试资源使用唯一前缀并 cleanup。
- 新增行为严格 TDD，每个 Task 独立 commit。

---

## Backup Scope and Fixed Cadence

| Source | Method | Maximum recovery-point lag | Retention | Verify |
|---|---|---:|---:|---|
| Platform PostgreSQL | daily base + continuous WAL | 5m | 35d | restore marker + FK/digest |
| Temporal persistence/visibility DB | base + WAL in dedicated database | 5m | 35d | workflow history/replay digest |
| Keycloak DB | base + WAL in dedicated database | 5m | 35d | realm/client/keys safe digest + login |
| Vault integrated storage/PKI | encrypted Raft snapshot every 5m | 5m | 35d | snapshot restore + seal/issuer health |
| Evidence/audit object store | versioning/Object Lock + cross-zone replication | 5m | policy retention | object/version/digest sample |
| Platform chart/image/config | signed Git/registry content digest | immediate | immutable release history | signature/digest |

### Task 1: Implement fixed backup drivers, manifests and least-privilege scheduling

**Files:**
- Create: `internal/platformbackup/model.go`
- Create: `internal/platformbackup/model_test.go`
- Create: `internal/platformbackup/registry.go`
- Create: `internal/platformbackup/registry_test.go`
- Create: `internal/platformbackup/orchestrator.go`
- Create: `internal/platformbackup/orchestrator_test.go`
- Create: `internal/platformbackup/postgres.go`
- Create: `internal/platformbackup/postgres_test.go`
- Create: `internal/platformbackup/vault.go`
- Create: `internal/platformbackup/vault_test.go`
- Create: `internal/platformbackup/objectstore.go`
- Create: `internal/platformbackup/objectstore_test.go`
- Create: `internal/platformbackup/postgres/repository.go`
- Create: `internal/platformbackup/postgres/repository_test.go`
- Create: `deploy/vault/policies/platform-backup.hcl`
- Create: `deploy/vault/policies/platform-backup_test.go`
- Create: `test/integration/backup/platform_backup_test.go`

**Interfaces:**
- Consumes: Platform revision, fixed source references, external KMS signer/encrypter, Phase 6 backup repository.
- Produces: immutable encrypted backup objects and safe `production_backup_manifests` rows.
- Safety: registry is closed; caller cannot provide command/path/SQL/bucket/key/retention override.

- [ ] **Step 1: Write failing manifest/driver/policy tests**

```go
func TestBackupRegistryContainsOnlyFixedPlatformSources(t *testing.T)
func TestBackupManifestBindsRecoveryCutObjectsAndPlatformRevision(t *testing.T)
func TestBackupManifestRejectsSecretEndpointPathAndMutableObjectReference(t *testing.T)
func TestPostgresDriverRequiresBaseBackupWALCoverageAndArchiveLagUnderFiveMinutes(t *testing.T)
func TestVaultDriverRequiresEncryptedRaftSnapshotAndPKIHealthDigest(t *testing.T)
func TestObjectStoreDriverRequiresVersioningLockReplicationAndDigest(t *testing.T)
func TestBackupWriterPolicyCannotReadDeleteRestoreOrDecrypt(t *testing.T)
func TestBackupScheduleIsIdempotentAndNeverOverlapsSameSource(t *testing.T)
```

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/platformbackup/... ./deploy/vault/policies -run 'Test(Backup|PostgresDriver|VaultDriver|ObjectStoreDriver)' -count=1
```

Expected: FAIL because backup registry/drivers/policies are absent.

- [ ] **Step 3: Implement typed backup contract**

```go
type SourceKind string

const (
    SourcePlatformPostgres SourceKind = "PLATFORM_POSTGRES"
    SourceTemporalPostgres SourceKind = "TEMPORAL_POSTGRES"
    SourceKeycloakPostgres SourceKind = "KEYCLOAK_POSTGRES"
    SourceVaultRaft        SourceKind = "VAULT_RAFT"
    SourceEvidenceStore    SourceKind = "EVIDENCE_STORE"
    SourceAuditStore       SourceKind = "AUDIT_STORE"
    SourceReleaseArtifacts SourceKind = "RELEASE_ARTIFACTS"
)

type ObjectProof struct {
    Kind             SourceKind
    ImmutableRef     string
    CiphertextDigest string
    PlaintextDigest  string
    RecoveryPoint    time.Time
    VerifiedAt       time.Time
}

type Manifest struct {
    Scope             assetcatalog.Scope
    ID                string
    PlatformID        string
    PlatformRevision  int64
    RecoveryCut       time.Time
    Objects           []ObjectProof
    KMSAttestationDigest string
    ManifestDigest    string
    Status            string
}
```

Canonicalize sorted objects and domain hash. `ImmutableRef` is opaque content reference, validated pattern only and redacted by String/Marshal public projection.

- [ ] **Step 4: Implement fixed drivers and orchestrator saga**

Each driver has `Prepare→Create→Verify→Finalize`; intent is durable before external call, request ID is manifest/source digest, replay reconciles by request ID. PostgreSQL waits for base/WAL archive verification; Vault takes Raft snapshot and verifies seal/PKI metadata digest; object store samples version/lock/replication. Partial source failure marks manifest FAILED and never advances current recovery cut.

- [ ] **Step 5: Schedule and monitor exact cadence**

Temporal Schedule IDs are content addressed by source/platform revision；Overlap SKIP, catch-up 5m, no browser override. A separate verifier identity reads ciphertext metadata/sample-decrypts into memory, checks digest and destroys plaintext. Backup writer never reads it.

- [ ] **Step 6: Run backup tests/integration**

```bash
go test -race ./internal/platformbackup/... ./deploy/vault/policies -count=1
go test -tags=integration ./test/integration/backup -run 'TestPlatformBackup' -count=1 -timeout=30m
```

Expected: PASS；recovery cut lag <=5m and least privilege enforced.

- [ ] **Step 7: Commit backup subsystem**

```bash
git add internal/platformbackup deploy/vault/policies/platform-backup.hcl deploy/vault/policies/platform-backup_test.go
git commit -m "feat(recovery): create immutable platform backups"
```

### Task 2: Build a fixed clean-room restore controller

**Files:**
- Create: `internal/platformrecovery/model.go`
- Create: `internal/platformrecovery/model_test.go`
- Create: `internal/platformrecovery/controller.go`
- Create: `internal/platformrecovery/controller_test.go`
- Create: `internal/platformrecovery/steps.go`
- Create: `internal/platformrecovery/steps_test.go`
- Create: `internal/platformrecovery/verifier.go`
- Create: `internal/platformrecovery/verifier_test.go`
- Create: `cmd/platform-recovery/main.go`
- Create: `cmd/platform-recovery/main_test.go`
- Create: `deploy/helm/aiops/templates/recovery-job.yaml`
- Create: `deploy/helm/aiops/templates/recovery-job_test.go`
- Create: `test/recovery/cleanroom/restore_test.go`

**Interfaces:**
- Consumes: one verified Manifest, clean-room cluster identity, restore-only KMS/Vault role and desired recovery point.
- Produces: fixed recovery state/evidence and `production_recovery_exercises` row.
- Safety: restore Job is disabled by default, cannot target production namespace/DNS and never opens admission.

- [ ] **Step 1: Write failing recovery state/order/safety tests**

```go
func TestRecoveryStateMachineHasFixedOrderedStepsAndNoCallerCommands(t *testing.T)
func TestRecoveryRejectsUnverifiedMutableCrossScopeOrFutureManifest(t *testing.T)
func TestRecoveryStartsAndEndsWithAdmissionAndKillSwitchClosed(t *testing.T)
func TestRecoveryRestoresVaultPostgresTemporalKeycloakEvidenceAuditInDependencyOrder(t *testing.T)
func TestRecoveryRotatesEveryIdentityAndRejectsUncertainRevocation(t *testing.T)
func TestRecoveryVerifierChecksMigrationsScopeDigestsAuditAndWorkflowReplay(t *testing.T)
func TestRecoveryJobCannotAddressProductionNamespaceOrExternalTargets(t *testing.T)
```

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/platformrecovery ./cmd/platform-recovery ./deploy/helm/aiops/templates -run 'TestRecovery' -count=1
```

Expected: FAIL because fixed recovery controller/job are absent.

- [ ] **Step 3: Implement exact state machine**

```go
type State string

const (
    StateRequested       State = "REQUESTED"
    StateFenced          State = "FENCED"
    StateManifestVerified State = "MANIFEST_VERIFIED"
    StateVaultRestored   State = "VAULT_RESTORED"
    StateDataRestored    State = "DATA_RESTORED"
    StateServicesStarted State = "SERVICES_STARTED"
    StateIdentityRotated State = "IDENTITY_ROTATED"
    StateVerified        State = "VERIFIED"
    StateCompleted       State = "COMPLETED"
    StateFailed          State = "FAILED"
)
```

Only fixed next transitions. CLI accepts `--config-fd` containing recovery exercise ID and manifest digest, not commands/paths/URLs. Repository resolves private objects by digest. Every external step uses idempotency token and records safe proof before next.

- [ ] **Step 4: Enforce clean-room verification**

Verify recovery marker after desired cut; migrations exactly `000015..000020`; FK/count/digest samples; platform/policy/runtime/Grant/Receipt/Evidence/audit chain；Temporal workflow replay；Keycloak real login；Vault seal/PKI health；all credentials/certs newly issued. Runner target egress and production DNS remain absent.

- [ ] **Step 5: Run controller and clean-room integration**

```bash
go test -race ./internal/platformrecovery ./cmd/platform-recovery ./deploy/helm/aiops/templates -count=1
go test -tags=e2e ./test/recovery/cleanroom -run 'TestCleanRoomRestore' -count=1 -timeout=45m
```

Expected: PASS；restored platform stays fenced and complete verification digest is persisted.

- [ ] **Step 6: Commit restore controller**

```bash
git add internal/platformrecovery cmd/platform-recovery deploy/helm/aiops/templates/recovery-job.yaml deploy/helm/aiops/templates/recovery-job_test.go
git commit -m "feat(recovery): restore platform in clean room"
```

### Task 3: Add DR fencing, site promotion and split-brain protection

**Files:**
- Create: `internal/platformdr/model.go`
- Create: `internal/platformdr/model_test.go`
- Create: `internal/platformdr/coordinator.go`
- Create: `internal/platformdr/coordinator_test.go`
- Create: `internal/platformdr/fence.go`
- Create: `internal/platformdr/fence_test.go`
- Create: `internal/platformdr/postgres/repository.go`
- Create: `internal/platformdr/postgres/repository_test.go`
- Create: `test/recovery/dr/failover_test.go`
- Create: `test/recovery/dr/split_brain_test.go`

**Interfaces:**
- Consumes: external quorum fence generation, verified restore exercise, platform/rollout revision, dependency readiness and authorized recent human DR decision.
- Produces: one ACTIVE site, fenced old generation and measured recovery evidence.
- Safety: database availability alone cannot promote；unknown old-site state is NO_GO until externally fenced.

- [ ] **Step 1: Write failing DR tests**

```go
func TestExactlyOneSiteCanHoldCurrentExternalFenceGeneration(t *testing.T)
func TestPromotionRequiresVerifiedRestoreIdentityRotationAndRecentHumanDecision(t *testing.T)
func TestOldSiteCannotServeClaimCompleteOrAuditAfterGenerationChange(t *testing.T)
func TestUnknownPrimaryStatePreventsAutomaticPromotion(t *testing.T)
func TestFailbackCreatesNewGenerationAndNeverReusesOldCredentials(t *testing.T)
func TestDRMeasuresRPOAndRTOFromDurableMarkers(t *testing.T)
```

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/platformdr/... ./test/recovery/dr -run 'Test(ExactlyOne|Promotion|OldSite|UnknownPrimary|Failback|DRMeasures)' -count=1
```

Expected: FAIL because DR coordinator/fence are absent.

- [ ] **Step 3: Implement external fence protocol**

```go
type FenceLease struct {
    DeploymentID   string
    SiteID         string
    Generation     int64
    HolderDigest   string
    IssuedAt       time.Time
    ExpiresAt      time.Time
    AttestationDigest string
}

type ExternalFence interface {
    Acquire(context.Context, string, string, int64) (FenceLease, error)
    Verify(context.Context, FenceLease) error
    Revoke(context.Context, FenceLease) error
}
```

Gateway/Control/Worker include fence generation in readiness, lease and audit. Generation never decreases；old certificate/DB lease/task completion fails after change. Promotion requires old lease revoked/expired with quorum attestation, restore VERIFIED and all dependencies ready.

- [ ] **Step 4: Execute failover/failback integration**

Simulate zone loss, full primary cluster loss and network partition. Measure last committed marker vs restored marker (RPO), incident declaration vs all safe readiness checks (RTO). Keep human traffic/READ admission closed until promotion; target writes remain absent. Failback repeats restore and creates another generation.

- [ ] **Step 5: Run DR tests**

```bash
go test -race ./internal/platformdr/... -count=1
go test -tags=e2e ./test/recovery/dr -count=1 -timeout=60m
```

Expected: PASS；one ACTIVE site, no old-fence effect, RPO/RTO measured.

- [ ] **Step 6: Commit DR fencing**

```bash
git add internal/platformdr test/recovery/dr
git commit -m "feat(recovery): fence production read disaster recovery"
```

### Task 4: Automate RPO/RTO exercises and backup/recovery gates

**Files:**
- Create: `test/recovery/verify-rpo-rto.sh`
- Create: `test/recovery/verify-corrupt-backup.sh`
- Create: `test/recovery/verify-lost-wal.sh`
- Create: `test/recovery/verify-kms-vault-outage.sh`
- Create: `test/recovery/verify-cleanroom.sh`
- Create: `test/recovery/run-all.sh`
- Create: `test/recovery/scripts_contract_test.go`
- Create: `internal/productionplatform/recovery_gate.go`
- Create: `internal/productionplatform/recovery_gate_test.go`
- Modify: `internal/productionplatform/gate_collector.go`
- Modify: `internal/productionplatform/gate_collector_test.go`

**Interfaces:**
- Consumes: backup manifests, recovery/DR exercise rows and measured markers.
- Produces: deterministic `BACKUP_RECENT_VALID` and `CLEAN_ROOM_RECOVERY_PROVEN` gate observations with PASS/FAIL/INCONCLUSIVE results.
- Safety: scripts use generated IDs/digests only, have EXIT cleanup and cannot print/receive secrets.

- [ ] **Step 1: Write failing script/gate tests**

```go
func TestRecoveryScriptsHaveCleanupTimeoutAndNoArbitraryInput(t *testing.T)
func TestRecoveryGateRequiresFreshSuccessfulCleanRoomAndDRExercises(t *testing.T)
func TestRecoveryGateFailsRPOOverFiveMinutesOrRTOOverThirtyMinutes(t *testing.T)
func TestRecoveryGateIsInconclusiveOnMissingMarkerDigestOrIdentityRotation(t *testing.T)
func TestCorruptMissingWALKMSAndVaultFailuresNeverProduceCompletedRestore(t *testing.T)
```

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./test/recovery ./internal/productionplatform -run 'Test(RecoveryScripts|RecoveryGate|Corrupt)' -count=1
```

Expected: FAIL because exercise automation/gate are absent.

- [ ] **Step 3: Implement fixed gate rules**

Gate PASS requires a clean-room restore and DR failover no older than 30 days, exact current platform revision, all verification/rotation flags, RPO `0..300s`, RTO `0..1800s`, evidence digest and zero split-brain/write side effect. Any breached measured value is FAIL；missing/stale data is INCONCLUSIVE.

- [ ] **Step 4: Run all positive and negative exercises**

```bash
./test/production/up.sh
./test/recovery/run-all.sh
go test -tags=e2e ./test/recovery/... -count=1 -timeout=120m
./test/production/down.sh
```

Expected: positive restore/failover meets RPO/RTO；corrupt/lost-WAL/KMS/Vault cases fail closed with no admission.

- [ ] **Step 5: Commit recovery gates**

```bash
git add test/recovery internal/productionplatform/recovery_gate.go internal/productionplatform/recovery_gate_test.go internal/productionplatform/gate_collector.go internal/productionplatform/gate_collector_test.go
git commit -m "test(recovery): prove platform RPO and RTO"
```

## Pack Completion Gate

```bash
go test -race ./internal/platformbackup/... ./internal/platformrecovery ./internal/platformdr/... ./internal/productionplatform -count=1
go test ./deploy/vault/policies ./deploy/helm/aiops/templates ./test/recovery -count=1
git diff --check
```

Expected: all commands exit 0；backup least privilege/immutability, clean-room verification, external fencing and measured RPO/RTO are complete.
