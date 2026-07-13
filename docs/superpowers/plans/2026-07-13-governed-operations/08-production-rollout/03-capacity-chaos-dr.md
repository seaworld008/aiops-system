# Capacity, Load, Chaos, and Disaster Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the production assembly sustains the approved load envelope, fails closed under dependency loss, cleans up credentials after crashes, and restores governed state within the 99.9% availability, five-minute RPO, and thirty-minute RTO objectives.

**Architecture:** Use a production-equivalent isolated environment with the same chart, external-service topology and trust boundaries as production. Generate deterministic alert/investigation workloads, inject one bounded fault at a time, export signed machine-readable evidence, and require a fresh release gate for each material topology or capacity change. Restore tests rebuild into a clean environment instead of validating only that backup files exist.

**Tech Stack:** Go test harnesses, k6, Kubernetes Jobs, Chaos Mesh or the platform-approved equivalent, PostgreSQL PITR tooling, Temporal visibility/repair APIs, Vault/PKI operational APIs, object-storage immutability, Prometheus/VictoriaMetrics, and OpenTelemetry traces.

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- Baseline load is 1,000 alerts/minute for ten minutes with 20 concurrent investigations, inherited from the accepted architecture blueprint.
- Monthly control-plane availability objective is 99.9%; operational-state RPO is at most five minutes and service RTO is at most thirty minutes.
- Load generation uses synthetic tenants/assets and cannot target a production Asset, ConnectionProfile, credential reference or Action.
- Chaos experiments cannot run in production by default. A production game day requires its own approved immutable experiment plan, narrow namespace/targets, Kill Switch, abort conditions and incident commander.
- A failed dependency never causes fallback to ungoverned identity, cached stale authorization, arbitrary endpoint access, fake credential issuance or duplicate write.
- Recovery revalidates Asset, Runtime, policy, Kill Switch, Grant, Action and credential state before reopening claims.
- Evidence excludes request bodies, credentials, query text, model prompts, raw upstream responses and secret-bearing logs.

### Task 1: Establish the capacity model and repeatable load suite

**Files:**
- Create: `docs/operations/production/capacity-envelope.md`
- Create: `tests/load/k6/alert-intake.js`
- Create: `tests/load/k6/investigation-read.js`
- Create: `tests/load/k6/action-canary.js`
- Create: `tests/load/config/production-equivalent.json`
- Create: `tests/load/verify_summary_test.go`
- Create: `scripts/run-production-load.sh`
- Modify: `Makefile`

**Interfaces:**
- Consumes: production-equivalent API URL, test OIDC client, synthetic asset manifest, accepted read and canary Action fixtures
- Produces: bounded workload, percentile/error/queue/credential metrics, signed load evidence digest

- [ ] **Step 1: Write failing summary-verification tests**

Define a versioned result schema and tests that reject missing series, a shorter-than-ten-minute steady window, fewer than 10,000 alerts, fewer than 20 concurrent investigations, nonzero unauthorized/duplicate mutations, orphaned credentials, missing audit/outbox delivery, unbounded queue growth, and unknown threshold status.

```go
func TestVerifyLoadSummaryRejectsCredentialLeak(t *testing.T) {
    result := validLoadSummary()
    result.Credential.ActiveAfterGrace = 1

    err := VerifySummary(result, ApprovedEnvelope())
    require.ErrorContains(t, err, "credential cleanup")
}
```

Run:

```bash
go test ./tests/load -run TestVerifyLoadSummary -count=1
```

Expected: FAIL because the verifier and schema do not exist.

- [ ] **Step 2: Implement the approved capacity envelope**

`capacity-envelope.md` records:

- 1,000 alert events/minute sustained for ten minutes, including duplicates and out-of-order delivery.
- 20 concurrent governed investigations, each with up to 12 tool calls and at most three concurrent calls per source.
- Concurrent source-sync fixtures for every accepted adapter, including paginated inventory, duplicate/out-of-order pages and provider rate limiting；cursor lag must return below its accepted baseline after load stops.
- Production-write canary concurrency of one until a later separately approved capacity revision.
- 30% headroom after the steady-state run for Control Plane/Worker/Discovery Worker CPU, memory, PostgreSQL connections, Temporal task queues, source-run leases/cursors, Gateway streams and Runner leases.
- No sustained queue-age increase after the warm-up window; all queues return below the accepted baseline within five minutes after load stops.
- 100% audit/outbox delivery, 100% evidence citation presence, zero unauthorized claims, zero duplicate Action effect and zero active credential after the cleanup grace.
- Explicit per-component saturation signals and a scaling owner.

Do not silently change these values in a test script. A changed envelope updates this document, the release manifest and gate digest together.

- [ ] **Step 3: Implement k6 scenarios and a safe launcher**

Use synthetic IDs signed by a dedicated non-production issuer. The alert test includes a deterministic idempotency key and expected incident grouping. The read test waits for a terminal investigation and validates only schema/status. The Action test invokes a non-production idempotent fixture whose verifier can prove exactly one effect.

```javascript
export const options = {
  scenarios: {
    alert_intake: {
      executor: 'constant-arrival-rate',
      rate: 1000,
      timeUnit: '1m',
      duration: '10m',
      preAllocatedVUs: 50,
      maxVUs: 200,
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
    checks: ['rate>0.99'],
  },
};
```

`run-production-load.sh` must require `AIOPS_ENVIRONMENT=production-equivalent`, verify the cluster label and release digest, refuse a production hostname, create a run UUID, collect metrics/traces/log references, redact artifacts, call the Go verifier, sign the summary, and submit only its URI/digest through the release-evidence API.

- [ ] **Step 4: Run the suite and commit**

```bash
go test ./tests/load -count=1
AIOPS_ENVIRONMENT=production-equivalent bash scripts/run-production-load.sh
make check
git add docs/operations/production/capacity-envelope.md tests/load scripts/run-production-load.sh Makefile
git commit -m "test(capacity): prove the production load envelope"
```

Expected: verifier and repository checks pass; the run produces a signed `PASS` summary with no secret-bearing artifact.

### Task 2: Prove fail-closed dependency and process behavior

**Files:**
- Create: `tests/chaos/scenarios/control-plane-pod-loss.yaml`
- Create: `tests/chaos/scenarios/worker-pod-loss.yaml`
- Create: `tests/chaos/scenarios/postgres-failover.yaml`
- Create: `tests/chaos/scenarios/temporal-unavailable.yaml`
- Create: `tests/chaos/scenarios/keycloak-unavailable.yaml`
- Create: `tests/chaos/scenarios/vault-pki-unavailable.yaml`
- Create: `tests/chaos/scenarios/runner-network-partition.yaml`
- Create: `tests/chaos/scenarios/runner-crash-after-effect.yaml`
- Create: `tests/chaos/harness_test.go`
- Create: `tests/chaos/invariants_test.go`
- Create: `docs/operations/production/chaos-game-day.md`

**Interfaces:**
- Consumes: exact release digest, approved experiment manifest, production-equivalent cluster, telemetry and audit projections
- Produces: invariant results for availability, authorization, fencing, cleanup, reconciliation and recovery

- [ ] **Step 1: Write failing invariant tests**

The harness must observe and fail on:

- Claim succeeds after Grant/lease/approval/policy/Kill Switch becomes invalid.
- A WRITE retry occurs after an uncertain effect without reconciliation.
- More than one fencing token acts on the same target.
- Credential remains usable after Task terminal state or cleanup deadline.
- Control Plane accepts new privileged decisions while OIDC freshness cannot be established.
- Worker executes a stale task after PostgreSQL/Temporal recovery.
- Runner network partition leaks a raw upstream response or Secret.
- Audit/outbox terminal record is missing or contradictory.

Run:

```bash
go test ./tests/chaos -run 'TestInvariant|TestScenarioSchema' -count=1
```

Expected: FAIL until scenario schema and observers exist.

- [ ] **Step 2: Implement bounded experiment manifests**

Every manifest contains:

```yaml
apiVersion: aiops.seaworld.io/v1alpha1
kind: GovernedChaosExperiment
metadata:
  name: runner-crash-after-effect
spec:
  environment: production-equivalent
  releaseDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  maxDuration: 300s
  blastRadius:
    namespaces: ["aiops-chaos"]
    maxPods: 1
  preconditions:
    - killSwitchStateIs: NORMAL
    - noProductionTargets: true
  abortWhen:
    - unauthorizedClaimCountGreaterThan: 0
    - activeWriteCredentialAfterGraceGreaterThan: 0
    - duplicateActionEffectGreaterThan: 0
```

The launcher resolves the real digest, so the repository fixture uses a nondeployable digest. Experiments use labels and immutable UIDs, never fuzzy names. A cleanup handler runs on success, failure, cancellation and operator abort.

- [ ] **Step 3: Implement scenario-specific assertions**

For `runner-crash-after-effect`, use a non-production Action fixture that records its side effect atomically. Crash after the target effect but before Complete; assert the task enters `OUTCOME_UNCERTAIN`, the WRITE credential is revoked, no automatic retry occurs, reconciliation observes the exact effect, and only then does the workflow emit a verified Receipt or human escalation.

For dependency loss:

- PostgreSQL failover: no lost committed transition; stale transaction/fencing writes fail.
- Temporal loss: running activities heartbeat/timeout safely; no alternate local queue.
- Keycloak loss: existing low-risk reads may continue only until their already validated token/grant boundary; reauth and privileged decisions close.
- Vault/PKI loss: no new credential or certificate; active credential expiry still works; claim stops.
- Runner partition: lease/grant expires and cleanup is durable before a replacement claim.
- Pod loss: PDB/topology retains service within availability budget.
- Discovery Worker loss/rate-limit: stale owner cannot advance the cursor, the replacement resumes the last committed checkpoint once, no asset is falsely retired, and the affected source becomes `DEGRADED|RATE_LIMITED` rather than silently current.

- [ ] **Step 4: Run, capture, and commit chaos evidence support**

```bash
AIOPS_E2E_CLUSTER=production-equivalent go test ./tests/chaos -count=1 -timeout=45m
git diff --check
git add tests/chaos docs/operations/production/chaos-game-day.md
git commit -m "test(resilience): verify fail-closed dependency loss"
```

Expected: every scenario reaches a known terminal state and all security invariants pass.

### Task 3: Implement backup, point-in-time restore, and clean-room validation

**Files:**
- Create: `docs/operations/production/data-classification.md`
- Create: `docs/operations/production/backup-restore.md`
- Create: `scripts/backup/verify-postgres-backup.sh`
- Create: `scripts/backup/restore-clean-room.sh`
- Verify: `test/recovery/verify-rpo-rto.sh`
- Verify: `test/recovery/verify-cleanroom.sh`
- Verify: `test/recovery/run-all.sh`
- Create: `tests/recovery/postgres_restore_test.go`
- Create: `tests/recovery/cross_system_reconciliation_test.go`
- Create: `tests/recovery/fixtures/expected-invariants.json`

**Interfaces:**
- Consumes: encrypted PostgreSQL base backup/WAL, Temporal namespace backup policy, audit artifact store, external identity/credential-system recovery contracts
- Produces: clean-room restored control state, reconciled external state, measured RPO/RTO evidence

- [ ] **Step 1: Write failing restored-state invariants**

Tests assert the clean database has:

- All migrations through `000022` exactly once.
- Scope-safe Assets, Connections, Runtime publications and Grants.
- No nonexpired Grant restored as claimable; recovery marks them expired/revoked.
- No Action in `EXECUTING` restored as automatically retryable; it enters recovery reconciliation.
- All credential issuances have a terminal revocation/expiry projection or a blocking cleanup task.
- Append-only Evidence, Receipt, Audit, decision and release digests still verify.
- Outbox records reconcile without duplicate publication.
- Every previously active wave transitions to existing state `HELD` with typed `hold_reason=RECOVERY_REVALIDATION_REQUIRED`; the release remains an immutable candidate and admission stays closed until dependencies and gates revalidate.

Run:

```bash
go test ./tests/recovery -run 'TestRestoredState|TestCrossSystemReconciliation' -count=1
```

Expected: FAIL because recovery tooling and fixtures do not exist.

- [ ] **Step 2: Document data classes and recovery order**

Classify PostgreSQL operational records, audit/evidence artifacts, Temporal workflow history, Vault leases/roles, PKI issuers/certificates, Keycloak realm/client configuration and Helm release artifacts. For each, record source of truth, encryption, retention, backup owner, restore mechanism, RPO/RTO contribution and deletion/legal-hold policy.

The runbook order is fixed:

1. Declare incident and activate global or scoped Kill Switch.
2. Create an isolated clean recovery environment and verify artifact signatures.
3. Restore PostgreSQL base backup plus WAL to the selected point.
4. Restore/reconnect Temporal, Keycloak, Vault/PKI and artifact stores using their supported procedures.
5. run migrations and read-only integrity validation.
6. Revoke/expire restored Grants and credentials; reconcile in-flight read/write work.
7. Rebuild projections/outbox idempotently.
8. Revalidate runtime publications, policies, identities, trust and release gates.
9. Open Shadow, then READ_ONLY; production write stays held for an explicit decision.

- [ ] **Step 3: Implement safe scripts and clean-room test**

Scripts use `set -euo pipefail`, require a new empty destination, verify checksums/signatures/encryption metadata, refuse a production DSN as destination, write structured timestamps, and never echo connection strings or restore encryption keys. They orchestrate the Phase 6 backup/recovery APIs and call the already-owned `test/recovery/verify-rpo-rto.sh` and `test/recovery/verify-cleanroom.sh` contracts；they do not reimplement a second backup driver or restore state machine.

Run:

```bash
AIOPS_RECOVERY_ENV=clean-room bash scripts/backup/verify-postgres-backup.sh
AIOPS_RECOVERY_ENV=clean-room bash scripts/backup/restore-clean-room.sh
go test ./tests/recovery -count=1 -timeout=30m
```

Expected: restore completes with measured data loss no greater than five minutes and service recovery no greater than thirty minutes; every invariant passes before traffic is enabled.

- [ ] **Step 4: Commit recovery tooling**

```bash
git add docs/operations/production/data-classification.md docs/operations/production/backup-restore.md scripts/backup tests/recovery
git commit -m "feat(recovery): verify clean-room production restore"
```

### Task 4: Exercise zone loss and release recovery decision

**Files:**
- Create: `tests/recovery/zone_loss_test.go`
- Create: `tests/recovery/release_recovery_test.go`
- Create: `docs/operations/production/zone-and-region-recovery.md`
- Create: `docs/operations/production/recovery-evidence.schema.json`
- Modify: `internal/releasegovernance/gates.go`
- Modify: `internal/releasegovernance/gates_test.go`

**Interfaces:**
- Consumes: HA topology, clean-room recovery output, signed recovery summary
- Produces: `GateDisasterRecovery` evidence and an explicit reopen/hold decision

- [ ] **Step 1: Add failing recovery-gate tests**

Assert zone loss retains quorum and service, restored environments default to `HOLD`, old release decisions cannot be replayed, recovery evidence expires on material topology change, and write remains closed until a new independent decision.

Run:

```bash
go test ./tests/recovery ./internal/releasegovernance -run 'TestZoneLoss|TestRecoveryGate' -count=1
```

Expected: FAIL until the gate consumes recovery evidence.

- [ ] **Step 2: Implement the zone and recovery drill**

Drain or isolate one topology zone in the production-equivalent environment. Verify Control Plane/Worker/Runner PDB and spread, PostgreSQL/Temporal/Keycloak/Vault service contracts, queue continuity and availability budget. Then simulate a total primary-environment loss and execute the clean-room runbook in the designated recovery environment.

The evidence schema records start/end, last durable transaction timestamp, restore point, RPO/RTO, component versions/digests, unresolved work, credential cleanup, audit reconciliation, tested traffic modes and signers.

- [ ] **Step 3: Bind evidence to release gates**

`GateDisasterRecovery` passes only if signatures, environment identity, exact release/chart/schema digests, RPO/RTO, invariant results and freshness are valid. An unknown field, missing dependency drill or partial restore is `UNKNOWN` and blocks promotion.

Run:

```bash
AIOPS_E2E_CLUSTER=production-equivalent go test ./tests/recovery -run 'TestZoneLoss|TestTotalEnvironmentRecovery' -count=1 -timeout=60m
go test ./internal/releasegovernance -run TestRecoveryGate -count=1
```

Expected: PASS and a signed recovery artifact is accepted once for the exact release candidate.

- [ ] **Step 4: Commit DR gate**

```bash
git add tests/recovery docs/operations/production/zone-and-region-recovery.md docs/operations/production/recovery-evidence.schema.json internal/releasegovernance
git commit -m "feat(release): gate production on disaster recovery"
```
