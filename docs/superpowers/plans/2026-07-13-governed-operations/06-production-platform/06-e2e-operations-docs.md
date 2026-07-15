# Production Read Platform E2E Operations and Documentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 用真实 HA PostgreSQL、Temporal、Keycloak Server 26.6.3、Vault/PKI、对象存储、监控和多副本应用/Runners 验证 Phase 6 全路径，完成真实阶段 soak、依赖/安全/恢复演练、企业控制台 E2E、运行手册、ADR 0009 与唯一生产只读 decision。

**Architecture:** 多节点 Kind reference stack 验证可重复机制，实际目标环境执行同一 image/chart/platform revision 和 pilot runner。测试通过真实 OIDC/mTLS/Vault dynamic credential/Temporal/Gateway/target 服务，不使用 fake/MSW/loopback dependency。所有演练生成 sanitized evidence digest 写入 `000020`，最后 Decision Service 只在全 gate PASS 与真实 soak 达标时接受三值之一；文档记录事实而非预设批准。

**Tech Stack:** Kubernetes 1.36.2/Kind、Helm 3、PostgreSQL 18.4 HA/PITR、Temporal、Keycloak Server 26.6.3、browser keycloak-js 26.2.4、Vault HA/PKI、S3-compatible Object Lock、Prometheus/Alertmanager/Grafana/OTel、Go 1.26.5、pnpm 10.34.0、Playwright 1.61.1、axe-core 4.12.1、k6、CI artifact signing/scanning。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- Reference E2E uses production binaries/chart/config validation and real dependencies；fake、memory、MSW、Temporal testsuite、httptest upstream cannot satisfy acceptance.
- `deploy/images.lock` pins image name/version/sha256 for every dependency/application；no `latest` or mutable tag-only deployment.
- Local host access may terminate at a test TLS ingress, but production components themselves cannot be configured to loopback/plaintext/development endpoints.
- Real Keycloak login/reauth/logout, Vault Kubernetes auth/CSR PKI, Runner mTLS and READ credential issue/revoke must occur in E2E.
- E2E includes real Victoria Metrics/Logs/Traces, Host Probe/AWX fixture and PostgreSQL target；seeding is isolated and removed before READ tests.
- Production stack contains at least required replicas, topology labels, PDB/HPA/default-deny NetworkPolicy and distinct ServiceAccounts/Realms.
- Every failure path scans DB、Temporal History、Vault audit metadata、app/dependency logs、traces、metrics、API/HAR、object metadata/evidence、screenshots/reports for canaries.
- Scripts use `set -euo pipefail`, bounded timeouts and EXIT cleanup；failure does not leave credentials、cluster、volumes、DNS or admission open.
- CI may use deterministic/accelerated clocks to verify state-machine mechanics, but cannot substitute for 24h/72h real soak evidence used by final decision.
- Actual pilot sequence is fixed and may span multiple executions/days；evidence collector resumes by immutable rollout revision and cannot backfill fabricated timestamps/counts.
- A failed/inconclusive gate results in NO_GO or CONTINUE_SHADOW, never manual override/SQL edit/alert silence.
- Documentation cannot claim approved production READ until the decision row, evidence-set digest and actual commands exist.
- Final approval is Phase 7 input；WRITE claim/credential/Runner/Action remains unavailable and deployment absent.
- ADR fixed path `docs/adr/0009-production-read-platform.md`；do not reuse another number.
- Frontend E2E uses the packaged Control Plane image through the test TLS ingress and real Keycloak；it never starts Vite、`vite preview` or an ad-hoc `web/dist` server. Route interception permits only observation/security assertions, never response mocking.
- Rolling verification keeps N and N-1 browser/API contracts compatible. If a stale browser cannot load a hashed chunk, it must disable high-risk mutations, show a persistent safe-reload prompt and never automatically replay a mutation.
- CI Phase 6 jobs cannot use `continue-on-error` or skip because Docker/Kubernetes is absent on required runner.
- 新增行为严格 TDD，每个 Task 独立 commit。

---

### Task 1: Complete the reusable multi-node production reference stack

**Files:**
- Modify: `test/production/kind-ha.yaml`
- Modify: `test/production/images.lock`
- Modify: `test/production/up.sh`
- Modify: `test/production/down.sh`
- Modify: `test/production/wait-ready.sh`
- Modify: `test/production/verify-all.sh`
- Modify: `test/production/manifests/namespaces.yaml`
- Modify: `test/production/manifests/postgresql-ha.yaml`
- Modify: `test/production/manifests/temporal.yaml`
- Modify: `test/production/manifests/keycloak.yaml`
- Modify: `test/production/manifests/vault-ha.yaml`
- Modify: `test/production/manifests/object-store.yaml`
- Modify: `test/production/manifests/observability.yaml`
- Modify: `test/production/manifests/test-targets.yaml`
- Modify: `test/production/manifests/networking.yaml`
- Modify: `test/production/bootstrap-keycloak.sh`
- Modify: `test/production/bootstrap-vault.sh`
- Modify: `test/production/stack_contract_test.go`
- Modify: `test/production/control_plane_image_contract_test.go`

**Interfaces:**
- Consumes: locked images, Phase 6 Helm chart, migrations 000001..000020 and test-only target seed manifests.
- Produces: TLS DNS endpoints and `.state/reference.json` containing only safe IDs/digests/CA paths for E2E clients.
- Safety: bootstrap credentials are ephemeral files mode 0600, never output/env, revoked and removed after setup.

- [ ] **Step 1: Write failing stack contract tests**

```go
func TestProductionStackPinsEveryImageByDigest(t *testing.T)
func TestProductionStackHasThreeZonesAndRequiredReplicaPDBHPA(t *testing.T)
func TestProductionStackUsesRealPostgresTemporalKeycloakVaultAndObjectStore(t *testing.T)
func TestProductionStackHasDistinctServiceAccountsAndDefaultDeny(t *testing.T)
func TestProductionStackContainsNoFakeMemoryMSWLoopbackDevModeOrUnauthorizedWriteWorkload(t *testing.T)
func TestProductionStackUsesSinglePackagedControlPlaneWebAPIImage(t *testing.T)
func TestControlPlaneImageContainsNoNodePnpmMSWServiceWorkerOrSourceMap(t *testing.T)
func TestProductionScriptsHaveTimeoutCleanupAndSensitiveOutputGuards(t *testing.T)
func TestProductionStackAndDeployImageLocksMatch(t *testing.T)
```

- [ ] **Step 2: Run stack tests and verify failure**

```bash
go test ./test/production -run 'Test(Production|ControlPlaneImage)' -count=1
```

Expected: FAIL because the Pack 01 foundation does not yet include every final E2E fixture, bootstrap revocation assertion and full-stack readiness check.

- [ ] **Step 3: Extend the deterministic stack setup for final E2E**

`up.sh` verifies Docker/Kind/kubectl/Helm/Go/Node24/pnpm10 and lock digests；builds/loads the Phase 6 multi-stage Control Plane image whose application payload consists of the Go binary and `/opt/aiops/web` assets；creates one control-plane + three zone-labeled workers；installs real HA PostgreSQL with WAL archive, Temporal persistence/visibility, Keycloak Server 26.6.3 production TLS, Vault 3-node Raft auto-unseal test KMS/PKI, versioned locked object store, OTel/Prometheus/Alertmanager/Grafana；then applies test targets and Phase 6 chart with required replicas. Node/pnpm are host build/test prerequisites only and never exist in the deployed image.

Bootstrap creates Keycloak realm/users/client/MFA fixture and removes admin bootstrap values；configures Vault Kubernetes auth, exact roles/policies/PKI, then revokes bootstrap token. Seed jobs write deterministic Metrics/Logs/Traces/PostgreSQL/Host fixture data from a separate namespace and terminate before READ Realm policies activate.

- [ ] **Step 4: Implement readiness and safe state output**

Wait for database replication/WAL archive, Temporal namespace/task queue, Keycloak OIDC discovery/login, Vault seal/PKI, object lock, monitoring scrape, migrations, platform revision APPLIED and all application replica readiness. Control Plane readiness additionally verifies its packaged `/opt/aiops/web` index/asset manifest and public `/api/v1/browser-config`; TLS ingress routes the same origin to the single Control Plane Service. `.state/reference.json` has public TLS host aliases, Scope/Platform IDs/digests and test user alias；password/token/cookie/DSN/Vault path excluded.

- [ ] **Step 5: Bring stack up/down and inspect**

```bash
./test/production/up.sh
kubectl get pods,pdb,hpa,networkpolicy --all-namespaces
./test/production/verify-all.sh --stack-only
./test/production/down.sh
```

Expected: all dependencies/replicas ready, the Phase 6 chart matches its empty accepted Action manifest and cleanup leaves no cluster/volume/temp credential. On later successors, the same contract permits only manifest-registered WRITE workloads.

- [ ] **Step 6: Commit final reference-stack extensions**

```bash
git add test/production
git commit -m "test(platform): complete real production reference stack"
```

### Task 2: Execute backend lifecycle, HA, security, recovery and staged-rollout E2E

**Files:**
- Create: `test/e2e/production/read_path_test.go`
- Create: `test/e2e/production/triggers_test.go`
- Create: `test/e2e/production/ha_test.go`
- Create: `test/e2e/production/dependencies_test.go`
- Create: `test/e2e/production/security_test.go`
- Create: `test/e2e/production/cleanup_test.go`
- Create: `test/e2e/production/recovery_test.go`
- Create: `test/e2e/production/rollout_test.go`
- Create: `test/e2e/production/write_closure_test.go`
- Create: `test/e2e/production/artifact_scan_test.go`
- Create: `test/e2e/production/fixtures.go`

**Interfaces:**
- Consumes: real reference stack and only public human API/Runner protocols/operations scripts.
- Produces: full lifecycle and negative evidence digests.
- Safety: direct database/dependency access is assertion/read-only setup only；system actions flow through production boundaries.

- [ ] **Step 1: Write failing full-path test inventory**

```go
func TestProductionHumanEventAndScheduleReadPathE2E(t *testing.T)
func TestProductionEveryVictoriaHostAndPostgresCapabilityE2E(t *testing.T)
func TestProductionThreeReplicaTakeoverAndRollingUpgradeE2E(t *testing.T)
func TestProductionEveryDependencyFailureFailsAsContractedE2E(t *testing.T)
func TestProductionRunnerCrashAndCredentialCleanupE2E(t *testing.T)
func TestProductionSixLevelKillSwitchE2E(t *testing.T)
func TestProductionDLPIdentityNetworkAndAuditIsolationE2E(t *testing.T)
func TestProductionCleanRoomRestoreAndDRFenceE2E(t *testing.T)
func TestProductionFourStagesCannotSkipAndShadowHasZeroSideEffectsE2E(t *testing.T)
func TestProductionWriteSurfacesMatchAcceptedManifestE2E(t *testing.T)
func TestProductionArtifactsContainNoSensitiveCanaryE2E(t *testing.T)
```

- [ ] **Step 2: Run tests and verify missing scenarios fail**

```bash
go test ./test/e2e/production -run 'TestProduction' -count=1
```

Expected: FAIL because production E2E suite is absent.

- [ ] **Step 3: Implement positive lifecycle assertions**

Authenticate via real Keycloak；run every accepted source adapter through the real multi-replica Discovery Worker with cursor/fence/rate-limit/soft-delete proof；discover/publish exact assets/connections/runtime；Preview policy；trigger manual/incident/schedule；issue fresh Snapshot/Grant；execute through mTLS Gateway/READ Runner；enforce budget/schema/DLP；persist Evidence/Receipt/Audit and terminal credential cleanup. Cover all 18 Victoria capabilities, Host/AWX fixed capabilities and six PostgreSQL queries that are available in fixture.

- [ ] **Step 4: Implement HA/failure/security/recovery assertions**

Kill each lease holder, partition dependencies one at a time, rotate identity, drift runtime/network, close each Kill Switch, inject DLP canaries, corrupt backup/lost WAL, clean-room restore, DR promote/failback and N→N+1 rollout. Query domain facts after recovery to prove one terminal effect/current fence. Force unregistered WRITE claims/API/credentials/network and assert denial/zero request；the Phase 6 fixture also proves the empty manifest denies every WRITE attempt.

- [ ] **Step 5: Implement accelerated stage mechanics tests**

Use test-only signed clock/source in the reference environment to prove min duration/count/busy-window checks cannot be bypassed and transitions cannot skip. This marks only `MECHANICS_VERIFIED`, never actual soak gate PASS. Shadow request counters for Task/credential/private Target/network remain exact zero.

- [ ] **Step 6: Run full backend E2E**

```bash
./test/production/up.sh
go test -tags=e2e ./test/e2e/production -count=1 -timeout=120m
./test/production/verify-all.sh --backend
./test/production/down.sh
```

Expected: PASS；real dependencies/Runners, HA/failure/recovery/security/stage mechanics verified, no canary/write availability.

- [ ] **Step 7: Commit backend E2E**

```bash
git add test/e2e/production
git commit -m "test(platform): verify production read lifecycle"
```

### Task 3: Verify the enterprise console with real Keycloak and production APIs

**Files:**
- Modify: `web/playwright.config.ts`
- Create: `web/e2e/platform/readiness.spec.ts`
- Create: `web/e2e/platform/dependencies.spec.ts`
- Create: `web/e2e/platform/realms-runtime.spec.ts`
- Create: `web/e2e/platform/slo.spec.ts`
- Create: `web/e2e/platform/rollout.spec.ts`
- Create: `web/e2e/platform/decision.spec.ts`
- Create: `web/e2e/platform/security.spec.ts`
- Create: `web/e2e/platform/accessibility.spec.ts`
- Create: `web/e2e/platform/visual.spec.ts`
- Create: `web/e2e/platform/fixtures.ts`

**Interfaces:**
- Consumes: immutable packaged Control Plane Web/API image, its exact OpenAPI/Web bundle digests, real Keycloak Server 26.6.3/browser keycloak-js 26.2.4 and TLS-ingress Control Plane origin.
- Produces: real auth/session/permissions/workflow/viewport/a11y/network-leak evidence.
- Safety: no API mocking/service-worker interception；HAR/trace/screenshots scanned before artifact upload.

- [ ] **Step 1: Write failing browser scenarios**

```ts
test('authenticates and recently reauthenticates through real Keycloak Server 26.6.3')
test('keeps tokens out of browser persistence and application cookies')
test('shows production write closed on every platform page')
test('navigates readiness dependencies realms runtime SLO and rollout deep links')
test('renders failure stale unknown and inconclusive as distinct states')
test('offers only server effective actions and exact three legal decisions')
test('cannot skip stages or approve when one gate is not pass')
test('requires typed confirmation and recent authentication for decision')
test('keeps N and N-1 browser clients compatible with the rolling API')
test('blocks high-risk mutation and requests safe reload after chunk load failure without replay')
test('restores URL state and keyboard focus at 1440 1024 and 390')
test('has no serious axe violations or sensitive network console DOM artifact')
```

- [ ] **Step 2: Run tests and verify failure**

```bash
pnpm --dir web test:e2e -- --grep 'production readiness|production read platform'
```

Expected: FAIL because real platform browser specs are absent.

- [ ] **Step 3: Configure real production build/auth tests**

Build the multi-stage Control Plane image once, load/deploy that exact digest through the Phase 6 Helm chart, and navigate its TLS-ingress origin；do not separately serve `web/dist`. Perform Keycloak login/reauth/logout with ephemeral test users and verify `/api/v1/browser-config` is closed、public-only and `no-store`. Reject any MSW/service worker、source map、unknown origin、separate Web/BFF endpoint, or Runner/Temporal/Vault/target request from browser. Capture network/console/storage/cookies and assert token/private fields absent.

- [ ] **Step 4: Implement workflow, responsive, visual and axe assertions**

Exercise all routes, URL state, stage timeline/gates, dependency failure, SLO burn, cleanup uncertain, Realm drift, Shadow zero side effect and legal decision state. During a rolling N→N+1 upgrade, keep an N browser session active and prove both N and N-1 API contracts remain accepted. Force a stale hashed-chunk load failure and prove all high-risk mutation controls become disabled, a persistent safe-reload prompt appears, and no mutation request is sent or replayed. Visual baselines cover normal/failure/inconclusive/read-only-approved at desktop/tablet/mobile；mask only timestamps/opaque IDs, never safety/gate status.

- [ ] **Step 5: Run real browser E2E**

```bash
./test/production/up.sh
pnpm --dir web generate:api:check
pnpm --dir web test:e2e -- --grep 'production readiness|production read platform'
pnpm --dir web test:a11y -- --grep 'production readiness|production read platform'
go test ./test/e2e/production -run 'TestProductionArtifactsContainNoSensitiveCanaryE2E' -count=1
./test/production/down.sh
```

Expected: PASS；the browser uses the packaged same-origin Control Plane image through TLS ingress, real Keycloak, no separate Web server/MSW/token leak, N/N-1 compatibility holds, chunk failure fails safe, and all viewports/keyboard/axe/visual are stable.

- [ ] **Step 6: Commit browser E2E**

```bash
git add web/playwright.config.ts web/e2e/platform
git commit -m "test(web): verify production read console"
```

### Task 4: Run actual pilot, persist operations/ADR/status and enforce CI

**Files:**
- Create: `test/production/pilot/start-preview.sh`
- Create: `test/production/pilot/start-nonproduction-readonly.sh`
- Create: `test/production/pilot/start-production-shadow.sh`
- Create: `test/production/pilot/start-supervised-readonly.sh`
- Create: `test/production/pilot/collect-gates.sh`
- Create: `test/production/pilot/decide.sh`
- Create: `test/production/pilot/pilot_contract_test.go`
- Create: `docs/adr/0009-production-read-platform.md`
- Create: `docs/operations/production-read/deployment-and-upgrade.md`
- Create: `docs/operations/production-read/dependency-failure.md`
- Create: `docs/operations/production-read/slo-error-budget.md`
- Create: `docs/operations/production-read/runner-and-credential-recovery.md`
- Create: `docs/operations/production-read/identity-network-dlp-incident.md`
- Create: `docs/operations/production-read/backup-restore-dr.md`
- Create: `docs/operations/production-read/kill-switch.md`
- Create: `docs/operations/production-read/shadow-readonly-go-no-go.md`
- Create: `docs/status/production-readiness.md`
- Modify: `docs/status/current.md`
- Modify: `docs/architecture/implementation-blueprint-v4.md`
- Modify: `docs/architecture/overview.md`
- Modify: `docs/README.md`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: actual deployed Platform/Rollout revisions, real elapsed pilot samples, gate collector and Decision API.
- Produces: exercised runbooks, ADR 0009, truthful status, CI gates and one allowed decision record.
- Safety: pilot scripts cannot forge gates/clock/counts, skip stages or accept decision outside enum.

- [ ] **Step 1: Write failing pilot/document/CI contract tests**

```go
func TestPilotScriptsEnforceExactOrderMinimumElapsedTimeAndSamples(t *testing.T)
func TestPilotDecisionAcceptsOnlyThreeValuesAndUsesDecisionAPI(t *testing.T)
func TestProductionReadADRPreservesWriteClosureAndPhaseSevenHandoff(t *testing.T)
func TestEveryCriticalAlertHasAnExercisedRunbook(t *testing.T)
func TestStageStatusCannotClaimApprovalWithoutMatchingDecisionDigest(t *testing.T)
func TestCIHasMandatoryUnitRaceMigrationChartRealE2ESecurityRecoveryJobs(t *testing.T)
```

- [ ] **Step 2: Run contract tests and verify failure**

```bash
go test ./test/production/pilot ./docs/... -run 'Test(Pilot|ProductionReadADR|EveryCritical|StageStatus|CIHas)' -count=1
```

Expected: FAIL because pilot/docs/CI contract are absent.

- [ ] **Step 3: Implement resumable actual-pilot scripts**

Scripts accept only Scope ID, rollout ID and expected digest through safe files；authenticate with operator OIDC, use API commands, poll immutable server time/count/gates and exit while soak is still running. They never set status/evidence directly. Execute in order:

```bash
./test/production/pilot/start-preview.sh
./test/production/pilot/start-nonproduction-readonly.sh
./test/production/pilot/start-production-shadow.sh
./test/production/pilot/start-supervised-readonly.sh
./test/production/pilot/collect-gates.sh
./test/production/pilot/decide.sh NO_GO
```

The displayed `NO_GO` is the safe command example, not a predetermined outcome. At decision time an authorized operator chooses exactly one allowed value based on gate output；if any gate is not PASS, the script only permits `NO_GO` or, at Shadow stage, `CONTINUE_SHADOW`.

- [ ] **Step 4: Write and exercise normative operations documents**

Every runbook contains owner/trigger/impact/safe signals、decision tree、containment、fixed commands、verification、recovery、rollback/escalation and last drill evidence. ADR `0009` records real process split, PostgreSQL/Temporal truth boundary, 99.9/RPO/RTO, Keycloak/Vault identity, Helm ownership Phase6→7→8, stage gates, decision enum, write closure and rejected alternatives. It fixes the Phase 7 handoff invariant: only `APPROVE_PRODUCTION_READ_ONLY` atomically persists non-null server-generated `handoff_id`/canonical `handoff_digest` in the immutable decision row；the handoff grants no WRITE authority and Phase 7 must reference its full composite Scope/rollout/decision tuple.

`production-readiness.md` records commit/chart/image/platform/rollout/evidence/decision digests, exact dependency versions, test/drill/soak timestamps, SLO/error budget, RPO/RTO, known risks and chosen allowed decision. `current.md` links it and never says program complete.

- [ ] **Step 5: Add mandatory CI**

Jobs: Go unit/race/vet/build；000020 real PostgreSQL；single packaged Control Plane Web/API image build and filesystem contract；Helm render/schema/write-absence；frontend generate/check/unit/build；real dependency/backend E2E；TLS-ingress real Keycloak browser/axe/visual including N/N-1 and chunk-failure safety；network/identity/DLP/write closure；load/HA/dependency chaos；backup/clean-room/DR smoke；sensitive artifact scan. No `continue-on-error` or required-job skip.

- [ ] **Step 6: Run complete final verification**

```bash
go test -race -shuffle=on -count=1 ./...
go vet ./...
go build ./cmd/...
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/store/postgres ./internal/productionplatform/postgres -count=1
pnpm --dir web generate:api:check
pnpm --dir web check
helm lint deploy/helm/aiops
./test/production/up.sh
go test -tags=e2e ./test/e2e/production -count=1 -timeout=120m
pnpm --dir web test:e2e -- --grep 'production readiness|production read platform'
./test/production/verify-all.sh
./test/production/down.sh
git diff --check
```

Expected: all commands exit 0；actual pilot evidence may still be soaking, in which case status/decision remains not approved rather than falsified.

- [ ] **Step 7: Persist the actual allowed decision and commit docs/CI**

After real soak and all gates, call `decide.sh` with exactly one allowed decision, verify returned decision/evidence digest, update status to match and commit:

```bash
git add test/production/pilot docs/adr/0009-production-read-platform.md docs/operations/production-read docs/status docs/architecture docs/README.md .github/workflows/ci.yml
git commit -m "docs(platform): accept production read decision"
```

Expected: decision is `NO_GO`, `CONTINUE_SHADOW`, or `APPROVE_PRODUCTION_READ_ONLY`；WRITE remains closed and status names Phase 7 as next gate.

## Final Acceptance Gate

```bash
go test ./internal/productionassembly ./internal/productionplatform/... ./internal/productionrollout/... -count=1
set -o pipefail
go test -json ./test/security/production ./deploy/helm/aiops ./test/production ./test/e2e/production \
  -run '^(TestProductionWriteSurfacesMatchAcceptedManifestAndDenyEverythingElse|TestRenderedChartMatchesAcceptedActionManifestAndReadBaseline|TestProductionWriteSurfacesMatchAcceptedManifestE2E|TestProductionStackContainsNoFakeMemoryMSWLoopbackDevModeOrUnauthorizedWriteWorkload)$' \
  -count=1 | tee /tmp/phase6-write-closure.json
test "$(rg -c '"Action":"pass".*"Test":"Test(ProductionWriteSurfacesMatchAcceptedManifestAndDenyEverythingElse|RenderedChartMatchesAcceptedActionManifestAndReadBaseline|ProductionWriteSurfacesMatchAcceptedManifestE2E|ProductionStackContainsNoFakeMemoryMSWLoopbackDevModeOrUnauthorizedWriteWorkload)"' /tmp/phase6-write-closure.json)" -eq 4
pnpm --dir web generate:api:check
pnpm --dir web check
go test ./test/production -run TestProductionStackContainsNoFakeMemoryMSWLoopbackDevModeOrUnauthorizedWriteWorkload -count=1
go test ./test/production -run 'Test(ProductionStackUsesSinglePackagedControlPlaneWebAPIImage|ControlPlaneImageContainsNoNodePnpmMSWServiceWorkerOrSourceMap)' -count=1
test -f docs/adr/0009-production-read-platform.md
git diff --check
```

Expected: all positive checks exit 0, rendered WRITE scan has no match, one truthful allowed decision exists and Phase 7 receives accepted read evidence without any write availability.
