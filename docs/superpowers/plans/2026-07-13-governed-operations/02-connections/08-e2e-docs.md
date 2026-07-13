# Connection Production Assembly, E2E, and Documentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将 Connection 发布后端、独立 Validation Runner、OIDC 前端和滚动 Runtime 发布装配为真实可恢复的生产闭环，并用真实协议端到端测试、可访问性测试、运维文档和质量门完成验收。

**Architecture:** Control Plane、Gateway、Validation Runner 和 Runtime distributor 是独立生产进程；E2E 环境使用真实 PostgreSQL、Keycloak 测试 Realm、mTLS、Prometheus、VictoriaLogs 和构建产物，浏览器不加载 MSW；审计、指标、恢复和回滚都有可验证契约。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、Keycloak Server 26.6.3 测试 Realm、keycloak-js 26.2.4、mTLS、Prometheus、VictoriaLogs、Docker Compose、Playwright 1.61.1、@axe-core/playwright 4.12.1、pnpm 10.34.0。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- 本包验收的是生产闭环，不是 demo/read-only pilot；测试环境允许临时证书和测试账户，但运行的协议、二进制、数据库 migration、OIDC flow 与生产相同。
- Production constructors 缺 PostgreSQL、OIDC verifier、keyring、issuer、Realm registry、mTLS trust、distributor 中任何一项都启动失败；不得 fallback 到 memory、fake、MSW 或同进程 Runner。
- Validation Runner 与 Investigation Runner 使用独立 root、SPIFFE pool、Realm、listener、queue、credential issuer；E2E 必须证明交叉访问被拒绝。
- 所有恢复通过持久 Operation/lease/fencing/cleanup/publication phase；杀进程后由另一副本安全接管。
- 本阶段只发布只读 Connection/Capability Runtime，为后续受治理写执行提供不可变 Connection/Realm 基础；不得增加 write capability。
- Package 07 的 `/credential-references`、`/runner-realms`、安全 Capability binding 投影和真实 OIDC/API 浏览器用例是本包的强制输入；最终门不得只验 Connection 向导而遗漏治理库存。
- `docs/design/frontend/connections-runtime.md` 与 `docs/design/frontend/credential-references-runner-realms.md` 是唯一持久 UI 细节契约；本包只消费和检查，不复制第三份页面规范。
- 审计/指标/日志/trace/截图/Playwright artifact 禁止 Credential、token、DSN、PEM、Vault path 和 raw upstream body。
- 完整 Go 测试必须在不含用户 `.worktrees/` 的隔离 worktree 中运行；不得删除用户 worktree。

### Task 19: Wire production processes, configuration, audit, metrics and recovery

**Files:**
- Modify: `cmd/control-plane/main.go`
- Modify: `cmd/control-plane/main_test.go`
- Modify: `cmd/control-plane/runner_gateway.go`
- Modify: `cmd/control-plane/runner_gateway_test.go`
- Modify: `cmd/validation-runner/main.go`
- Modify: `cmd/validation-runner/main_test.go`
- Create: `build/package/validation-runner/Dockerfile`
- Create: `internal/connectionobservability/metrics.go`
- Create: `internal/connectionobservability/metrics_test.go`
- Create: `internal/connectionrecovery/reconciler.go`
- Create: `internal/connectionrecovery/reconciler_test.go`

**Interfaces:**
- Consumes: packages 01–07；existing config/OIDC/authz/audit/metrics conventions；Runtime distributor；package 07 production inventory readers and safe Web routes。
- Produces: fail-closed Control Plane and Validation Runner binaries；startup reconciliation；low-cardinality metrics and safe audit events。

- [ ] **Step 1: Write failing assembly and recovery tests**

```go
func TestControlPlaneRejectsMissingConnectionSecurityDependency(t *testing.T)
func TestPublicRouterDoesNotExposeValidationRunnerRoutes(t *testing.T)
func TestValidationRunnerRequiresDedicatedMTLSIdentity(t *testing.T)
func TestStartupReconcilerResumesExpiredValidationLease(t *testing.T)
func TestStartupReconcilerResumesPendingRuntimePublication(t *testing.T)
func TestConnectionMetricsHaveNoSensitiveOrHighCardinalityLabels(t *testing.T)
func TestConnectionAuditEventUsesSafeReferencesOnly(t *testing.T)
```

- [ ] **Step 2: Verify failure**

Run:

```bash
go test ./cmd/control-plane ./cmd/validation-runner ./internal/connectionobservability ./internal/connectionrecovery -count=1
```

Expected: FAIL because production assembly wiring, observability and recovery packages are not complete.

- [ ] **Step 3: Implement fail-closed process assembly**

Control Plane builds PostgreSQL repositories, authn/authz, Validation Capsule signer/keyring, Realm/credential/trust/network registries, public managers and internal Gateway handlers. Public HTTP and mTLS Gateway bind distinct addresses/listeners. `cmd/validation-runner` loads only Validation trust root, workload certificate/key, Realm, provider CA bundle and Gateway address; it has no Control Plane DB or general Credential Store access.

Production environment validation requires:

```text
AIOPS_POSTGRES_DSN
AIOPS_OIDC_ISSUER
AIOPS_OIDC_AUDIENCE
AIOPS_VALIDATION_SIGNING_KEY_FILE
AIOPS_VALIDATION_VERIFY_KEYRING_FILE
AIOPS_VALIDATION_GATEWAY_LISTEN
AIOPS_VALIDATION_CLIENT_CA_FILE
AIOPS_RUNTIME_DISTRIBUTOR_ENDPOINT
AIOPS_RUNTIME_DISTRIBUTOR_CA_FILE
```

Runner requires:

```text
AIOPS_VALIDATION_GATEWAY_URL
AIOPS_VALIDATION_RUNNER_CERT_FILE
AIOPS_VALIDATION_RUNNER_KEY_FILE
AIOPS_VALIDATION_GATEWAY_CA_FILE
AIOPS_VALIDATION_REALM_REFERENCE
```

Startup validates file permissions and certificate Pool/Realm claims before listening. Docker image runs non-root, read-only rootfs compatible, no shell/package manager, and exposes no public port.

- [ ] **Step 4: Implement recovery, audit and metrics**

Reconciler uses DB advisory ownership plus row leases to:

- expire stale claim/start attempts and make work claimable with incremented attempt/fencing;
- retry pending Credential revocation before any Validation terminal success;
- mark deadline-exceeded Operations `EXPIRED` with stable code;
- resume `PENDING/APPLYING` Runtime Publications or roll back `DRIFTED/FAILED`;
- never mutate immutable artifacts or in-flight bundle bindings.

Audit actions: `connection.created`, `revision.created`, `validation.started/completed`, `connection.published/revoked`, `runtime.applied/drifted/rolled_back`. Fields are actor, Scope, safe resource IDs/revisions, old/new status, request/operation/trace/audit IDs, change reason hash and artifact digests. No endpoint query, issuer path, credential fields or raw error.

Metrics cover validation claim/attempt/duration/result/cleanup, Operation age, publication rollout/rollback/drift and reconciler repairs. Labels use provider/status/reason class only.

- [ ] **Step 5: Run assembly, race and binary checks**

Run:

```bash
go test ./cmd/control-plane ./cmd/validation-runner ./internal/connectionobservability ./internal/connectionrecovery -count=1
go test -race ./internal/connectionrecovery ./internal/runtimepublication ./internal/connectionvalidation -count=1
go build ./cmd/control-plane ./cmd/validation-runner
```

Expected: PASS；missing dependency/startup identity fails；restart reconciliation is idempotent；public listener has no Runner routes.

- [ ] **Step 6: Commit**

```bash
git add cmd/control-plane cmd/validation-runner build/package/validation-runner internal/connectionobservability internal/connectionrecovery
git commit -m "feat: assemble production connection publication services"
```

### Task 20: Build real-protocol E2E and responsive accessibility coverage

**Files:**
- Modify: `test/e2e/docker-compose.connections.yaml`
- Modify: `test/e2e/connections/keycloak-realm.json`
- Modify: `test/e2e/connections/bootstrap.go`
- Modify: `test/e2e/connections/bootstrap_test.go`
- Modify: `web/playwright.config.ts`
- Modify: `web/e2e/support/fixtures.ts`
- Modify: `web/e2e/support/accessibility.ts`
- Create: `web/e2e/connections-publication.spec.ts`
- Create: `web/e2e/connections-security.spec.ts`
- Create: `web/e2e/connections-responsive.spec.ts`

**Interfaces:**
- Consumes: package 07 real PostgreSQL/Keycloak/Control Plane/Web compose base、bootstrap and governance-inventory specs；built Validation Runner；real Keycloak authorization-code + PKCE；TLS Prometheus/VictoriaLogs；Playwright browser。
- Produces: extended repeatable no-MSW production-path E2E suite covering Connection publication plus Credential References/Runner Realms and screenshot/axe evidence。

- [ ] **Step 1: Write failing full-closure bootstrap and browser extensions**

Extend the package 07 compose in place so it starts:

- PostgreSQL 18.4 with `000001..000016`;
- Keycloak test Realm with ephemeral ADMIN/SRE/AUDITOR users and authorization-code + PKCE client;
- two Control Plane replicas;
- dedicated mTLS Validation Gateway and two Validation Runner replicas;
- TLS Prometheus and VictoriaLogs instances containing deterministic health/query data;
- Runtime distributor fixture implementing the real attestation protocol;
- production Web build served with same-origin API routing.

`bootstrap.go` keeps the package 07 Credential Reference/Runner Realm/cross-Scope fixtures, then adds test CA/certs at runtime, registers exact VALIDATION workload identities/Realm/capability bindings, inserts Operational Asset records, and creates issuer-backed short credentials. Private material stays in temporary `0700` directory and is deleted after suite. Do not replace the already-real Keycloak/API inventory path with fixture interception.

- [ ] **Step 2: Verify E2E fails before implementation**

Run:

```bash
go test ./test/e2e/connections -count=1
corepack pnpm@10.34.0 --dir web test:e2e -- --project=chromium
```

Expected: FAIL because the base inventory stack does not yet contain the complete mTLS Validation/Runtime publication closure and connection publication specs.

- [ ] **Step 3: Implement real OIDC and publication scenarios**

Playwright authenticates through Keycloak UI; it does not inject bearer tokens or storage state from a fake endpoint. Test scenarios:

1. SRE can create a DRAFT and run validation but cannot publish;
2. ADMIN recent-auth publishes validated Prometheus Revision and observes `PENDING→APPLYING→APPLIED`;
3. VictoriaLogs fixed Probe succeeds and publishes exact Target/Capability digests;
4. wrong Realm identity and Investigation identity receive non-enumerating denial;
5. kill claimed Runner, wait lease expiry, second Runner resumes with higher fencing;
6. kill Control Plane/worker during publication, second replica resumes;
7. inject deployment digest drift, assert gate remains closed and last bundle is restored;
8. double-submit and browser reload return the same Operation;
9. stale ETag yields 412 safe comparison;
10. revoke Connection closes new use while existing investigation remains pinned to old bundle;
11. AUDITOR sees safe references/audit but no mutation;
12. browser network/DOM/console/artifacts contain no forbidden credential keys or values.

Package 07 `credential-references.spec.ts`、`runner-realms.spec.ts`、`governance-inventory-security.spec.ts` and `governance-inventory-responsive.spec.ts` run unchanged against this expanded stack. Add cross-slice assertions that a published Connection links to the same opaque Credential Reference and exact Realm binding digests shown by the inventory pages, while neither page reveals endpoint/credential/identity material or gains a binding/elevation control.

- [ ] **Step 4: Add axe, keyboard and viewport assertions**

Use viewports `1440×1000`, `1024×768` and `390×844`. At each size validate Connection list/detail/all six wizard steps plus Credential Reference and Runner Realm list/detail/binding flows. 390 px must complete publish/recent-auth and permitted reference-validation confirmation without horizontal page scroll.

`accessibility.ts` runs axe with WCAG 2.2 A/AA tags and fails serious/critical violations. Keyboard scenario covers skip link、navigation、filter、table selection、detail close/focus return、wizard stepper、dialog and Operation live region. Screenshots use deterministic timestamps/data and mask only ephemeral OIDC secrets; they may not mask layout defects.

- [ ] **Step 5: Run no-MSW E2E gates**

Run:

```bash
docker compose -f test/e2e/docker-compose.connections.yaml up -d --build
go test ./test/e2e/connections -count=1
corepack pnpm@10.34.0 --dir web test:e2e
corepack pnpm@10.34.0 --dir web test:a11y
node web/scripts/check-governance-inventory-artifacts.mjs
docker compose -f test/e2e/docker-compose.connections.yaml down -v
```

Expected: all PASS；Playwright asserts no MSW service worker/request interception；inventory Scope/cursor/effective-actions, takeover, cleanup, rollout/rollback, OIDC and three viewports succeed.

- [ ] **Step 6: Commit**

```bash
git add test/e2e web/playwright.config.ts web/e2e
git commit -m "test: verify connection publication production flow"
```

### Task 21: Persist architecture, operations and stage status; run the final gate

**Files:**
- Modify: `docs/architecture/overview.md`
- Modify: `docs/architecture/implementation-blueprint-v3.md`
- Modify: `docs/README.md`
- Create: `docs/adr/0002-connection-compilation-publication.md`
- Create: `docs/operations/connection-profile-publication.md`
- Create: `docs/operations/validation-runner.md`
- Create: `docs/operations/runtime-publication-rollback.md`
- Create: `docs/operations/connection-incident-response.md`
- Create: `docs/operations/governed-operations-stage-status.md`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: implemented contracts and observed test commands from packages 01–07。
- Produces: durable architecture/runbooks/status and CI gate；explicit handoff to later Grant/policy/write-governance phases。

- [ ] **Step 1: Write the documentation acceptance checklist first**

Each document must state:

- authoritative model and Scope;
- trust boundary and fail-closed behavior;
- immutable revision/digest relationships;
- the ADR decision that only validated, attested, immutable revisions compile into a published Runtime Bundle;
- normal create/validate/publish/rollout sequence;
- HA takeover, Credential cleanup and retry;
- safe observable signals and forbidden data;
- drift/rollback/revoke incident actions;
- exact verification commands;
- limitations: only Prometheus/VictoriaLogs read capabilities in this stage;
- UI contract references: `docs/design/frontend/connections-runtime.md` and `docs/design/frontend/credential-references-runner-realms.md`, including their drift-check commands and E2E evidence;
- handoff: Connection/Realm Runtime closure is the immutable base for later governed write execution, but write remains disabled here.

Do not claim readiness before the corresponding test output exists. Stage status records commit SHA, migration range, tested PostgreSQL/Node/pnpm versions, passed gates, open risks and rollback drill evidence.

- [ ] **Step 2: Update CI without weakening existing gates**

CI jobs:

1. Go unit/race/vet/build in checkout without nested user worktrees;
2. PostgreSQL migration/integration;
3. Web generate/typecheck/lint/unit/build;
4. both persistent frontend design-contract drift checks;
5. Connection plus Credential Reference/Runner Realm E2E with real Keycloak/mTLS/Runner and uploaded Playwright artifacts;
6. secret-pattern scan over API fixtures, browser artifacts and logs.

No job may set `continue-on-error` for connection gates. E2E secrets are ephemeral CI values, never committed.

- [ ] **Step 3: Run the complete backend gate in an isolated worktree**

Create a temporary clean worktree outside this repository root, then run:

```bash
test ! -d .worktrees
go test ./...
go test -race ./internal/connectionprofile/... ./internal/connectionvalidation/... ./internal/validationrunner/... ./internal/runtimepublication/... ./internal/httpapi/...
go vet ./...
go build ./cmd/control-plane ./cmd/validation-runner ./cmd/worker ./cmd/read-runner ./cmd/write-runner ./cmd/executor
```

Expected: all PASS. The `test ! -d .worktrees` assertion prevents the known architecture scanner false failure caused by user-owned nested worktrees.

- [ ] **Step 4: Run database, frontend and E2E gates**

Run:

```bash
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/store/postgres ./internal/connectionprofile/postgres ./internal/connectionvalidation/postgres ./internal/runtimepublication/postgres -count=1
corepack pnpm@10.34.0 --dir web generate:api:check
corepack pnpm@10.34.0 --dir web typecheck
corepack pnpm@10.34.0 --dir web lint
corepack pnpm@10.34.0 --dir web test
corepack pnpm@10.34.0 --dir web build
node web/scripts/check-connections-design-contract.mjs
node web/scripts/check-governance-inventory-design-contract.mjs
docker compose -f test/e2e/docker-compose.connections.yaml up -d --build
go test ./test/e2e/connections -count=1
corepack pnpm@10.34.0 --dir web test:e2e
corepack pnpm@10.34.0 --dir web test:a11y
node web/scripts/check-governance-inventory-artifacts.mjs
docker compose -f test/e2e/docker-compose.connections.yaml down -v
```

Expected: all PASS；generated contract and both persistent UI designs are drift-free；production build contains no MSW；real OIDC inventory Scope/cursor/effective-actions, mTLS validation, HA takeover, cleanup, Runtime rolling apply/rollback and accessibility pass.

- [ ] **Step 5: Perform the production-readiness review**

Record evidence that:

- zero open high/critical secret leaks, axe violations or race failures;
- Validation and Investigation cross-pool tests deny both directions;
- all nonterminal Operations recover after process termination;
- all issued validation credentials have REVOKED/NO_CREDENTIAL receipt;
- bundle drift closes gates and restores last attested bundle;
- audit chain links request/operation/revision/publication without sensitive fields;
- dashboards/alerts exist for stuck lease, cleanup failure, Operation age, rollout drift and rollback;
- rollback runbook was exercised against the E2E stack;
- write actions remain absent from capability registry and UI.
- Credential Reference inventory exposes no material retrieval/create/edit/revoke surface；Runner Realm inventory exposes no arbitrary binding/elevation/connect surface；both render actions only from current API `effective_actions`.
- Connection/Realm/Capability/Runtime digests shown across Connection and governance inventory pages match the same immutable publication closure.

- [ ] **Step 6: Commit**

```bash
git add docs/architecture docs/adr/0002-connection-compilation-publication.md docs/operations docs/README.md .github/workflows/ci.yml
git commit -m "docs: operationalize connection runtime publication"
```

## Execution Handoff

Execute packages 01–08 in README order. Within this package, use `superpowers:executing-plans` task by task and stop on any unexpected test failure. Do not mark `governed-operations-stage-status.md` ready until every command above—including both design drift checks and both governance inventory pages against the expanded real stack—has real PASS evidence.
