# Host and PostgreSQL Diagnostics E2E, Operations, and Durable Documentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 用真实 Host Probe、AWX、Vault、PostgreSQL、Runner Gateway 与浏览器验收第五阶段，覆盖完整负向安全矩阵、可访问性、SLO、cleanup/灾难恢复，并把架构决策、前端细节和当前状态持久化为后续开发唯一依据。

**Architecture:** CI 以显式配置的真实依赖运行后端集成和单次 Governed Read E2E；Playwright 从公共 API 验证 UI，不绕过后端。OpenTelemetry 指标和 immutable audit chain 提供运行证据；运行手册按 issuance/execution/DLP/cleanup 故障域拆分。四份 ADR 精确承接远程诊断、命名 SQL、READ/WRITE 凭据隔离和 Evidence/DLP 决策。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、Vault、AWX、TLS 1.3 Host Probe fixture、Temporal、Keycloak Server 26.6.3、浏览器 `keycloak-js` 26.2.4、OpenTelemetry/Prometheus、GitHub Actions、pnpm 10.34.0、Playwright 1.61.1、@axe-core/playwright 4.12.1、Markdown link/contract tests。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- 真实集成依赖必须显式配置；缺失时诊断性本地调用可报告 Skip 原因，但对应 Task checkbox 必须保持未完成且不得提交。CI production gate 必须把依赖缺失或 required-test Skip 视为失败，不能用 fake 替代后宣称通过。
- E2E 必须经 OIDC/Control Plane/Grant/Gateway/Runner/Target/Evidence/cleanup 全链，不得直接调用 executor 或写数据库制造成功。
- 至少在一个调查中执行 Metrics、Logs、Traces、Host、PostgreSQL 各一个固定 READ 能力，证明 Phase 1–5 组合闭环。
- 包 02/03 的 Provider Runtime `AVAILABLE` 不能替代 diagnostic capability 验收；本包必须对 exact Host/AWX/PostgreSQL Capability successor 分别写独立 attestation，未通过的保持 `UNAVAILABLE`，全局 READ Admission 仍默认关闭。
- Host/AWX/PostgreSQL 的所有禁止能力必须有输入层零网络和上游恶意响应零 Evidence 两类证明。
- Secret scan 覆盖日志、Trace export、Temporal history、audit/outbox、test artifacts、Playwright screenshots/traces、JUnit，不仅扫描源代码。
- Playwright 不保存 sensitive Evidence body 到 trace；测试使用合成安全数据，生产分类内容关闭录屏/trace 或先 redacted。
- 所有 SLO/告警使用低基数 labels；不得以 Asset ID、QueryID 自由值、Target、Runner、Lease 或错误正文作 label。
- cleanup uncertain 的目标是 0；出现即停止受影响 admission 并 Pager，不允许用可用性 SLO 掩盖。
- 备份/恢复必须包含 000019 六表与前置 Snapshot/Grant/Evidence/Audit 一致性，不能只恢复 UI 查询表。
- READ Admission 在计划实施后默认仍 CLOSED；只有 Go/No-Go 记录获批才按 Scope canary 打开。WRITE 始终 CLOSED。
- 四份 ADR 文件名与编号固定为 0005–0008，不创建其他 Phase 5 ADR。
- `docs/status/current.md` 只记录真实通过的步骤；失败时写 Blocked/命令/证据，不把计划完成写成实现完成。
- 每个 Task 严格 TDD、独立 commit。

---

## Package Position

- 顺序：8 / 8；包 01–07 全部完成后执行。
- 前置接口：完整 Host/PostgreSQL production path、公共 API、Web UI、Phase 1–4 Metrics/Logs/Traces 与 Grant/Gateway。
- 最终交付：CI gates、E2E/axe/visual artifacts、telemetry、runbooks、四份 ADR、蓝图/状态更新与第五阶段 Go/No-Go dossier。
- 本包完成不自动授权生产 rollout；它只生成可供人工批准的证据。

### Task 19: 建立真实依赖集成、跨能力 E2E 与负向安全门

**Files:**
- Create: `internal/hostprobe/integration_test.go`
- Create: `internal/connectors/awx/diagnostic_integration_test.go`
- Create: `internal/readcredential/vault/integration_test.go`
- Create: `internal/postgresrunner/integration_test.go`
- Create: `internal/diagnostice2e/governed_reads_integration_test.go`
- Create: `internal/diagnostice2e/negative_security_integration_test.go`
- Create: `test/diagnostics/compose.yaml`
- Create: `test/diagnostics/host-probe-fixture/README.md`
- Create: `test/diagnostics/awx-fixture/README.md`
- Modify: `Makefile`
- Modify: `.github/workflows/ci.yml`
- Modify: `internal/runtimepublication/provider_gate.go`
- Modify: `internal/runtimepublication/provider_gate_test.go`
- Create: `internal/runtimepublication/diagnostic_attestation_integration_test.go`

**Interfaces:**
- Consumes: packages 01–07 的 production composition、Provider readiness/AWX discovery evidence、Host/PostgreSQL `PENDING` Capability successors 与显式 CI services。
- Produces: `test-diagnostics-integration`、`test-governed-reads-e2e`、负向安全 CI gate、每 Provider/Capability exact signed attestation 与可审计测试报告。

- [ ] **Step 1: 先写 dependency contract 与正向闭环失败测试**

~~~go
func TestGovernedReadE2ERequiresAllRealDependencies(t *testing.T) {
    requireConfigured(t,
        "AIOPS_TEST_POSTGRES_DSN", "AIOPS_TEST_VAULT_ADDR",
        "AIOPS_TEST_AWX_URL", "AIOPS_TEST_HOST_PROBE_URL",
        "AIOPS_TEST_TEMPORAL_ADDRESS", "AIOPS_TEST_OIDC_ISSUER",
    )
}

func TestOneInvestigationExecutesFiveFixedReadFamilies(t *testing.T) {
    fixture := newGovernedReadFixture(t)
    run := fixture.startIncidentInvestigation(t, []string{
        "VICTORIAMETRICS_INSTANT_QUERY",
        "VICTORIALOGS_SEARCH",
        "VICTORIATRACES_SERVICE_GRAPH",
        "HOST_CPU_MEMORY_SNAPSHOT",
        "POSTGRES_SERVER_HEALTH",
    })
    result := fixture.awaitTerminal(t, run, 2*time.Minute)
    if result.Status != "SUCCEEDED" { t.Fatalf("run = %#v", result) }
    assertFiveDistinctEvidenceContracts(t, result)
    assertAllCredentialCleanupTerminal(t, result, "REVOKED", "NO_CREDENTIAL")
    assertAuditChainLinksSnapshotGrantTasksEvidenceReceipts(t, result)
}

func TestNoProductionComponentIsFakeOrMemoryBacked(t *testing.T) {
    graph := assembleProductionDiagnosticsForTest(t)
    assertConcretePackage(t, graph.ContractRepository, "postgres")
    assertConcretePackage(t, graph.CredentialRepository, "postgres")
    assertConcretePackage(t, graph.Issuer, "readcredential/vault")
    assertConcretePackage(t, graph.Revoker, "readcredential/vault")
    assertConcretePackage(t, graph.RunnerGateway, "runnergateway")
}

func TestProviderReadinessCannotSubstituteForDiagnosticCapabilityAttestation(t *testing.T)
func TestRealE2EAttestationOpensOnlyExactProviderCapabilityRevision(t *testing.T)
func TestFailedCapabilityLeavesSiblingAndProviderGatesOrthogonal(t *testing.T)
~~~

- [ ] **Step 2: 写完整负向安全矩阵**

`negative_security_integration_test.go` 用表驱动测试以下类别，每项断言 stable failure、零越权网络/数据库 mutation、零 Evidence、cleanup terminal 或 manual stop：

| 边界 | 必测输入/故障 |
|---|---|
| Host input | command、argv、env、path traversal、glob、script、interpreter、stdin、newline/NUL、shell metacharacter |
| Remote protocol | SSH、WinRM、PTY、Agent Forwarding、local/remote/dynamic forwarding、SFTP/SCP、redirect、proxy、DNS rebinding |
| AWX | 任意 inventory/template/limit/extra_vars/tags/credential/verbosity/timeout、promptable template、stdout、跨 origin |
| PostgreSQL input | arbitrary SQL、semicolon/multi-statement、DDL/DML、COPY、large object、function、extension、temp、LISTEN/NOTIFY、EXPLAIN ANALYZE、timeout/search_path/role/database override |
| PostgreSQL runtime | transaction_read_only off、wrong server cert、DNS/IP drift、lock/statement timeout、row/byte/field overflow、extension missing |
| DLP/Evidence | secret/token/password/private key/DSN/email/IP、unknown nested field、bad UTF-8、NaN/Inf、duplicate JSON、oversize/trailing bytes |
| Grant/runtime | revoked/expired Grant、six-level kill switch、Asset stale/quarantined、mapping ambiguous、Target/Runtime/Realm drift、budget exhausted |
| Credential | issuer timeout after dispatch、delivery response loss、complete/cancel/timeout/runner crash/gateway crash、revoker timeout/5xx/ambiguous lookup |

~~~go
func TestForbiddenInputsHaveZeroExternalSideEffects(t *testing.T) {
    for _, test := range forbiddenDiagnosticInputs() {
        t.Run(test.Name, func(t *testing.T) {
            before := captureExternalFacts(t)
            response := submitDiagnosticRequest(t, test.Request)
            assertStableRejection(t, response, test.Code)
            after := captureExternalFacts(t)
            assertNoNewHostCallsAWXJobsDatabaseMutationsOrEvidence(t, before, after)
        })
    }
}
~~~

- [ ] **Step 3: 运行失败测试并确认 fixtures/gates 缺失**

Run:

~~~bash
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" \
AIOPS_TEST_VAULT_ADDR="$AIOPS_TEST_VAULT_ADDR" \
AIOPS_TEST_AWX_URL="$AIOPS_TEST_AWX_URL" \
AIOPS_TEST_HOST_PROBE_URL="$AIOPS_TEST_HOST_PROBE_URL" \
go test ./internal/diagnostice2e -count=1
~~~

Expected: FAIL because real fixtures, five-family composition and CI targets are not yet defined.

- [ ] **Step 4: 建立可重复的真实测试环境**

`compose.yaml` 固定 PostgreSQL 18.4、Vault dev/test、AWX test dependency 和专用 Host Probe fixture image，使用独立 network、只读 config mounts、健康检查、无宿主 secret。Fixture README 固定镜像 digest、证书生成、Host synthetic data、AWX inventory/template seed、Vault READ role SQL、清理命令和禁止生产复用说明。

Host Probe fixture 必须实现真实 TLS 1.3 mTLS、attestation 和七个固定 ProbeID；它返回合成数据，不调用宿主 shell。AWX fixture 发布专用 read-only playbook/module，模块返回 `host_diagnostic_v1` 结构，不接受 shell/command module 或任意 extra vars。测试检查 AWX template `ask_*` 全 false、凭据无 become/write privilege。

PostgreSQL seed 创建只读诊断角色和代表性 stats/locks/replication fixture；Vault Database secrets role 使用固定 creation/revocation statements、`default_ttl<=5m`、`max_ttl<=5m`、nonrenewable。不能给 role superuser/createdb/createrole/replication/bypassrls 或 schema create。

- [ ] **Step 5: 扩展 Makefile 与 CI，运行真实集成**

Make targets 固定：

~~~make
test-diagnostics-integration:
	@test -n "$$AIOPS_TEST_POSTGRES_DSN"
	@test -n "$$AIOPS_TEST_VAULT_ADDR"
	@test -n "$$AIOPS_TEST_AWX_URL"
	@test -n "$$AIOPS_TEST_HOST_PROBE_URL"
	go test -race -count=1 ./internal/hostprobe ./internal/connectors/awx ./internal/readcredential/vault ./internal/postgresrunner

test-governed-reads-e2e:
	go test -race -count=1 ./internal/diagnostice2e
~~~

CI services 全部健康后才运行 targets，上传 JUnit 但先执行 secret scan。禁止 `continue-on-error`、`|| true` 或仅 warning。Runner/Control Plane 构建使用 production tags，验证无 fake symbol。

每个真实成功场景生成内容寻址 attestation，绑定 Scope、Provider、Connection revision、Target/CapabilitySet/Bundle、contract/query、executor、Realm/Network、credential cleanup、Evidence/Receipt 和 negative-suite digest。Gate service 验证签名与当前闭包后，只把 exact capability revision 标为 `AVAILABLE`；例如 `POSTGRES_SERVER_HEALTH` 成功不能打开 `POSTGRES_SLOW_QUERY_SUMMARY`，Host Probe 成功不能打开 AWX。失败/未运行/漂移的 capability 保持 `UNAVAILABLE`，且这一步不改变全局/Scope READ Admission 的 `CLOSED` 默认值。

Run:

~~~bash
make test-diagnostics-integration
make test-governed-reads-e2e
~~~

Expected: PASS；五类 READ、Receipt/Audit/cleanup、完整负向矩阵均由真实边界证明。

- [ ] **Step 6: Commit**

~~~bash
git add internal/hostprobe internal/connectors/awx internal/readcredential/vault internal/postgresrunner internal/diagnostice2e internal/runtimepublication test/diagnostics Makefile .github/workflows/ci.yml
git commit -m "test: verify governed diagnostic boundaries"
~~~

### Task 20: 完成 Playwright、axe、响应式与视觉回归验收

**Files:**
- Create: `web/e2e/diagnostics.spec.ts`
- Create: `web/e2e/diagnostics-accessibility.spec.ts`
- Create: `web/e2e/diagnostics-responsive.spec.ts`
- Create: `web/e2e/diagnostics-security.spec.ts`
- Create: `web/e2e/__screenshots__/diagnostics-desktop.png`
- Create: `web/e2e/__screenshots__/diagnostics-tablet.png`
- Create: `web/e2e/__screenshots__/diagnostics-mobile.png`
- Modify: `web/playwright.config.ts`
- Modify: `web/package.json`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: package 07 UI/API/MSW or seeded E2E backend、持久化设计文档。
- Produces: browser lifecycle、axe、keyboard、1440/1024/390、视觉与敏感数据泄漏 gates。

- [ ] **Step 1: 写浏览器生命周期与 URL 恢复测试**

~~~ts
test("runs a fixed PostgreSQL diagnostic and keeps cleanup visible", async ({ page }) => {
  await loginAs(page, "sre");
  await page.goto(assetURL("?tab=diagnostics&diagnostic_capability=POSTGRES_LOCK_SNAPSHOT"));
  await page.getByLabel("最小等待时间").selectOption("5");
  await page.getByRole("button", { name: "运行固定诊断" }).click();
  await expect(page).toHaveURL(/diagnostic_run=/);
  await expect(page.getByRole("dialog", { name: "诊断运行详情" })).toBeVisible();
  await expect(page.getByText("凭据已吊销")).toBeVisible({ timeout: 30_000 });
  await expect(page.getByRole("heading", { name: "Evidence" })).toBeVisible();
  await page.reload();
  await expect(page.getByRole("dialog", { name: "诊断运行详情" })).toBeVisible();
});

test("cancel keeps cleanup running and restores focus", async ({ page }) => {
  await openRunningHostDiagnostic(page);
  const trigger = page.getByRole("button", { name: "取消诊断" });
  await trigger.click();
  await page.getByRole("button", { name: "确认取消" }).click();
  await expect(page.getByText("正在完成凭据清理")).toBeVisible();
  await page.getByRole("button", { name: "关闭运行详情" }).click();
  await expect(trigger).toBeFocused();
});
~~~

- [ ] **Step 2: 写 axe、键盘、响应式和禁用控件测试**

每个 1440×1000、1024×900、390×844 viewport 验证无横向溢出、主要 CTA/状态/抽屉、Evidence 转换与 44px target。键盘覆盖 skip link、Tab 顺序、rail roving tabindex、Select、dialog trap/Escape/focus restore。Reduced Motion 下无 pulse animation。

~~~ts
test("has no terminal or SQL editor and leaks no sensitive response fields", async ({ page }) => {
  const sensitive = /dsn|password|secret|token|vault|inventory_id|template_id|query_text|command|endpoint/i;
  page.on("response", async response => {
    if (response.url().includes("/api/v1/") && response.headers()["content-type"]?.includes("json")) {
      expect(await response.text()).not.toMatch(sensitive);
    }
  });
  await openDiagnostics(page);
  await expect(page.locator("[data-terminal], .monaco-editor, textarea[name*=sql i]")).toHaveCount(0);
  expect(await new AxeBuilder({ page }).analyze()).toHaveNoViolations();
});
~~~

- [ ] **Step 3: 运行并确认测试先失败**

Run:

~~~bash
pnpm --dir web playwright test e2e/diagnostics.spec.ts e2e/diagnostics-accessibility.spec.ts e2e/diagnostics-responsive.spec.ts e2e/diagnostics-security.spec.ts
~~~

Expected: FAIL until all lifecycle states, viewports, keyboard behavior and snapshots are implemented/approved.

- [ ] **Step 4: 修正实现并批准最小视觉基线**

只根据 `docs/design/frontend/host-postgresql-diagnostics.md` 修正，不能为截图临时隐藏状态。视觉截图固定 synthetic non-sensitive fixture、字体与时区；mask 动态 run/audit/time。Reviewer 对比 desktop/tablet/mobile 的层级、密度、rail/workspace/drawer、DLP/cleanup persistent state；禁止大面积营销留白、玻璃拟态或移动端缩小 desktop。

Playwright trace 默认 `retain-on-failure`，但 diagnostics security project 设置 trace/screenshots 在 sensitive Evidence 测试中 off；CI artifact 上传前运行 JSON/image metadata secret scan。

- [ ] **Step 5: 运行浏览器全量 gate**

Run:

~~~bash
pnpm --dir web test
pnpm --dir web generate:api:check
pnpm --dir web typecheck
pnpm --dir web lint
pnpm --dir web build
pnpm --dir web playwright test
~~~

Expected: PASS；0 axe serious/critical，三个 viewport 无溢出，键盘/Reduced Motion/URL/权限/危险状态/视觉 snapshot 全通过。

- [ ] **Step 6: Commit**

~~~bash
git add web/e2e web/playwright.config.ts web/package.json .github/workflows/ci.yml
git commit -m "test: verify diagnostic web experience"
~~~

### Task 21: 落盘 telemetry、SLO、恢复手册、四份 ADR 与阶段状态

**Files:**
- Create: `internal/diagnostictelemetry/metrics.go`
- Create: `internal/diagnostictelemetry/metrics_test.go`
- Create: `internal/diagnostictelemetry/audit_test.go`
- Create: `docs/operations/host-read-diagnostics.md`
- Create: `docs/operations/postgresql-read-diagnostics.md`
- Create: `docs/operations/read-credential-cleanup.md`
- Create: `docs/operations/diagnostic-evidence-dlp.md`
- Create: `docs/operations/diagnostic-go-no-go.md`
- Create: `docs/adr/0005-remote-diagnostic-boundary.md`
- Create: `docs/adr/0006-postgresql-named-read-diagnostics.md`
- Create: `docs/adr/0007-read-write-credential-isolation.md`
- Create: `docs/adr/0008-evidence-and-dlp.md`
- Create: `internal/diagnosticapi/docs_contract_test.go`
- Modify: `docs/status/current.md`
- Modify: `docs/architecture/implementation-blueprint-v4.md`
- Modify: `docs/README.md`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: 完整运行路径、E2E/Playwright 证据与现有 docs status/blueprint。
- Produces: 低基数 telemetry、审计链验证、值班/恢复/Go-No-Go 手册、四份 ADR 与精确当前状态。

- [ ] **Step 1: 写 metric labels、audit 链与文档链接失败测试**

~~~go
func TestDiagnosticMetricsUseOnlyBoundedLabels(t *testing.T) {
    registry := newMetricRegistry(t)
    recordAllDiagnosticOutcomes(registry)
    assertMetricLabelKeys(t, registry, []string{
        "provider", "capability_family", "outcome", "failure_class",
        "dlp_state", "cleanup_state", "duration_bucket",
    })
    assertNoMetricLabelKeys(t, registry, []string{
        "tenant_id", "workspace_id", "asset_id", "task_id", "query_id",
        "target", "runner", "lease", "error", "database", "endpoint",
    })
}

func TestDiagnosticAuditChainContainsRequiredFactsAndNoSensitiveValues(t *testing.T) {
    records := executeAuditedDiagnostic(t)
    assertAuditFacts(t, records, []string{
        "actor_or_scheduler", "incident_or_trigger", "model_and_schema",
        "asset", "connection", "target_digest", "capability", "grant",
        "runtime_digest", "realm", "runner_certificate_digest",
        "credential_issue_use_revoke", "probe_or_query_id", "input_hash",
        "result_counts", "result_bytes", "truncated", "dlp_state",
        "evidence", "receipt", "audit_chain",
    })
    assertNoSensitiveAuditValues(t, records)
}

func TestDiagnosticDocumentationLinksAndRequiredSections(t *testing.T) {
    assertMarkdownLinksResolve(t, "docs/operations", "docs/adr", "docs/design/frontend")
    assertADRRangeExactly(t, 5, 8, []string{
        "0005-remote-diagnostic-boundary.md",
        "0006-postgresql-named-read-diagnostics.md",
        "0007-read-write-credential-isolation.md",
        "0008-evidence-and-dlp.md",
    })
}
~~~

- [ ] **Step 2: 运行失败测试**

Run:

~~~bash
go test ./internal/diagnostictelemetry ./internal/diagnosticapi -run 'TestDiagnostic' -count=1
~~~

Expected: FAIL because telemetry and durable operations/ADR documents do not exist.

- [ ] **Step 3: 实现低基数 metrics、traces 与 alerts**

必须提供：run requested/terminal counter、phase duration histogram、result items/bytes histogram、DLP redaction/rejection counter、credential issue counter、cleanup latency/retry/uncertain/manual counter、contract mismatch、Grant/Runtime rejection、active runs gauge、cleanup queue age gauge。Trace spans 使用 hash/enum，不带 endpoint/query/params/Evidence。

初始 SLO 与告警固定写入 Go/No-Go：

| 指标 | 目标 | 告警 |
|---|---|---|
| eligible diagnostic accepted | 99.9% / 30d（排除显式 Grant/Kill Switch 拒绝） | 5m burn 14.4×、1h burn 6× |
| Host mTLS p95 | < 10s | 15m p95 > 10s |
| AWX p95 | < 60s | 30m p95 > 60s 或 stuck job |
| PostgreSQL p95 | < 5s | 15m p95 > 5s / timeout > 1% |
| cleanup p99 | < 60s | oldest pending > 60s |
| cleanup uncertain/manual | 0 | 任意一条立即 Pager + admission containment |
| DLP bypass | 0 | schema/digest mismatch 或 unsafe Evidence 任意一条立即 Pager |

- [ ] **Step 4: 写运行手册、恢复演练与四份 ADR**

Host 手册：mTLS cert/CA rotation、attestation key rotation、DNS/Network Policy、Probe/AWX template publication、job cancel/stuck、禁止 SSH/terminal 诊断替代流程。PostgreSQL 手册：Query revision/golden publication、extension preflight、read replica preference、TLS/CA、role privileges、timeout/lock、row cap 与 safe rollback。

Credential cleanup 手册必须逐步覆盖 issuer after-dispatch crash、delivery loss、Runner/Gateway crash、complete/cancel/timeout、revoker ambiguous、keyring rotation、manual lookup/revoke/confirm；人工命令只接受内部 lease ID，经最近认证/双人审批，不打印 accessor。Evidence/DLP 手册覆盖 classification、redaction/HMAC key rotation、DLP rejection triage、Evidence retention/deletion、audit continuity。

恢复演练固定：kill Gateway after Vault issue/before delivery；kill Runner during query；partition revoker；expire cleanup claim；corrupt accessor key ID；AWX stuck；Host bad attestation；PostgreSQL lock timeout；restore six 000019 tables plus Snapshot/Grant/Evidence/Audit to isolated database and verify hashes。记录 RPO≤5m、control-plane RTO≤30m、cleanup containment≤60s；未达标即 No-Go。

四份 ADR 精确内容：

- `0005-remote-diagnostic-boundary.md`：选择固定 mTLS Probe/AWX template，拒绝 interactive SSH/WinRM/PTY/forward/SFTP，未来变更需独立 ADR。
- `0006-postgresql-named-read-diagnostics.md`：选择 schema-versioned known SQL bytes/typed params/read-only tx/caps，拒绝任意 SQL/函数/timeout。
- `0007-read-write-credential-isolation.md`：READ/WRITE issuer/revoker/token/mount/role/table/config/identity 分离，single delivery 与 durable cleanup。
- `0008-evidence-and-dlp.md`：schema-first projection、DLP-before-Evidence、counts/truncation/redaction/receipt/audit，拒绝 raw results。

每份 ADR 含 Context、Decision、Alternatives Rejected、Security Consequences、Operational Consequences、Migration/Rollback、Verification、Status；文档链接到对应 tests/runbooks/design，不写未验证结论。

- [ ] **Step 5: 更新唯一状态与蓝图，但保留 Admission CLOSED**

仅在 Task 19–20 和本 Task 全绿后更新 `docs/status/current.md`：记录 000019、Host Probe/AWX、六 Query、READ credential isolation、cleanup、API/Web/E2E 的 implemented/verified commit 和命令；醒目标注 `READ Admission: CLOSED pending production Go/No-Go approval`、`WRITE: CLOSED`。失败则记录 Blocked 和失败证据。

`implementation-blueprint-v4.md` 增加 Host/PostgreSQL data/control/credential/evidence flows、六表所有权、single-attempt credential saga、cleanup containment、public API/UI route、SLO/HA/backup；保留 V3 与 Phase 1–4 历史。`docs/README.md` 链接 design、runbooks、ADRs 和 status。

- [ ] **Step 6: 执行全量验证与计划自检**

Run:

~~~bash
go test ./...
go test -race -shuffle=on -count=1 ./...
go vet ./...
make test-integration
make test-diagnostics-integration
make test-governed-reads-e2e
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
pnpm --dir web test
pnpm --dir web typecheck
pnpm --dir web lint
pnpm --dir web build
pnpm --dir web playwright test
AIOPS_ARTIFACT_ROOTS='test-results,logs,traces,temporal-history,audit-export' \
  go test ./internal/diagnostice2e -run 'TestDiagnosticArtifactsAreSecretFree' -count=1
git diff --check
~~~

Expected: 全部 PASS；artifact scanner 解析格式并允许明确 `[REDACTED]`，拒绝任何真实值或敏感字段正文；Admission 配置仍 closed，status/blueprint 与实际一致。

- [ ] **Step 7: Commit**

`docs/operations/diagnostic-go-no-go.md` 汇总 migration hash、image digest、contract/query golden、证书与 key rotation、Vault policy、role privilege diff、E2E/JUnit/axe/visual、SLO dashboard、alerts、backup restore、五类故障演练、cleanup uncertain=0、known risks、reviewer/approval slots、canary/rollback。文档不能自行填写批准人或打开开关。

~~~bash
git add internal/diagnostictelemetry internal/diagnosticapi/docs_contract_test.go \
  docs/operations/host-read-diagnostics.md docs/operations/postgresql-read-diagnostics.md \
  docs/operations/read-credential-cleanup.md docs/operations/diagnostic-evidence-dlp.md \
  docs/operations/diagnostic-go-no-go.md docs/adr/0005-remote-diagnostic-boundary.md \
  docs/adr/0006-postgresql-named-read-diagnostics.md docs/adr/0007-read-write-credential-isolation.md \
  docs/adr/0008-evidence-and-dlp.md docs/status/current.md \
  docs/architecture/implementation-blueprint-v4.md docs/README.md .github/workflows/ci.yml
git commit -m "docs: operationalize host and postgres diagnostics"
~~~
