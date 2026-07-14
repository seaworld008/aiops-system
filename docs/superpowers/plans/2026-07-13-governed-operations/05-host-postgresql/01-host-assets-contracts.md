# Host Diagnostic Facts and Contracts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 以固定迁移 `000019_host_postgresql_read_diagnostics` 和纯 Go 领域契约锁定 Host Probe、AWX 模板、PostgreSQL 命名查询、READ 凭据 cleanup 与诊断 Receipt 的不可变事实边界。

**Architecture:** PostgreSQL 只保存版本化合同、生命周期事实和安全摘要；私有执行内容由受信任发布流程写入，浏览器、Task、模型与 Runner 请求都不能创建或覆盖。领域层用不透明 ID、严格 union、JCS/SHA-256 和 redacted marshal 把八表投影为后续执行包可消费的窄接口。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、pgx/v5、RFC 8785 JCS、SHA-256、现有 `assetcatalog`、`connectionprofile`、`runtimepublication`、`investigationgrant`、`readtask`、`store`。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- 实现基线固定为 `main@ad50d9f`；执行前创建独立 worktree，不删除或修改用户已有 worktree。
- 迁移名和文件名必须精确为 `000019_host_postgresql_read_diagnostics`；只创建 README 指定的八张新表。允许且必须做本阶段所需的 additive 兼容变更（Provider allowlist、Runtime artifact kind/size、AWX Connection projection、Validation Run/Check private proof fields、Environment candidate key、Audit Environment projection），但不得改变 Phase 1–4 领域语义或绕过其状态机。AWX enrollment 使用本迁移专属 Operation/Attempt，不复用 Investigation lease、Phase 1 SourceRun 或 Connection Validation Run。
- `000019` 是 `public.asset_catalog_future_source_gate_admitted(candidate public.asset_sources) RETURNS boolean` 的 Phase 5 successor owner；只能 `CREATE OR REPLACE` 同一签名 body，逐字保留 `000017` 的 Kubernetes Operator branch，并增加 exact `AWX_INVENTORY / AWX_API / AWX_READ_V1 / available runtime closure / validation proof` branch。函数替换不创建额外或第九张表，也不得形成 overload 或第二套 admission。
- 所有行都绑定 Tenant/Workspace/Environment；跨 Scope 外键、读取、列表、发布和 cleanup 必须 fail closed。
- 合同 revision 一经写入不可 UPDATE/DELETE/TRUNCATE；新行为只能新建 revision，已被 Grant 固定的旧 revision 保持可解析，安全撤销实时覆盖。
- Host 合同不得出现 command、argv、env、path、glob、script、interpreter、stdin、PTY、forward、SFTP、SSH 或 WinRM 字段。
- AWX 合同只保存预发布 inventory/template/limit 的不可变映射；公共投影不得返回其数值 ID。
- PostgreSQL 合同只接受六个固定 QueryID 和 versioned schema；SQL 模板是私有事实，任何 Marshal/String/Audit 都必须 redacted。
- `read_credential_leases` 不保存 credential value、username、password；只保存加密 accessor、key ID、HMAC 和签发/吊销事实。
- Receipt 不保存 SQL、命令、原始响应、完整 Evidence、endpoint、DSN、Vault/AWX 内部信息；只保存稳定 ID、hash、counts、bytes、truncation、DLP、cleanup、Evidence/Audit 关联。
- Production Repository 必须是 PostgreSQL；内存仓储只能在 `*_test.go`。
- 所有新代码严格 TDD；每个 Task 独立 commit。

---

## Package Position

- 顺序：1 / 8；必须最先执行。
- 前置：Phase 1 的 Asset/Scope，Phase 2 的 Connection/PublishedTarget/Capability/Runtime/Realm，Phase 4 的 Snapshot/Grant/Budget/Evidence。
- 交付给下一包：`hostdiagnostic.Registry`、`postgresdiagnostic.Registry`、八表 PostgreSQL repository、AWX enrollment 固定协议与稳定 schema/状态常量。
- 本包只建立事实与合同，不发网络请求、不签发凭据、不接入公共 API。

### Task 1: 创建 000019 八表迁移与完整性保护

**Files:**
- Create: `migrations/000019_host_postgresql_read_diagnostics.up.sql`, `migrations/000019_host_postgresql_read_diagnostics.down.sql`
- Modify: `internal/store/postgres/migrations_integration_test.go`, `internal/store/postgres/database_role_admission.go`, `internal/store/postgres/database_role_admission_test.go`
- Modify: `internal/assetcatalog/postgres/schema_admission.go`, `internal/assetcatalog/postgres/schema_admission_test.go`, `internal/assetcatalog/postgres/schema_admission_integration_test.go`
- Modify: `internal/assetcatalog/postgres/migration_recovery_integration_test.go`, `internal/assetcatalog/postgres/recovery_container_test.go`, `docs/operations/database-role-bootstrap.md`
- Create: `internal/assetdiscovery/awx/source_profile.go`, `internal/assetdiscovery/awx/source_profile_test.go`
- Create: `internal/diagnosticcontract/schema_manifest.go`, `internal/diagnosticcontract/schema_manifest_test.go`

**Interfaces:**
- Consumes: 000015 `assets` 与 default-false Future Source hook，000016 Connection/Target/Capability/Runtime/Realm，000017 已验收的 Kubernetes Operator successor body/definition digest，000018 Snapshot/Grant，现有 `investigation_task_attempts`、`evidence`、`runner_evidence_receipts`、`audit_records`、`outbox_events`。
- Produces: 八张表、不可变/状态/延迟闭包触发器、cleanup/enrollment claim 索引、Receipt 唯一性、`000019` Future Source successor body、精确 runtime role-admission 增量与 guarded down migration；AWX enrollment 的唯一协议/表/摘要契约见 `docs/contracts/awx-host-identity-enrollment-v1.md`。
- Safety: AWX branch 逐状态验收：`VALIDATING` 需要 same-Scope canonical Integration、exact `AWX_READ_V1` draft revision、唯一 exact `AVAILABLE` Runtime closure 与 newly queued Validation Run；`AVAILABLE|DEGRADED` 再要求 exact published revision 和 successful validation/cleanup proof。错误 profile/schema/revision/runtime/bundle/digest、缺失或重复 closure 一律 false。Down 只要存在任一 AWX Source（包括 `UNAVAILABLE|SUSPENDED`）就整笔拒绝；空状态回滚才可恢复 exact `000017` body，因此 Kubernetes branch 继续有效而 AWX 再次默认关闭，且旧 AWX revision/proof 不可能跨 migration generation 复用。

- [ ] **Step 1: 写失败的迁移、作用域、不可变与 rollback 测试**

在 `migrations_integration_test.go` 增加以下真实 PostgreSQL 18.4+ 测试；不得用 sqlmock 代替迁移验收：

~~~go
func TestHostPostgreSQLDiagnosticsMigrationOwnsExactlyEightTables(t *testing.T) {
    database := openMigrationDatabase(t)
    migrateThrough(t, database, 19)
    got := migrationTables(t, database, []string{
        "host_probe_contract_revisions",
        "awx_read_template_revisions",
        "postgres_diagnostic_query_revisions",
        "read_credential_leases",
        "read_credential_cleanup_attempts",
        "diagnostic_execution_receipts",
        "awx_host_identity_enrollments", "awx_host_identity_enrollment_attempts",
    })
    if diff := cmp.Diff([]string{
        "awx_host_identity_enrollment_attempts", "awx_host_identity_enrollments", "awx_read_template_revisions", "diagnostic_execution_receipts",
        "host_probe_contract_revisions", "postgres_diagnostic_query_revisions",
        "read_credential_cleanup_attempts", "read_credential_leases",
    }, got); diff != "" {
        t.Fatalf("000019 table ownership mismatch (-want +got):\n%s", diff)
    }
}
func TestDiagnosticContractsRejectMutationAndCrossScopeReferences(t *testing.T) {
    database := migratedDiagnosticsDatabase(t)
    fixture := insertPublishedDiagnosticFixture(t, database)
    insertHostProbeRevision(t, database, fixture)
    assertSQLState(t, updateHostProbeRevision(t, database, fixture), "55000")
    assertForeignKeyViolation(t, insertCrossScopeQueryRevision(t, database, fixture))
    assertCheckViolation(t, insertCallerControlledHostFields(t, database, fixture))
}
func TestDiagnosticCredentialLeaseIsSingleAttemptAndReceiptIsImmutable(t *testing.T) {
    database := migratedDiagnosticsDatabase(t)
    fixture := insertRunningReadAttempt(t, database)
    insertReadCredentialLease(t, database, fixture)
    assertUniqueViolation(t, insertSecondLeaseForAttempt(t, database, fixture))
    insertDiagnosticReceipt(t, database, fixture)
    assertSQLState(t, updateDiagnosticReceipt(t, database, fixture), "55000")
}
func TestHostPostgreSQLDiagnosticsDownIsGuarded(t *testing.T) {
    database := migratedDiagnosticsDatabase(t)
    fixture := insertPublishedDiagnosticFixture(t, database)
    insertHostProbeRevision(t, database, fixture)
    err := migrateDownOne(t, database)
    assertConstraintError(t, err, "host_postgresql_read_diagnostics_down_guard")
}
func TestHostPostgreSQLDiagnosticsMigrationRoundTripsEmptyDatabase(t *testing.T) {
    database := migratedDiagnosticsDatabase(t)
    truncateDiagnosticsOwnedState(t, database)
    migrateDownOne(t, database)
    migrateUpOne(t, database)
}
func TestHostPostgreSQLDiagnosticsMigrationOwnsExactFutureSourceGateDefinition(t *testing.T) { assert000019FutureSourceGateDefinition(t) }
func TestHostPostgreSQLDiagnosticsMigrationPreservesVictoriaFutureSourceGate(t *testing.T) { assert000019VictoriaTruthTable(t) }
func TestHostPostgreSQLDiagnosticsMigrationAdmitsOnlyExactAWXRuntimeClosure(t *testing.T) { assert000019AWXRuntimeClosure(t) }
func TestHostPostgreSQLDiagnosticsMigrationRejectsAWXProfileManifestSchemaAndDigestDrift(t *testing.T) { assert000019AWXProfileDrift(t) }
func TestHostPostgreSQLDiagnosticsMigrationRejectsAWXSelectionAndSourceProofDrift(t *testing.T) { assert000019AWXProofDrift(t) }
func TestHostPostgreSQLDiagnosticsMigrationEnforcesJCSSafeAWXIDs(t *testing.T) { assert000019JCSSafeAWXIDs(t) }
func TestHostPostgreSQLDiagnosticsMigrationRecoversAWXOnlyAfterExactRevalidation(t *testing.T) { assert000019AWXRecovery(t) }
func TestHostPostgreSQLDiagnosticsDownRefusesAnyAWXAndRestoresVictoriaGate(t *testing.T) { assert000019DownAWXGuardAndVictoriaRestore(t) }
func TestHostPostgreSQLDiagnosticsDownRefusesOrphanAWXMappingArtifact(t *testing.T) { assert000019DownOrphanArtifactGuard(t) }
func TestHostPostgreSQLDiagnosticsDownRefusesAWXConnectionOrSelectionProjection(t *testing.T) { assert000019DownProjectionGuard(t) }
func TestHostPostgreSQLDiagnosticsMigrationNowaitLockFailureIsAtomicAndRetryable(t *testing.T) { assert000019CompleteNowaitLockSet(t) }
func TestHostPostgreSQLDiagnosticsMigrationRejectsPredecessorManifestDrift(t *testing.T) { assert000019PredecessorDrift(t) }
func TestHostPostgreSQLDiagnosticsMigrationPreflightMatchesReviewedManifest(t *testing.T) { assert000019ReviewedManifestParity(t) }
func TestHostPostgreSQLDiagnosticsMigrationBindsExactAWXInventoryArtifact(t *testing.T) { assert000019AWXArtifactAndEnrollmentClosure(t) }
func TestHostPostgreSQLDiagnosticsMigrationOwnsExactRoutineManifest(t *testing.T) { assert000019ExactEightTableRoutineTriggerManifest(t) }
func TestHostPostgreSQLDiagnosticsMigrationRejectsCallerOwnedContractAndReceiptDigests(t *testing.T) { assert000019DatabaseOwnedDigests(t) }
func TestHostPostgreSQLDiagnosticsMigrationRejectsNoncanonicalContractJSON(t *testing.T) { assert000019CanonicalContractJSON(t) }
func TestHostPostgreSQLDiagnosticsMigrationEnforcesExactCredentialStateMatrices(t *testing.T) { assert000019CredentialAndEnrollmentStateMatrices(t) }
func TestHostPostgreSQLSchemaAdmissionIncludesAWXSuccessorDefinitionDigest(t *testing.T) { assert000019SchemaAdmissionDigest(t) }
func TestHostPostgreSQLSchemaAdmissionRejectsAWXSuccessorBodyDrift(t *testing.T) { assert000019SchemaAdmissionDrift(t) }
func TestHostPostgreSQLDatabaseRoleAdmissionPreservesExactOwnerGraph(t *testing.T) { assert000019DatabaseRoleGraph(t) }
func TestHostPostgreSQLSchemaAdmissionSurvivesMultiOwnerDumpRestore(t *testing.T) { assert000019MultiOwnerRestore(t) }
func TestAWXReadProfileManifestV1Golden(t *testing.T) { assertAWXReadProfileManifestV1Golden(t) }
func TestAWXProviderSchemaV1Golden(t *testing.T) { assertAWXProviderSchemaV1Golden(t) }
func TestAWXSourceDefinitionV2Golden(t *testing.T) { assertAWXSourceDefinitionV2Golden(t) }
func Test000019EmbedsExactAWXProfileGolden(t *testing.T) { assert000019AWXProfileGolden(t) }
~~~

Every wrapper above has a real helper body in the same RED commit；undefined helper、Skip、compile-only failure or one shared vague assertion is forbidden。Future Source helpers query `pg_proc`/`pg_get_functiondef` and compare the exact PostgreSQL 18.4 UTF-8 definition SHA-256 golden，proving the sole hook identity and preserved `000017` truth table。The eight-table/routine/artifact helper also executes the exact enrollment contract golden against direct SQL。Before 000019，initial AWX Source commit fails；after up only canonical Integration/Connection/selection/mapping Runtime permits initial Source closure，and only its own later validation proof plus `REVOKED` cleanup opens `AVAILABLE`。Enum/Profile/Runtime presence alone never admits。The manifest-parity helper byte-compares every inlined up/down assertion and generated lock set with reviewed manifests；comment-only、omitted relation or runtime skip fails before DDL。

- [ ] **Step 2: 运行测试并确认 000019 缺失**

Run:

~~~bash
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/store/postgres -run 'Test(HostPostgreSQLDiagnostics|DiagnosticContracts|DiagnosticCredential)' -count=1
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/store/postgres -run 'TestHostPostgreSQLDatabaseRoleAdmission' -count=1
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/assetcatalog/postgres -run 'TestHostPostgreSQLSchemaAdmission' -count=1
go test ./internal/assetdiscovery/awx -run 'Test(AWX|000019Embeds).*Golden' -count=1
~~~

Expected: FAIL，错误明确指出 migration 19、八张表、enrollment Operation/Attempt closure 或 `000019` reviewed successor manifest 不存在；不能因环境未设置而把 CI 验收标记为通过。

- [ ] **Step 3: 实现合同事实表**

Up migration first performs a read-only minimum-existence check，then takes the successor advisory lock and one complete NOWAIT table lock set before any fingerprint、guard、`ALTER` or `CREATE`。It validates the full reviewed 000017+000018 predecessor manifest under the deparse GUCs，restores the public DDL search path explicitly，and only then creates contract facts。The fenced block is an **ordered DDL excerpt, not a copyable migration**：the final migration must inline every predecessor assertion exported from reviewed manifests at the marked GUC boundary and every successor routine/trigger/index body before postflight。The generated predecessor-manifest relation set must equal the one-shot lock set exactly；up/down parser tests byte-compare assertions and set equality，then hold each relation independently to require `55P03` before mutation。There is no comment-only substitute、runtime skip or hand-maintained shorter set。字段与检查至少如下，执行者不得增加自由输入列：

~~~sql
BEGIN;
SET LOCAL lock_timeout = '5s';
DO $$
BEGIN
  IF EXISTS (
       SELECT 1
       FROM pg_catalog.unnest(ARRAY[
         'public.environments',
         'public.asset_sources',
         'public.asset_source_revisions',
         'public.asset_source_revision_authorities',
         'public.asset_source_runs',
         'public.asset_observations',
         'public.assets',
         'public.asset_type_details',
         'public.asset_conflicts',
         'public.asset_relationships',
         'public.service_asset_bindings',
         'public.credential_references',
         'public.credential_reference_revisions',
         'public.connection_profiles',
         'public.connection_revisions',
         'public.connection_revision_capabilities',
         'public.capability_definitions',
         'public.connection_validation_runs',
         'public.connection_validation_checks',
         'public.validation_credential_revocations',
         'public.runner_realms',
         'public.runner_capability_bindings',
         'public.published_targets',
         'public.published_capability_sets',
         'public.published_capability_set_items',
         'public.runtime_publications',
         'public.runtime_publication_artifacts',
         'public.victoria_operator_source_revisions',
         'public.victoria_compatibility_profiles',
         'public.victoria_compatibility_capabilities',
         'public.victoria_connection_contracts',
         'public.integrations',
         'public.asset_snapshots',
         'public.asset_snapshot_items',
         'public.investigation_grants',
         'public.investigation_task_attempts',
         'public.runner_evidence_receipts',
         'public.evidence',
         'public.audit_records',
         'public.outbox_events'
       ]) AS prerequisite(name)
       WHERE pg_catalog.to_regclass(prerequisite.name) IS NULL
     )
     OR pg_catalog.to_regprocedure(
          'public.asset_catalog_future_source_gate_admitted(public.asset_sources)'
        ) IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='55000',
      MESSAGE='000015, 000016, 000017 and 000018 are required',
      CONSTRAINT='host_postgresql_read_diagnostics_prerequisite';
  END IF;
END $$;
SELECT pg_catalog.pg_advisory_xact_lock(712017001900001);
LOCK TABLE
  public.environments,
  public.asset_sources, public.asset_source_revisions,
  public.asset_source_revision_authorities, public.asset_source_runs,
  public.asset_observations, public.assets, public.asset_type_details,
  public.asset_conflicts, public.asset_relationships, public.service_asset_bindings,
  public.credential_references, public.credential_reference_revisions,
  public.connection_profiles, public.connection_revisions,
  public.connection_revision_capabilities, public.capability_definitions,
  public.connection_validation_runs, public.connection_validation_checks,
  public.validation_credential_revocations,
  public.runner_realms, public.runner_capability_bindings,
  public.published_targets, public.published_capability_sets,
  public.published_capability_set_items,
  public.runtime_publications, public.runtime_publication_artifacts,
  public.victoria_operator_source_revisions,
  public.victoria_compatibility_profiles,
  public.victoria_compatibility_capabilities,
  public.victoria_connection_contracts,
  public.integrations,
  public.asset_snapshots, public.asset_snapshot_items,
  public.investigation_grants, public.investigation_task_attempts,
  public.runner_evidence_receipts, public.evidence, public.audit_records, public.outbox_events
IN ACCESS EXCLUSIVE MODE NOWAIT;
SET LOCAL quote_all_identifiers = off;
SET LOCAL search_path = pg_catalog, pg_temp;
-- Ordered excerpt resumes only after the final migration has executed every
-- reviewed 000017+000018 definition/owner/ACL/signature assertion.
SET LOCAL search_path = public, pg_catalog, pg_temp;
ALTER TABLE connection_profiles
  DROP CONSTRAINT connection_profiles_provider_kind_check,
  ADD CONSTRAINT connection_profiles_provider_kind_check
  CHECK (provider_kind IN (
    'PROMETHEUS','VICTORIAMETRICS','VICTORIALOGS','VICTORIATRACES',
    'HOST_PROBE_MTLS','AWX_API','POSTGRESQL'
  ));
ALTER TABLE runner_capability_bindings
  DROP CONSTRAINT runner_capability_bindings_provider_kind_check,
  ADD CONSTRAINT runner_capability_bindings_provider_kind_check
  CHECK (provider_kind IN (
    'PROMETHEUS','VICTORIAMETRICS','VICTORIALOGS','VICTORIATRACES',
    'HOST_PROBE_MTLS','AWX_API','POSTGRESQL'
  ));
ALTER TABLE capability_definitions
  DROP CONSTRAINT capability_definitions_provider_kind_check,
  ADD CONSTRAINT capability_definitions_provider_kind_check
  CHECK (provider_kind IN (
    'PROMETHEUS','VICTORIAMETRICS','VICTORIALOGS','VICTORIATRACES',
    'HOST_PROBE_MTLS','AWX_API','POSTGRESQL'
  ));
ALTER TABLE investigation_task_attempts
  ADD CONSTRAINT investigation_task_attempts_environment_attempt_uk
  UNIQUE (tenant_id, workspace_id, environment_id,
          investigation_id, task_id, lease_epoch);
ALTER TABLE runner_evidence_receipts
  ADD CONSTRAINT runner_evidence_receipts_environment_attempt_resource_uk
  UNIQUE (tenant_id, workspace_id, environment_id,
          investigation_id, task_id, lease_epoch, id);
ALTER TABLE audit_records
  ADD COLUMN environment_id uuid,
  ADD CONSTRAINT audit_records_environment_scope_fk
    FOREIGN KEY (tenant_id, workspace_id, environment_id)
    REFERENCES environments (tenant_id, workspace_id, id),
  ADD CONSTRAINT audit_records_environment_resource_uk
    UNIQUE (tenant_id, workspace_id, environment_id, id);

CREATE TABLE host_probe_contract_revisions (
  tenant_id uuid NOT NULL, workspace_id uuid NOT NULL, environment_id uuid NOT NULL,
  id uuid NOT NULL, revision bigint NOT NULL CHECK (revision > 0),
  capability_definition_id uuid NOT NULL,
  capability_definition_revision bigint NOT NULL CHECK (capability_definition_revision > 0),
  provider_kind text NOT NULL CHECK (provider_kind = 'HOST_PROBE_MTLS'),
  probe_id text NOT NULL CHECK (probe_id IN (
    'host.system-info.v1', 'host.cpu-memory-snapshot.v1',
    'host.disk-usage.v1', 'host.network-listeners.v1',
    'host.systemd-status.v1', 'host.windows-service-status.v1',
    'host.bounded-log-window.v1'
  )),
  input_schema_version text NOT NULL CHECK (input_schema_version = 'host-diagnostic-input.v1'),
  input_schema bytea NOT NULL CHECK (octet_length(input_schema) BETWEEN 2 AND 32768),
  evidence_schema_version text NOT NULL CHECK (evidence_schema_version = 'host-diagnostic-evidence.v1'),
  evidence_schema bytea NOT NULL CHECK (octet_length(evidence_schema) BETWEEN 2 AND 32768),
  max_duration_ms integer NOT NULL CHECK (max_duration_ms BETWEEN 100 AND 20000),
  max_result_items integer NOT NULL CHECK (max_result_items BETWEEN 1 AND 200),
  max_result_bytes integer NOT NULL CHECK (max_result_bytes BETWEEN 1024 AND 262144),
  contract_digest text NOT NULL CHECK (contract_digest ~ '^[a-f0-9]{64}$'),
  status text NOT NULL CHECK (status = 'AVAILABLE'),
  created_by text NOT NULL CHECK (octet_length(created_by) BETWEEN 1 AND 256),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, workspace_id, environment_id, id, revision),
  UNIQUE (tenant_id, workspace_id, environment_id, probe_id, revision),
  FOREIGN KEY (tenant_id, workspace_id, environment_id,
               capability_definition_id, capability_definition_revision)
    REFERENCES capability_definitions
      (tenant_id, workspace_id, environment_id, id, revision)
);

CREATE TABLE awx_read_template_revisions (
  tenant_id uuid NOT NULL, workspace_id uuid NOT NULL, environment_id uuid NOT NULL,
  id uuid NOT NULL, revision bigint NOT NULL CHECK (revision > 0),
  capability_definition_id uuid NOT NULL,
  capability_definition_revision bigint NOT NULL,
  provider_kind text NOT NULL CHECK (provider_kind = 'AWX_API'),
  inventory_id bigint NOT NULL CHECK (inventory_id BETWEEN 1 AND 9007199254740991),
  job_template_id bigint NOT NULL CHECK (job_template_id BETWEEN 1 AND 9007199254740991),
  identity_artifact_sha256 text NOT NULL CHECK (identity_artifact_sha256 ~ '^[a-f0-9]{64}$'), identity_artifact_root_digest text NOT NULL CHECK (identity_artifact_root_digest ~ '^[a-f0-9]{64}$'), identity_binding_count integer NOT NULL CHECK (identity_binding_count BETWEEN 1 AND 10000),
  extra_vars_schema bytea NOT NULL CHECK (octet_length(extra_vars_schema) BETWEEN 2 AND 32768),
  output_projection_schema bytea NOT NULL CHECK (octet_length(output_projection_schema) BETWEEN 2 AND 32768),
  max_poll_seconds integer NOT NULL CHECK (max_poll_seconds BETWEEN 1 AND 120),
  max_result_items integer NOT NULL CHECK (max_result_items BETWEEN 1 AND 200),
  max_result_bytes integer NOT NULL CHECK (max_result_bytes BETWEEN 1024 AND 262144),
  template_fingerprint_manifest bytea NOT NULL CHECK (octet_length(template_fingerprint_manifest) BETWEEN 2 AND 16384),
  template_fingerprint_digest text NOT NULL CHECK (template_fingerprint_digest ~ '^[a-f0-9]{64}$'),
  contract_digest text NOT NULL CHECK (contract_digest ~ '^[a-f0-9]{64}$'),
  status text NOT NULL CHECK (status = 'AVAILABLE'),
  created_by text NOT NULL CHECK (octet_length(created_by) BETWEEN 1 AND 256),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, workspace_id, environment_id, id, revision),
  UNIQUE (tenant_id, workspace_id, environment_id, inventory_id, job_template_id,
          capability_definition_id, capability_definition_revision, revision),
  FOREIGN KEY (tenant_id, workspace_id, environment_id,
               capability_definition_id, capability_definition_revision)
    REFERENCES capability_definitions
      (tenant_id, workspace_id, environment_id, id, revision)
);

CREATE TABLE postgres_diagnostic_query_revisions (
  tenant_id uuid NOT NULL, workspace_id uuid NOT NULL, environment_id uuid NOT NULL,
  id uuid NOT NULL, revision bigint NOT NULL CHECK (revision > 0),
  capability_definition_id uuid NOT NULL,
  capability_definition_revision bigint NOT NULL,
  provider_kind text NOT NULL CHECK (provider_kind = 'POSTGRESQL'),
  query_id text NOT NULL CHECK (query_id IN (
    'postgres.server-health.v1', 'postgres.connection-snapshot.v1',
    'postgres.lock-snapshot.v1', 'postgres.replication-snapshot.v1',
    'postgres.database-size.v1', 'postgres.slow-query-summary.v1'
  )),
  input_schema_version text NOT NULL CHECK (input_schema_version = 'postgres-diagnostic-input.v1'),
  input_schema bytea NOT NULL CHECK (octet_length(input_schema) BETWEEN 2 AND 32768),
  result_schema_version text NOT NULL CHECK (result_schema_version = 'postgres-diagnostic-result.v1'),
  result_schema bytea NOT NULL CHECK (octet_length(result_schema) BETWEEN 2 AND 32768),
  evidence_schema_version text NOT NULL CHECK (evidence_schema_version = 'postgres-diagnostic-evidence.v1'),
  evidence_schema bytea NOT NULL CHECK (octet_length(evidence_schema) BETWEEN 2 AND 32768),
  query_template bytea NOT NULL CHECK (octet_length(query_template) BETWEEN 16 AND 32768),
  query_sha256 text NOT NULL CHECK (query_sha256 ~ '^[a-f0-9]{64}$'),
  max_duration_ms integer NOT NULL CHECK (max_duration_ms BETWEEN 100 AND 10000),
  statement_timeout_ms integer NOT NULL CHECK (statement_timeout_ms BETWEEN 50 AND 9000),
  lock_timeout_ms integer NOT NULL CHECK (lock_timeout_ms BETWEEN 10 AND 1000),
  max_rows integer NOT NULL CHECK (max_rows BETWEEN 1 AND 200),
  max_result_bytes integer NOT NULL CHECK (max_result_bytes BETWEEN 1024 AND 262144),
  required_extension text CHECK (required_extension IN ('pg_stat_statements')),
  registry_digest text NOT NULL CHECK (registry_digest ~ '^[a-f0-9]{64}$'),
  status text NOT NULL CHECK (status = 'AVAILABLE'),
  created_by text NOT NULL CHECK (octet_length(created_by) BETWEEN 1 AND 256),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, workspace_id, environment_id, id, revision),
  UNIQUE (tenant_id, workspace_id, environment_id, query_id, revision),
  FOREIGN KEY (tenant_id, workspace_id, environment_id,
               capability_definition_id, capability_definition_revision)
    REFERENCES capability_definitions
      (tenant_id, workspace_id, environment_id, id, revision)
);
~~~

Task 1 owns seven immutable no-BOM/no-newline RFC 8785 fixtures：Host input 1296/ed3281141aeca72fe711113d874717b90ce90acd0e73b3bef3d3e4c9b97b5b57、Host evidence 4899/9ba1f395ebe0d9c3fc51e5a8a0d474d59801fbc8b51241d8c581de1ba558372a、AWX extra-vars 2446/fad880f84f8266903a9cdd2ed94b94c18d86393d5f7244e92e6ed170a57f0190、AWX output 3178/5db5e247bc26fba403d0acf9fc857de7e30bf844d3ca4bfe4384be736fb62e1e、PostgreSQL input 956/75f708971c11c8637ef554366075175e6b31548dc846b676511e2d2860ad05dc、PostgreSQL result 4752/108d651d7a776b815045089e5e7dcb05b7536cb3c38f6182fac292665ae6e42e、PostgreSQL evidence 4871/01a067a3469b14fb0e9c13a2b6465a58a4a5edce0133257b52514a1d88e6969f（bytes/SHA-256）：
~~~json
{"branches":[{"fields":{"log_source_id":{"enum":["AWX","KEYCLOAK","KERNEL","POSTGRESQL","SECURITY","SYSTEM","VICTORIA_LOGS","VICTORIA_METRICS","VICTORIA_TRACES"],"type":"string"},"lookback_seconds":{"enum":[60,300,900],"type":"integer"}},"id":"host.bounded-log-window.v1","required":["log_source_id","lookback_seconds"]},{"fields":{"sample_window_seconds":{"enum":[5,15,30],"type":"integer"}},"id":"host.cpu-memory-snapshot.v1","required":["sample_window_seconds"]},{"fields":{"filesystem_scope":{"enum":["ALL_FIXED","LOCAL"],"type":"string"}},"id":"host.disk-usage.v1","required":["filesystem_scope"]},{"fields":{"address_family":{"enum":["BOTH","IPV4","IPV6"],"type":"string"}},"id":"host.network-listeners.v1","required":["address_family"]},{"fields":{},"id":"host.system-info.v1","required":[]},{"fields":{"unit_id":{"enum":["AWX","KEYCLOAK","POSTGRESQL","VICTORIA_LOGS","VICTORIA_METRICS","VICTORIA_TRACES"],"type":"string"}},"id":"host.systemd-status.v1","required":["unit_id"]},{"fields":{"service_id":{"enum":["AWX","KEYCLOAK","POSTGRESQL","VICTORIA_LOGS","VICTORIA_METRICS","VICTORIA_TRACES"],"type":"string"}},"id":"host.windows-service-status.v1","required":["service_id"]}],"canonical":"RFC8785","kind":"closed-object-union","selector":"probe_id","version":"host-diagnostic-input.v1"}
{"branches":[{"allow_truncated":true,"fields":{"event_ref":{"classification":"HMAC_EXECUTION","max_bytes":64,"min_bytes":64,"pattern":"^[a-f0-9]{64}$","type":"string"},"message":{"classification":"DLP_TEXT","max_bytes":4096,"min_bytes":1,"type":"string"},"observed_at":{"format":"rfc3339nano-utc","max_bytes":35,"min_bytes":20,"type":"string"},"severity":{"enum":["DEBUG","ERROR","FATAL","INFO","NOTICE","TRACE","UNKNOWN","WARN"],"type":"string"},"source_id":{"enum":["AWX","KEYCLOAK","KERNEL","POSTGRESQL","SECURITY","SYSTEM","VICTORIA_LOGS","VICTORIA_METRICS","VICTORIA_TRACES"],"type":"string"}},"id":"host.bounded-log-window.v1","invariants":["source_id=input.log_source_id"],"item_order":["observed_at:ASC","event_ref:ASC_C"],"max_bytes":262144,"max_items":200,"min_items":0,"required":["event_ref","message","observed_at","severity","source_id"],"unique_by":["event_ref"]},{"allow_truncated":false,"fields":{"cpu_busy_basis_points":{"maximum":10000,"minimum":0,"type":"integer"},"memory_available_bytes":{"maximum":9007199254740991,"minimum":0,"type":"integer"},"memory_total_bytes":{"maximum":9007199254740991,"minimum":0,"type":"integer"}},"id":"host.cpu-memory-snapshot.v1","invariants":["memory_available_bytes<=memory_total_bytes"],"item_order":[],"max_bytes":8192,"max_items":1,"min_items":1,"required":["cpu_busy_basis_points","memory_available_bytes","memory_total_bytes"],"unique_by":[]},{"allow_truncated":true,"fields":{"filesystem_class":{"enum":["DATA","OTHER","ROOT","SYSTEM"],"type":"string"},"filesystem_ref":{"classification":"HMAC_EXECUTION","max_bytes":64,"min_bytes":64,"pattern":"^[a-f0-9]{64}$","type":"string"},"total_bytes":{"maximum":9007199254740991,"minimum":0,"type":"integer"},"used_basis_points":{"maximum":10000,"minimum":0,"type":"integer"},"used_bytes":{"maximum":9007199254740991,"minimum":0,"type":"integer"}},"id":"host.disk-usage.v1","invariants":["used_bytes<=total_bytes","used_basis_points=ratio_basis_points(used_bytes,total_bytes)"],"item_order":["filesystem_ref:ASC_C"],"max_bytes":65536,"max_items":64,"min_items":1,"required":["filesystem_class","filesystem_ref","total_bytes","used_basis_points","used_bytes"],"unique_by":["filesystem_ref"]},{"allow_truncated":true,"fields":{"address_family":{"enum":["IPV4","IPV6"],"type":"string"},"bind_scope":{"enum":["ANY","LOOPBACK","PRIVATE","PUBLIC","UNSPECIFIED"],"type":"string"},"endpoint_ref":{"classification":"HMAC_EXECUTION","max_bytes":64,"min_bytes":64,"pattern":"^[a-f0-9]{64}$","type":"string"},"port":{"maximum":65535,"minimum":1,"type":"integer"},"protocol":{"enum":["TCP","UDP"],"type":"string"}},"id":"host.network-listeners.v1","invariants":["input.address_family=BOTH or address_family=input.address_family"],"item_order":["address_family:ASC_C","endpoint_ref:ASC_C","port:ASC","protocol:ASC_C"],"max_bytes":131072,"max_items":128,"min_items":0,"required":["address_family","bind_scope","endpoint_ref","port","protocol"],"unique_by":["endpoint_ref","port","protocol"]},{"allow_truncated":false,"fields":{"architecture":{"enum":["AMD64","ARM64"],"type":"string"},"os_family":{"enum":["LINUX","WINDOWS"],"type":"string"},"os_version_family":{"max_bytes":32,"min_bytes":1,"pattern":"^[A-Z0-9][A-Z0-9._-]{0,31}$","type":"string"}},"id":"host.system-info.v1","invariants":[],"item_order":[],"max_bytes":8192,"max_items":1,"min_items":1,"required":["architecture","os_family","os_version_family"],"unique_by":[]},{"allow_truncated":false,"fields":{"active_state":{"enum":["ACTIVE","ACTIVATING","DEACTIVATING","FAILED","INACTIVE","RELOADING","UNKNOWN"],"type":"string"},"enabled_state":{"enum":["DISABLED","ENABLED","GENERATED","MASKED","STATIC","TRANSIENT","UNKNOWN"],"type":"string"},"sub_state":{"enum":["FAILED","OTHER","RUNNING","STOPPED","UNKNOWN"],"type":"string"},"unit_id":{"enum":["AWX","KEYCLOAK","POSTGRESQL","VICTORIA_LOGS","VICTORIA_METRICS","VICTORIA_TRACES"],"type":"string"}},"id":"host.systemd-status.v1","invariants":["unit_id=input.unit_id"],"item_order":[],"max_bytes":8192,"max_items":1,"min_items":1,"required":["active_state","enabled_state","sub_state","unit_id"],"unique_by":[]},{"allow_truncated":false,"fields":{"service_id":{"enum":["AWX","KEYCLOAK","POSTGRESQL","VICTORIA_LOGS","VICTORIA_METRICS","VICTORIA_TRACES"],"type":"string"},"start_type":{"enum":["AUTO","BOOT","DEMAND","DISABLED","SYSTEM","UNKNOWN"],"type":"string"},"state":{"enum":["CONTINUE_PENDING","PAUSE_PENDING","PAUSED","RUNNING","START_PENDING","STOPPED","STOP_PENDING","UNKNOWN"],"type":"string"},"status":{"enum":["DEGRADED","ERROR","OK","UNKNOWN"],"type":"string"}},"id":"host.windows-service-status.v1","invariants":["service_id=input.service_id"],"item_order":[],"max_bytes":8192,"max_items":1,"min_items":1,"required":["service_id","start_type","state","status"],"unique_by":[]}],"canonical":"RFC8785","kind":"closed-item-union","selector":"probe_id","version":"host-diagnostic-evidence.v1"}
{"branches":[{"fields":{"log_source_id":{"enum":["AWX","KEYCLOAK","KERNEL","POSTGRESQL","SECURITY","SYSTEM","VICTORIA_LOGS","VICTORIA_METRICS","VICTORIA_TRACES"],"type":"string"},"lookback_seconds":{"enum":[60,300,900],"type":"integer"}},"id":"host.bounded-log-window.v1","required":["log_source_id","lookback_seconds"]},{"fields":{"sample_window_seconds":{"enum":[5,15,30],"type":"integer"}},"id":"host.cpu-memory-snapshot.v1","required":["sample_window_seconds"]},{"fields":{"filesystem_scope":{"enum":["ALL_FIXED","LOCAL"],"type":"string"}},"id":"host.disk-usage.v1","required":["filesystem_scope"]},{"fields":{"address_family":{"enum":["BOTH","IPV4","IPV6"],"type":"string"}},"id":"host.network-listeners.v1","required":["address_family"]},{"fields":{},"id":"host.system-info.v1","required":[]},{"fields":{"unit_id":{"enum":["AWX","KEYCLOAK","POSTGRESQL","VICTORIA_LOGS","VICTORIA_METRICS","VICTORIA_TRACES"],"type":"string"}},"id":"host.systemd-status.v1","required":["unit_id"]},{"fields":{"service_id":{"enum":["AWX","KEYCLOAK","POSTGRESQL","VICTORIA_LOGS","VICTORIA_METRICS","VICTORIA_TRACES"],"type":"string"}},"id":"host.windows-service-status.v1","required":["service_id"]}],"canonical":"RFC8785","common_fields":{"attestation_nonce":{"max_bytes":64,"min_bytes":64,"pattern":"^[a-f0-9]{64}$","type":"string"},"diagnostic_schema_version":{"const":"host-diagnostic.v1","type":"string"},"expected_host_binding_digest":{"max_bytes":64,"min_bytes":64,"pattern":"^[a-f0-9]{64}$","type":"string"},"expected_host_id":{"maximum":9007199254740991,"minimum":1,"type":"integer"},"expected_identity_attestation_digest":{"max_bytes":64,"min_bytes":64,"pattern":"^[a-f0-9]{64}$","type":"string"},"expected_identity_key_sha256":{"max_bytes":64,"min_bytes":64,"pattern":"^[a-f0-9]{64}$","type":"string"},"input_hash":{"max_bytes":64,"min_bytes":64,"pattern":"^[a-f0-9]{64}$","type":"string"},"probe_id":{"enum":["host.bounded-log-window.v1","host.cpu-memory-snapshot.v1","host.disk-usage.v1","host.network-listeners.v1","host.system-info.v1","host.systemd-status.v1","host.windows-service-status.v1"],"type":"string"}},"common_required":["attestation_nonce","diagnostic_schema_version","expected_host_binding_digest","expected_host_id","expected_identity_attestation_digest","expected_identity_key_sha256","input_hash","probe_id"],"kind":"closed-object-union","selector":"probe_id","value_origin":"server-only","version":"awx-diagnostic-extra-vars.v1"}
{"branches":[{"allow_truncated":true,"fields":{"items":{"item_schema_branch":"host.bounded-log-window.v1","max_items":200,"min_items":0,"type":"array"}},"id":"host.bounded-log-window.v1","max_bytes":262144,"required":["items"]},{"allow_truncated":false,"fields":{"items":{"item_schema_branch":"host.cpu-memory-snapshot.v1","max_items":1,"min_items":1,"type":"array"}},"id":"host.cpu-memory-snapshot.v1","max_bytes":8192,"required":["items"]},{"allow_truncated":true,"fields":{"items":{"item_schema_branch":"host.disk-usage.v1","max_items":64,"min_items":1,"type":"array"}},"id":"host.disk-usage.v1","max_bytes":65536,"required":["items"]},{"allow_truncated":true,"fields":{"items":{"item_schema_branch":"host.network-listeners.v1","max_items":128,"min_items":0,"type":"array"}},"id":"host.network-listeners.v1","max_bytes":131072,"required":["items"]},{"allow_truncated":false,"fields":{"items":{"item_schema_branch":"host.system-info.v1","max_items":1,"min_items":1,"type":"array"}},"id":"host.system-info.v1","max_bytes":8192,"required":["items"]},{"allow_truncated":false,"fields":{"items":{"item_schema_branch":"host.systemd-status.v1","max_items":1,"min_items":1,"type":"array"}},"id":"host.systemd-status.v1","max_bytes":8192,"required":["items"]},{"allow_truncated":false,"fields":{"items":{"item_schema_branch":"host.windows-service-status.v1","max_items":1,"min_items":1,"type":"array"}},"id":"host.windows-service-status.v1","max_bytes":8192,"required":["items"]}],"canonical":"RFC8785","common_fields":{"attestation_nonce":{"max_bytes":64,"min_bytes":64,"pattern":"^[a-f0-9]{64}$","type":"string"},"collected_at":{"format":"rfc3339nano-utc","max_bytes":35,"min_bytes":20,"type":"string"},"host_binding_digest":{"max_bytes":64,"min_bytes":64,"pattern":"^[a-f0-9]{64}$","type":"string"},"host_id":{"maximum":9007199254740991,"minimum":1,"type":"integer"},"identity_algorithm":{"const":"ED25519_HOST_ATTESTATION_V1","type":"string"},"identity_attestation_digest":{"max_bytes":64,"min_bytes":64,"pattern":"^[a-f0-9]{64}$","type":"string"},"identity_key_sha256":{"max_bytes":64,"min_bytes":64,"pattern":"^[a-f0-9]{64}$","type":"string"},"identity_signature":{"max_bytes":128,"min_bytes":128,"pattern":"^[a-f0-9]{128}$","type":"string"},"input_hash":{"max_bytes":64,"min_bytes":64,"pattern":"^[a-f0-9]{64}$","type":"string"},"probe_id":{"enum":["host.bounded-log-window.v1","host.cpu-memory-snapshot.v1","host.disk-usage.v1","host.network-listeners.v1","host.system-info.v1","host.systemd-status.v1","host.windows-service-status.v1"],"type":"string"},"schema_version":{"const":"host-diagnostic.v1","type":"string"},"truncated":{"type":"boolean"}},"common_required":["attestation_nonce","collected_at","host_binding_digest","host_id","identity_algorithm","identity_attestation_digest","identity_key_sha256","identity_signature","input_hash","probe_id","schema_version","truncated"],"evidence_schema_sha256":"9ba1f395ebe0d9c3fc51e5a8a0d474d59801fbc8b51241d8c581de1ba558372a","evidence_schema_version":"host-diagnostic-evidence.v1","kind":"closed-object-union","selector":"probe_id","source":"event_data.res.host_diagnostic_v1","version":"awx-diagnostic-output-projection.v1"}
{"branches":[{"fields":{"state":{"enum":["ACTIVE","ALL","IDLE","WAITING"],"type":"string"}},"id":"postgres.connection-snapshot.v1","required":["state"]},{"fields":{"database_scope":{"enum":["CURRENT","PUBLISHED"],"type":"string"}},"id":"postgres.database-size.v1","required":["database_scope"]},{"fields":{"minimum_wait_seconds":{"enum":[0,1,5,15],"type":"integer"}},"id":"postgres.lock-snapshot.v1","required":["minimum_wait_seconds"]},{"fields":{"replication_scope":{"enum":["ALL","SENDER","SLOT"],"type":"string"}},"id":"postgres.replication-snapshot.v1","required":["replication_scope"]},{"fields":{},"id":"postgres.server-health.v1","required":[]},{"fields":{"minimum_calls":{"enum":[10,100,1000],"type":"integer"},"top_n":{"enum":[5,10,20],"type":"integer"}},"id":"postgres.slow-query-summary.v1","required":["minimum_calls","top_n"]}],"canonical":"RFC8785","kind":"closed-object-union","selector":"query_id","version":"postgres-diagnostic-input.v1"}
{"branches":[{"column_order":["state_bucket","connection_count"],"fields":{"connection_count":{"maximum":9007199254740991,"minimum":1,"pg_type":"int8","type":"integer"},"state_bucket":{"enum":["ACTIVE","IDLE","OTHER","WAITING"],"pg_type":"text","type":"string"}},"id":"postgres.connection-snapshot.v1","invariants":["input.state=ALL or state_bucket=input.state"],"max_bytes":16384,"max_rows":4,"min_rows":0,"required":["connection_count","state_bucket"],"row_order":["state_bucket:ASC_C"],"unique_by":["state_bucket"]},{"column_order":["database_ordinal","size_bucket","size_bytes"],"fields":{"database_ordinal":{"maximum":64,"minimum":1,"pg_type":"int8","type":"integer"},"size_bucket":{"enum":["GTE_100_GIB","LT_100_GIB","LT_10_GIB","LT_1_GIB"],"pg_type":"text","type":"string"},"size_bytes":{"maximum":9007199254740991,"minimum":0,"pg_type":"int8","type":"integer"}},"id":"postgres.database-size.v1","invariants":["size_bucket=size_bucket_for_bytes(size_bytes)"],"max_bytes":32768,"max_rows":64,"min_rows":1,"required":["database_ordinal","size_bucket","size_bytes"],"row_order":["database_ordinal:ASC"],"unique_by":["database_ordinal"]},{"column_order":["lock_type","lock_mode","granted","wait_bucket","lock_count"],"fields":{"granted":{"pg_type":"bool","type":"boolean"},"lock_count":{"maximum":9007199254740991,"minimum":1,"pg_type":"int8","type":"integer"},"lock_mode":{"enum":["AccessExclusiveLock","AccessShareLock","ExclusiveLock","RowExclusiveLock","RowShareLock","SIReadLock","ShareLock","ShareRowExclusiveLock","ShareUpdateExclusiveLock"],"pg_type":"text","type":"string"},"lock_type":{"enum":["advisory","applytransaction","extend","frozenid","object","page","relation","spectoken","transactionid","tuple","userlock","virtualxid"],"pg_type":"text","type":"string"},"wait_bucket":{"enum":["GRANTED","GTE_30S","LT_30S","LT_5S"],"pg_type":"text","type":"string"}},"id":"postgres.lock-snapshot.v1","invariants":["granted=(wait_bucket=GRANTED)"],"max_bytes":131072,"max_rows":200,"min_rows":0,"required":["granted","lock_count","lock_mode","lock_type","wait_bucket"],"row_order":["lock_type:ASC_C","lock_mode:ASC_C","granted:ASC","wait_bucket:ASC_C"],"unique_by":["lock_type","lock_mode","granted","wait_bucket"]},{"column_order":["source_kind","state_bucket","lag_bucket","item_count"],"fields":{"item_count":{"maximum":9007199254740991,"minimum":1,"pg_type":"int8","type":"integer"},"lag_bucket":{"enum":["GTE_10S","LT_10S","LT_1S","NOT_APPLICABLE","UNKNOWN"],"pg_type":"text","type":"string"},"source_kind":{"enum":["SENDER","SLOT"],"pg_type":"text","type":"string"},"state_bucket":{"enum":["ACTIVE","BACKUP","CATCHUP","INACTIVE","OTHER","STARTUP","STREAMING"],"pg_type":"text","type":"string"}},"id":"postgres.replication-snapshot.v1","invariants":["input.replication_scope=ALL or source_kind=input.replication_scope","source_kind=SLOT iff lag_bucket=NOT_APPLICABLE"],"max_bytes":65536,"max_rows":22,"min_rows":0,"required":["item_count","lag_bucket","source_kind","state_bucket"],"row_order":["source_kind:ASC_C","state_bucket:ASC_C","lag_bucket:ASC_C"],"unique_by":["source_kind","state_bucket","lag_bucket"]},{"column_order":["server_version_num","in_recovery","transaction_read_only","uptime_bucket"],"fields":{"in_recovery":{"pg_type":"bool","type":"boolean"},"server_version_num":{"maximum":999999,"minimum":90000,"pg_type":"int4","type":"integer"},"transaction_read_only":{"pg_type":"bool","type":"boolean"},"uptime_bucket":{"enum":["GTE_7D","LT_1D","LT_1H","LT_7D"],"pg_type":"text","type":"string"}},"id":"postgres.server-health.v1","invariants":[],"max_bytes":8192,"max_rows":1,"min_rows":1,"required":["in_recovery","server_version_num","transaction_read_only","uptime_bucket"],"row_order":[],"unique_by":[]},{"column_order":["query_fingerprint_source","calls","mean_time_bucket","total_exec_ms"],"fields":{"calls":{"maximum":9007199254740991,"minimum":10,"pg_type":"int8","type":"integer"},"mean_time_bucket":{"enum":["GTE_1S","LT_100MS","LT_10MS","LT_1S"],"pg_type":"text","type":"string"},"query_fingerprint_source":{"classification":"HMAC_SCOPE_IMMEDIATE","max_bytes":20,"min_bytes":1,"pattern":"^-?(0|[1-9][0-9]{0,18})$","pg_type":"text","type":"string"},"total_exec_ms":{"maximum":9007199254740991,"minimum":0,"pg_type":"numeric","scale":3,"type":"decimal"}},"id":"postgres.slow-query-summary.v1","invariants":["calls>=input.minimum_calls","row_count<=input.top_n"],"max_bytes":131072,"max_rows":20,"min_rows":0,"required":["calls","mean_time_bucket","query_fingerprint_source","total_exec_ms"],"row_order":["total_exec_ms:DESC","query_fingerprint_source:ASC_INT64"],"unique_by":["query_fingerprint_source"]}],"canonical":"RFC8785","kind":"closed-row-union","selector":"query_id","version":"postgres-diagnostic-result.v1"}
{"branches":[{"column_order":["state_bucket","connection_count"],"fields":{"connection_count":{"maximum":9007199254740991,"minimum":1,"pg_type":"int8","type":"integer"},"state_bucket":{"enum":["ACTIVE","IDLE","OTHER","WAITING"],"pg_type":"text","type":"string"}},"id":"postgres.connection-snapshot.v1","invariants":["input.state=ALL or state_bucket=input.state"],"max_bytes":16384,"max_rows":4,"min_rows":0,"required":["connection_count","state_bucket"],"row_order":["state_bucket:ASC_C"],"unique_by":["state_bucket"]},{"column_order":["database_ref","size_bucket","size_bytes"],"fields":{"database_ref":{"pattern":"^(CURRENT|PUBLISHED_(0[1-9]|[1-5][0-9]|6[0-4]))$","type":"string"},"size_bucket":{"enum":["GTE_100_GIB","LT_100_GIB","LT_10_GIB","LT_1_GIB"],"pg_type":"text","type":"string"},"size_bytes":{"maximum":9007199254740991,"minimum":0,"pg_type":"int8","type":"integer"}},"id":"postgres.database-size.v1","invariants":["size_bucket=size_bucket_for_bytes(size_bytes)"],"max_bytes":32768,"max_rows":64,"min_rows":1,"required":["database_ref","size_bucket","size_bytes"],"row_order":["database_ref:ASC_C"],"unique_by":["database_ref"]},{"column_order":["lock_type","lock_mode","granted","wait_bucket","lock_count"],"fields":{"granted":{"pg_type":"bool","type":"boolean"},"lock_count":{"maximum":9007199254740991,"minimum":1,"pg_type":"int8","type":"integer"},"lock_mode":{"enum":["AccessExclusiveLock","AccessShareLock","ExclusiveLock","RowExclusiveLock","RowShareLock","SIReadLock","ShareLock","ShareRowExclusiveLock","ShareUpdateExclusiveLock"],"pg_type":"text","type":"string"},"lock_type":{"enum":["advisory","applytransaction","extend","frozenid","object","page","relation","spectoken","transactionid","tuple","userlock","virtualxid"],"pg_type":"text","type":"string"},"wait_bucket":{"enum":["GRANTED","GTE_30S","LT_30S","LT_5S"],"pg_type":"text","type":"string"}},"id":"postgres.lock-snapshot.v1","invariants":["granted=(wait_bucket=GRANTED)"],"max_bytes":131072,"max_rows":200,"min_rows":0,"required":["granted","lock_count","lock_mode","lock_type","wait_bucket"],"row_order":["lock_type:ASC_C","lock_mode:ASC_C","granted:ASC","wait_bucket:ASC_C"],"unique_by":["lock_type","lock_mode","granted","wait_bucket"]},{"column_order":["source_kind","state_bucket","lag_bucket","item_count"],"fields":{"item_count":{"maximum":9007199254740991,"minimum":1,"pg_type":"int8","type":"integer"},"lag_bucket":{"enum":["GTE_10S","LT_10S","LT_1S","NOT_APPLICABLE","UNKNOWN"],"pg_type":"text","type":"string"},"source_kind":{"enum":["SENDER","SLOT"],"pg_type":"text","type":"string"},"state_bucket":{"enum":["ACTIVE","BACKUP","CATCHUP","INACTIVE","OTHER","STARTUP","STREAMING"],"pg_type":"text","type":"string"}},"id":"postgres.replication-snapshot.v1","invariants":["input.replication_scope=ALL or source_kind=input.replication_scope","source_kind=SLOT iff lag_bucket=NOT_APPLICABLE"],"max_bytes":65536,"max_rows":22,"min_rows":0,"required":["item_count","lag_bucket","source_kind","state_bucket"],"row_order":["source_kind:ASC_C","state_bucket:ASC_C","lag_bucket:ASC_C"],"unique_by":["source_kind","state_bucket","lag_bucket"]},{"column_order":["server_version_num","in_recovery","transaction_read_only","uptime_bucket"],"fields":{"in_recovery":{"pg_type":"bool","type":"boolean"},"server_version_num":{"maximum":999999,"minimum":90000,"pg_type":"int4","type":"integer"},"transaction_read_only":{"pg_type":"bool","type":"boolean"},"uptime_bucket":{"enum":["GTE_7D","LT_1D","LT_1H","LT_7D"],"pg_type":"text","type":"string"}},"id":"postgres.server-health.v1","invariants":[],"max_bytes":8192,"max_rows":1,"min_rows":1,"required":["in_recovery","server_version_num","transaction_read_only","uptime_bucket"],"row_order":[],"unique_by":[]},{"column_order":["query_fingerprint","calls","mean_time_bucket","total_exec_ms"],"fields":{"calls":{"maximum":9007199254740991,"minimum":10,"pg_type":"int8","type":"integer"},"mean_time_bucket":{"enum":["GTE_1S","LT_100MS","LT_10MS","LT_1S"],"pg_type":"text","type":"string"},"query_fingerprint":{"classification":"HMAC_SCOPE","max_bytes":64,"min_bytes":64,"pattern":"^[a-f0-9]{64}$","type":"string"},"total_exec_ms":{"maximum":9007199254740991,"minimum":0,"pg_type":"numeric","scale":3,"type":"decimal"}},"id":"postgres.slow-query-summary.v1","invariants":["calls>=input.minimum_calls","row_count<=input.top_n"],"max_bytes":131072,"max_rows":20,"min_rows":0,"required":["calls","mean_time_bucket","query_fingerprint","total_exec_ms"],"row_order":["total_exec_ms:DESC","query_fingerprint:ASC_C"],"unique_by":["query_fingerprint"]}],"canonical":"RFC8785","kind":"closed-row-union","projection_order":["STRICT_ROW","HMAC_SCOPE","DATABASE_ALIAS","DLP","CANONICAL_SORT","FINAL_SCHEMA"],"result_schema_sha256":"108d651d7a776b815045089e5e7dcb05b7536cb3c38f6182fac292665ae6e42e","selector":"query_id","version":"postgres-diagnostic-evidence.v1"}
~~~
Static columns must byte-equal their exact fixture；migration uses a closed table/provider/capability/probe-or-query CASE，never a generic schema interpreter。Closed means exact keys、no NULL/unknown，duplicate-aware one-value UTF-8/NFC decode，canonical integer/decimal and typed reconstruction；capability mapping、budgets、column OID/order、sort/unique/invariants and every cross-schema SHA are rechecked。The signed Host Probe and signed AWX module each generate a fresh 256-bit per-execution HMAC key inside their trusted local execution boundary；the key is never accepted as input、serialized、exported or logged and is destroyed after final projection。They collect raw endpoint/path/event references only into process-local buffers，perform `HMAC_EXECUTION`、closed enum mapping、DLP allowlist/redaction、canonical sort and final `host-diagnostic-evidence.v1` validation **before** constructing any Runner/provider result。Raw references or unredacted messages never enter AWX `event_data`、Runner/Gateway/Task/Evidence/Audit or logs；the playbook emits only the final safe `event_data.res.host_diagnostic_v1` projection，and Gateway merely revalidates exact schema/hash/budget/canaries without raw transformation。PostgreSQL `postgres-diagnostic-result.v1` likewise exists only inside the trusted Runner process；before any boundary crossing the executor uses its non-payload sealed HMAC handle、maps database ordinal to safe alias、applies DLP/sort and requires `postgres-diagnostic-evidence.v1`，so only final Evidence reaches Gateway。Go fixtures deep-copy and exact bytes/hash/transformation/migration-literal tests reject one-field/order/key drift and canaries prove raw values never reach an outbound payload even on failure。
AWX identity is the content-addressed private `AWX_HOST_IDENTITY_BINDINGS` artifact，not duplicated contract bytes。`awx_read_template_revisions` persists only its SHA、root digest and `1..10000` count；the pinned server resolver loads by exact Runtime+hash and projects one six-field Host binding in memory。The exact bootstrap authority、two enrollment tables、two-template fingerprint bundle、single-Host Job/credential protocol、strict output/fact keys and caps、signature challenges、Job summary、identity/Host/artifact digests、64 MiB artifact cap、N/N+1 seal/rollout、rotation and crash recovery are normatively and exclusively defined by `docs/contracts/awx-host-identity-enrollment-v1.md`。Before diagnostic launch the executor refreshes Host/Inventory，supplies nonce/expected Host/binding/key/attestation，and the fixed local attestor signs `FramedTupleV1("awx-host-diagnostic-challenge.v1",nonce,host_binding_digest,host_id,input_hash,probe_id)`；missing/revoked/rebound/cloned/extra Host or snapshot drift yields no Evidence and closes only that Asset capability。

同一 trigger 以 `FramedTupleV1` 和 raw content SHA 重算三类 caller-independent digest：`host-probe-contract.v1` frames Scope、contract/Capability/Provider/probe、input+evidence schema versions and raw SHAs、budgets/status；`awx-read-template.v1` frames Scope、contract/Capability/Provider、safe-range inventory/template IDs、raw diagnostic fingerprint-manifest SHA/digest、raw identity-artifact SHA/root/count、extra-vars/output JSON SHAs、budgets/status；`postgres-diagnostic-query.v1` frames Scope、contract/Capability/Provider/query ID、input+result+evidence schema versions and raw SHAs、raw query SHA、timeouts/limits/required-extension-or-NULL/status。Actor/time stay outside。`diagnostic_execution_receipt_reference_guard()` recomputes replay-stable `diagnostic-execution-receipt.v1` over T/W/E、Investigation/Task/attempt、Asset、Capability id/revision/code、contract kind/id/revision/raw recomputed digest、raw input hash、items/bytes/truncated/DLP/redaction、nullable Evidence id/hash、nullable Runner receipt id plus joined raw receipt hash、nullable credential lease id、cleanup/outcome/failure；it excludes new Receipt/Audit IDs and created time，while Audit guard requires resource/payload hash without a cycle。Named hashes are raw 32-byte frames；tests mutate every frame and the AWX same-template seven-Capability positive set、same-Capability duplicate/N+1 concurrent publication uniqueness。

AWX remote fingerprints are separate from local contract digests。`AWX_READ_TEMPLATE_FINGERPRINT` is the exact strict `awx-read-template-fingerprint-bundle.v1` envelope defined by `docs/contracts/awx-host-identity-enrollment-v1.md`，with distinct enrollment and diagnostic manifests/digests but one content-addressed artifact。Each branch freezes every AWX 24.6.1 execution field、all sixteen prompt flags、survey/stored defaults/preview/body/result/RBAC and signed module closure；only `ask_limit=true`。Package 02 bootstrap Runtime publishes mapping only；after Source discovery，package 04's release-authorized enrollment Operation first persists/cleans a GET-only bundle verification，then seals that bundle and identity artifact into a `PENDING` successor。The Source hook continues to consume only mapping；diagnostic Publisher later projects only the diagnostic branch from exact APPLIED successor plus identity root。Any omitted/default/cross-purpose/drifted field closes the exact operation before remote work or Evidence；package 08 attests bundle、both branch digests、identity root and contract digest。

- [ ] **Step 4: 实现凭据与 Receipt 事实表**

~~~sql
CREATE TABLE read_credential_leases (
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  environment_id uuid NOT NULL,
  id uuid NOT NULL,
  investigation_id uuid NOT NULL,
  task_id uuid NOT NULL,
  attempt_epoch bigint NOT NULL CHECK (attempt_epoch > 0),
  asset_id uuid NOT NULL,
  capability_definition_id uuid NOT NULL,
  capability_definition_revision bigint NOT NULL,
  target_id uuid NOT NULL,
  runtime_publication_id uuid NOT NULL,
  runner_realm_id uuid NOT NULL,
  grant_id uuid NOT NULL,
  issuer_id text NOT NULL CHECK (octet_length(issuer_id) BETWEEN 1 AND 128),
  issuer_revision text NOT NULL CHECK (octet_length(issuer_revision) BETWEEN 1 AND 128),
  usage_role text NOT NULL CHECK (usage_role IN ('READ_AUTOMATION','READ_DATABASE')),
  issue_claim_token_sha256 text CHECK (issue_claim_token_sha256 IS NULL OR issue_claim_token_sha256 ~ '^[a-f0-9]{64}$'),
  issue_claim_expires_at timestamptz,
  issue_started_at timestamptz,
  issue_request_digest text CHECK (issue_request_digest IS NULL OR issue_request_digest ~ '^[a-f0-9]{64}$'),
  issue_correlation_ref text CHECK (issue_correlation_ref IS NULL OR public.asset_catalog_opaque_reference_valid(issue_correlation_ref)),
  accessor_ciphertext bytea,
  accessor_key_id text CHECK (accessor_key_id IS NULL OR octet_length(accessor_key_id) BETWEEN 1 AND 128),
  accessor_hmac text CHECK (accessor_hmac IS NULL OR accessor_hmac ~ '^[a-f0-9]{64}$'),
  issued_at timestamptz,
  requested_expires_at timestamptz NOT NULL,
  expires_at timestamptz,
  cleanup_state text NOT NULL CHECK (cleanup_state IN (
    'NOT_ISSUED','ISSUING','ISSUED','CLEANUP_PENDING','CLEANUP_CLAIMED',
    'REVOKED','NO_CREDENTIAL','UNCERTAIN','MANUAL_REQUIRED'
  )),
  cleanup_reason text CHECK (cleanup_reason IS NULL OR cleanup_reason IN (
    'COMPLETE','CANCEL','TIMEOUT','RUNNER_CRASH','GATEWAY_CRASH','ISSUE_FAILED'
  )),
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, workspace_id, environment_id, id),
  UNIQUE (tenant_id, workspace_id, environment_id,
          investigation_id, task_id, attempt_epoch),
  UNIQUE (tenant_id, workspace_id, environment_id, id,
          investigation_id, task_id, attempt_epoch),
  CHECK ((accessor_ciphertext IS NULL AND accessor_key_id IS NULL AND accessor_hmac IS NULL)
      OR (accessor_ciphertext IS NOT NULL AND accessor_key_id IS NOT NULL AND accessor_hmac IS NOT NULL)),
  CHECK ((cleanup_state = 'NOT_ISSUED' AND accessor_ciphertext IS NULL
          AND issued_at IS NULL AND expires_at IS NULL AND cleanup_reason IS NULL
          AND issue_claim_token_sha256 IS NULL AND issue_claim_expires_at IS NULL
          AND issue_started_at IS NULL AND issue_request_digest IS NULL AND issue_correlation_ref IS NULL)
      OR (cleanup_state = 'ISSUING' AND accessor_ciphertext IS NULL
          AND issued_at IS NULL AND expires_at IS NULL
          AND issue_claim_token_sha256 IS NOT NULL AND issue_claim_expires_at IS NOT NULL
          AND ((issue_started_at IS NULL AND issue_request_digest IS NULL AND issue_correlation_ref IS NULL)
            OR (issue_started_at IS NOT NULL AND issue_request_digest IS NOT NULL AND issue_correlation_ref IS NOT NULL)))
      OR (cleanup_state IN ('ISSUED','CLEANUP_PENDING','CLEANUP_CLAIMED','REVOKED')
          AND issue_claim_token_sha256 IS NULL AND issue_claim_expires_at IS NULL
          AND accessor_ciphertext IS NOT NULL AND issued_at IS NOT NULL AND expires_at IS NOT NULL
          AND issue_started_at IS NOT NULL AND issue_request_digest IS NOT NULL AND issue_correlation_ref IS NOT NULL)
      OR (cleanup_state IN ('NO_CREDENTIAL','UNCERTAIN','MANUAL_REQUIRED')
          AND issue_claim_token_sha256 IS NULL AND issue_claim_expires_at IS NULL
          AND issue_started_at IS NOT NULL AND issue_request_digest IS NOT NULL AND issue_correlation_ref IS NOT NULL
          AND ((accessor_ciphertext IS NULL AND issued_at IS NULL AND expires_at IS NULL)
            OR (accessor_ciphertext IS NOT NULL AND issued_at IS NOT NULL AND expires_at IS NOT NULL)))),
  CHECK ((cleanup_state IN ('NOT_ISSUED','ISSUING','ISSUED') AND cleanup_reason IS NULL)
      OR (cleanup_state NOT IN ('NOT_ISSUED','ISSUING','ISSUED') AND cleanup_reason IS NOT NULL)),
  CHECK (requested_expires_at > created_at),
  CHECK (expires_at IS NULL OR (expires_at > created_at AND expires_at <= requested_expires_at)),
  FOREIGN KEY (tenant_id, workspace_id, environment_id,
               investigation_id, task_id, attempt_epoch)
    REFERENCES investigation_task_attempts
      (tenant_id, workspace_id, environment_id,
       investigation_id, task_id, lease_epoch),
  FOREIGN KEY (tenant_id, workspace_id, environment_id, asset_id)
    REFERENCES assets (tenant_id, workspace_id, environment_id, id),
  FOREIGN KEY (tenant_id, workspace_id, environment_id,
               capability_definition_id, capability_definition_revision)
    REFERENCES capability_definitions
      (tenant_id, workspace_id, environment_id, id, revision),
  FOREIGN KEY (tenant_id, workspace_id, environment_id, target_id)
    REFERENCES published_targets
      (tenant_id, workspace_id, environment_id, id),
  FOREIGN KEY (tenant_id, workspace_id, environment_id, runtime_publication_id)
    REFERENCES runtime_publications
      (tenant_id, workspace_id, environment_id, id),
  FOREIGN KEY (tenant_id, workspace_id, environment_id, runner_realm_id)
    REFERENCES runner_realms
      (tenant_id, workspace_id, environment_id, id),
  FOREIGN KEY (tenant_id, workspace_id, environment_id, grant_id)
    REFERENCES investigation_grants (tenant_id, workspace_id, environment_id, id)
);

CREATE TABLE read_credential_cleanup_attempts (
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  environment_id uuid NOT NULL,
  lease_id uuid NOT NULL,
  attempt bigint NOT NULL CHECK (attempt > 0),
  claim_token_sha256 text NOT NULL CHECK (claim_token_sha256 ~ '^[a-f0-9]{64}$'),
  claim_expires_at timestamptz NOT NULL,
  request_started_at timestamptz,
  request_digest text CHECK (request_digest IS NULL OR request_digest ~ '^[a-f0-9]{64}$'),
  state text NOT NULL CHECK (state IN ('CLAIMED','REVOKED','NO_CREDENTIAL','RETRYABLE','UNCERTAIN','MANUAL_REQUIRED')),
  failure_code text CHECK (failure_code IS NULL OR failure_code IN (
    'issuer_unavailable','revoker_unavailable','accessor_unreadable',
    'revoke_timeout','revoke_result_uncertain','recovery_budget_exhausted'
  )),
  started_at timestamptz NOT NULL,
  completed_at timestamptz,
  PRIMARY KEY (tenant_id, workspace_id, environment_id, lease_id, attempt),
  FOREIGN KEY (tenant_id, workspace_id, environment_id, lease_id)
    REFERENCES read_credential_leases (tenant_id, workspace_id, environment_id, id),
  CHECK ((request_started_at IS NULL) = (request_digest IS NULL)),
  CHECK ((state = 'CLAIMED' AND completed_at IS NULL AND failure_code IS NULL)
      OR (state IN ('REVOKED','NO_CREDENTIAL') AND completed_at IS NOT NULL AND failure_code IS NULL
          AND request_started_at IS NOT NULL)
      OR (state = 'RETRYABLE' AND completed_at IS NOT NULL AND failure_code IS NOT NULL
          AND request_started_at IS NULL)
      OR (state IN ('UNCERTAIN','MANUAL_REQUIRED') AND completed_at IS NOT NULL AND failure_code IS NOT NULL
          AND request_started_at IS NOT NULL)),
  CHECK (request_started_at IS NULL OR request_started_at >= started_at),
  CHECK (completed_at IS NULL OR completed_at >= started_at)
);

CREATE TABLE diagnostic_execution_receipts (
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  environment_id uuid NOT NULL,
  id uuid NOT NULL,
  investigation_id uuid NOT NULL,
  task_id uuid NOT NULL,
  attempt_epoch bigint NOT NULL CHECK (attempt_epoch > 0),
  asset_id uuid NOT NULL,
  capability_definition_id uuid NOT NULL,
  capability_definition_revision bigint NOT NULL CHECK (capability_definition_revision > 0),
  capability_code text NOT NULL CHECK (octet_length(capability_code) BETWEEN 1 AND 96),
  contract_kind text NOT NULL CHECK (contract_kind IN ('HOST_PROBE','AWX_TEMPLATE','POSTGRES_QUERY')),
  contract_id uuid NOT NULL,
  contract_revision bigint NOT NULL CHECK (contract_revision > 0),
  contract_digest text NOT NULL CHECK (contract_digest ~ '^[a-f0-9]{64}$'),
  input_hash text NOT NULL CHECK (input_hash ~ '^[a-f0-9]{64}$'),
  result_items integer NOT NULL CHECK (result_items BETWEEN 0 AND 200),
  result_bytes integer NOT NULL CHECK (result_bytes BETWEEN 0 AND 262144),
  truncated boolean NOT NULL,
  dlp_state text NOT NULL CHECK (dlp_state IN ('PASSED','REDACTED','REJECTED')),
  redaction_count integer NOT NULL CHECK (redaction_count BETWEEN 0 AND 10000),
  evidence_id uuid,
  evidence_content_hash text CHECK (evidence_content_hash IS NULL OR evidence_content_hash ~ '^[a-f0-9]{64}$'),
  runner_receipt_id uuid,
  credential_lease_id uuid,
  cleanup_state text NOT NULL CHECK (cleanup_state IN ('REVOKED','NO_CREDENTIAL','UNCERTAIN','MANUAL_REQUIRED')),
  outcome text NOT NULL CHECK (outcome IN ('SUCCEEDED','FAILED','CANCELLED','TIMED_OUT')),
  failure_code text CHECK (failure_code IS NULL OR failure_code IN (
    'AUTHORIZATION_REVOKED','BUDGET_EXHAUSTED','CAPABILITY_DRIFT','CONTRACT_REJECTED',
    'CREDENTIAL_ISSUE_FAILED','CREDENTIAL_CLEANUP_UNCERTAIN','DLP_REJECTED',
    'EVIDENCE_REJECTED','INPUT_REJECTED','PROVIDER_UNAVAILABLE',
    'PROVIDER_RESPONSE_REJECTED','RESULT_SCHEMA_REJECTED','RUNNER_ATTESTATION_REJECTED',
    'RUNTIME_DRIFT','EXECUTION_CANCELLED','EXECUTION_TIMEOUT','PERSISTENCE_FAILED'
  )),
  audit_record_id uuid NOT NULL,
  receipt_hash text NOT NULL CHECK (receipt_hash ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, workspace_id, environment_id, id),
  UNIQUE (tenant_id, workspace_id, environment_id,
          investigation_id, task_id, attempt_epoch),
  FOREIGN KEY (tenant_id, workspace_id, environment_id,
               investigation_id, task_id, attempt_epoch)
    REFERENCES investigation_task_attempts
      (tenant_id, workspace_id, environment_id,
       investigation_id, task_id, lease_epoch),
  FOREIGN KEY (tenant_id, workspace_id, environment_id, asset_id)
    REFERENCES assets (tenant_id, workspace_id, environment_id, id),
  FOREIGN KEY (tenant_id, workspace_id, environment_id,
               capability_definition_id, capability_definition_revision)
    REFERENCES capability_definitions
      (tenant_id, workspace_id, environment_id, id, revision),
  FOREIGN KEY (tenant_id, workspace_id, investigation_id, task_id,
               evidence_id, evidence_content_hash)
    REFERENCES evidence
      (tenant_id, workspace_id, investigation_id, task_id, id, content_hash),
  FOREIGN KEY (tenant_id, workspace_id, environment_id,
               investigation_id, task_id, attempt_epoch, runner_receipt_id)
    REFERENCES runner_evidence_receipts
      (tenant_id, workspace_id, environment_id,
       investigation_id, task_id, lease_epoch, id),
  FOREIGN KEY (tenant_id, workspace_id, environment_id, credential_lease_id,
               investigation_id, task_id, attempt_epoch)
    REFERENCES read_credential_leases
      (tenant_id, workspace_id, environment_id, id,
       investigation_id, task_id, attempt_epoch),
  FOREIGN KEY (tenant_id, workspace_id, environment_id, audit_record_id)
    REFERENCES audit_records (tenant_id, workspace_id, environment_id, id),
  CHECK ((evidence_id IS NULL) = (evidence_content_hash IS NULL)),
  CHECK ((outcome = 'SUCCEEDED' AND evidence_id IS NOT NULL
          AND evidence_content_hash IS NOT NULL AND runner_receipt_id IS NOT NULL
          AND failure_code IS NULL AND dlp_state <> 'REJECTED'
          AND cleanup_state IN ('REVOKED','NO_CREDENTIAL'))
      OR (outcome <> 'SUCCEEDED' AND failure_code IS NOT NULL))
);

CREATE INDEX read_credential_cleanup_claim_idx
  ON read_credential_leases (updated_at, id)
  WHERE cleanup_state = 'CLEANUP_PENDING'
     OR (cleanup_state = 'UNCERTAIN' AND accessor_ciphertext IS NOT NULL);
CREATE INDEX read_credential_issue_reclaim_idx
  ON read_credential_leases (issue_claim_expires_at, id)
  WHERE cleanup_state = 'ISSUING';
CREATE INDEX diagnostic_receipts_asset_idx
  ON diagnostic_execution_receipts
    (tenant_id, workspace_id, environment_id, asset_id, created_at DESC, id DESC);
~~~
The seventh/eighth owned relations are exactly `awx_host_identity_enrollments` and `awx_host_identity_enrollment_attempts`，with the columns、candidate keys、authority/cohort/state/fence/launch-marker/cleanup/result/seal constraints and indexes in `docs/contracts/awx-host-identity-enrollment-v1.md`。That contract is part of this Task's reviewed migration manifest；the SQL/Go golden test byte-compares its exact field/state/digest inventory，and no generic operation payload or ninth table may substitute for it。

Task 1, not Task 5, owns `AWXReadProfileManifestV1()`. It returns deep copies of the exact 954-byte RFC 8785 value `{"backpressure_base_seconds":5,"backpressure_max_seconds":300,"compatibility_class":"AWX_READ_V1","credential_purpose":"READ_AUTOMATION","dlp_policy_code":"ASSET_SAFE_V1","environment_mapping_mode":"SINGLE_ENVIRONMENT","freshness_kind":"OBJECT_TIME_SEQUENCE","integration_mode":"REQUIRED","max_document_bytes":16384,"max_page_bytes":1048576,"max_page_items":200,"max_page_relations":0,"network_mode":"REQUIRED","parser_code":"AWX_INVENTORY_HOST_V1","profile_code":"AWX_READ_V1","provider_kind":"AWX_API","rate_limit_requests":60,"rate_limit_window_seconds":60,"relationship_types":[],"schedule_mode":"REQUIRED","source_kind":"AWX_INVENTORY","sync_mode":"SCHEDULED","trust_mode":"REQUIRED","trusted_path_codes":["AWX_READ_V1_ASSET_KIND","AWX_READ_V1_DISPLAY_NAME","AWX_READ_V1_ENABLED","AWX_READ_V1_EXTERNAL_ID","AWX_READ_V1_INVENTORY_REFERENCE","AWX_READ_V1_PROVIDER_MODIFIED_AT"],"typed_extension_code":null,"version":"asset-source-profile-manifest.v1"}` with SHA-256 `4f02470a1d0ce77867b1319ba202880e0e8d79f5a5740af34de3b6131f86f792`.

Its exact 520-byte canonical Provider schema is `{"additionalProperties":false,"properties":{"asset_kind":{"enum":["BARE_METAL_HOST","LINUX_VM","WINDOWS_VM"]},"display_name":{"maxLength":256,"minLength":1,"type":"string"},"enabled":{"type":"boolean"},"inventory_reference":{"pattern":"^awx-inventory-v1-[a-f0-9]{64}$","type":"string"},"provider_modified_at":{"pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{6}Z$","type":"string"}},"required":["asset_kind","display_name","enabled","inventory_reference","provider_modified_at"],"type":"object"}` with SHA-256 `2600fd15bc9ff6ab9b839fe46ac476d801a8c41c8740de9cc0958a9bfc843ad5`. `inventory_reference` is exactly `awx-inventory-v1-<sha256>` and never the numeric ID. The six-frame `asset-source-definition.v2` for `AWX_INVENTORY/AWX_API/AWX_READ_V1` is 151 bytes with SHA-256 `af073d77f4ecd7b0191ccdb18e9cba6e95abec0774dff81dc9f5f33451f5e84f`. Migration SQL embeds independent raw literals and recomputes them; tests byte-compare SQL, typed reconstruction and Go. Task 5 only registers/consumes this fixture.

`000019` owns exactly 18 new routines plus the replace-only hook (net `+18`)：pure `public.host_postgresql_awx_connection_binding_digest(uuid,uuid,uuid,uuid,bigint,uuid,text,text)`、`public.host_postgresql_awx_selection_fact_digest(uuid,uuid,uuid,uuid,uuid,bigint,text,text,bigint,text)`、`public.host_postgresql_awx_selection_proof_digest(text,text,text)`；trigger-returning `public.enforce_host_postgresql_awx_connection_revision()`、`public.enforce_host_postgresql_awx_validation_run_selection_fact()`、`public.enforce_host_postgresql_awx_validation_check_selection_proof()`、`public.enforce_host_postgresql_awx_runtime_artifact()`、`public.enforce_diagnostic_contract_revision()`、`public.read_credential_lease_reference_guard()`、`public.diagnostic_execution_receipt_reference_guard()`、`public.enforce_read_credential_lease_transition()`、`public.enforce_read_credential_cleanup_attempt_transition()`、`public.validate_read_credential_cleanup_closure()`、`public.enforce_awx_host_identity_enrollment_transition()`、`public.enforce_awx_host_identity_enrollment_attempt_transition()`、`public.validate_awx_host_identity_enrollment_closure()`、`public.reject_host_postgresql_immutable_mutation()`、`public.reject_host_postgresql_delete_or_truncate()`；and the in-place `public.asset_catalog_future_source_gate_admitted(public.asset_sources)` manifest entry。Trusted identities are qualified，path is `pg_catalog, public, pg_temp`，pure digests are INVOKER/runtime-only EXECUTE，fifteen triggers are DEFINER/OWNER-only，PUBLIC/workload direct ACL absent。Role admission grants exact three-contract+Receipt SELECT/INSERT，lease/cleanup and enrollment root/attempt least-privilege claim/controlled UPDATE，and only predecessor AWX column rights named above，never DELETE/TRUNCATE。Real workload and rogue-grantee tests plus pre/postflight fingerprint all ACLs。

The exact lease matrix is database-owned. Insert is only `NOT_ISSUED/version=1`; claim performs `NOT_ISSUED→ISSUING` with a private expiring claim hash. Before the remote call, one CAS writes the immutable request digest/correlation reference and `issue_started_at`; an expired claim with all three still NULL may only rotate the claim and retry, while any crash after this marker becomes `UNCERTAIN` and can only become `MANUAL_REQUIRED` because Vault cannot recover an unknown lease ID from an audit correlation. `issue_correlation_ref` is safe audit/human-triage metadata only and is never an automatic Vault lookup/retry key。A live claimant may finish `ISSUING→ISSUED|NO_CREDENTIAL|UNCERTAIN`; every exit clears claim token/expiry but retains the immutable request marker triplet。`requested_expires_at` is insert-immutable；actual `expires_at` may change exactly once from NULL to the trusted bounded response value only on `ISSUING→ISSUED` or an accessor-bearing `ISSUING→UNCERTAIN`，and stays NULL for a true no-credential result。`ISSUED→CLEANUP_PENDING`; `CLEANUP_PENDING→CLEANUP_CLAIMED`; cleanup uncertainty with a persisted accessor may re-enter `CLEANUP_CLAIMED` or become `MANUAL_REQUIRED`. `REVOKED|NO_CREDENTIAL|MANUAL_REQUIRED` are terminal. Each parent mutation increments version exactly once and leaves identity/bindings/issuer/requested expiry and write-once issue facts immutable；state shape distinguishes issuance-time `NO_CREDENTIAL` from an issued lease later confirmed absent without erasing its accessor/lease identity。

Each cleanup claim atomically changes the parent to `CLEANUP_CLAIMED` and inserts exactly `max(attempt)+1` append-only `CLAIMED` attempt. Its request marker/digest are write-once; `CLAIMED→REVOKED|NO_CREDENTIAL|RETRYABLE|UNCERTAIN|MANUAL_REQUIRED` occurs exactly once. Claim expiry before the marker seals `RETRYABLE` and returns the parent to `CLEANUP_PENDING`; only that pre-request terminal shape may omit the marker。Expiry/failure after it seals both attempt and parent `UNCERTAIN|MANUAL_REQUIRED`；a successful `REVOKED|NO_CREDENTIAL` requires the marker。The deferred closure attached to both parent and attempts requires the same transaction to map attempt `REVOKED|NO_CREDENTIAL|RETRYABLE|UNCERTAIN|MANUAL_REQUIRED` to the identical parent terminal or `RETRYABLE→CLEANUP_PENDING`, with exact Audit/Outbox. No attempt row is overwritten and terminal rows have no outgoing edge. Tests cover crash-before-request, crash-after-request and concurrent reclaim. Provider binding is fixed: `AWX_API→READ_AUTOMATION`, `POSTGRESQL→READ_DATABASE`, Host Probe has no lease and uses receipt `NO_CREDENTIAL`; the reference guard derives this from the joined contract/provider rather than trusting `usage_role`.

`000019` extends `runtime_publication_artifacts_kind_check` by exactly four private values，`AWX_INVENTORY_MAPPING|AWX_READ_TEMPLATE_FINGERPRINT|AWX_HOST_IDENTITY_BINDINGS|AWX_ENROLLMENT_AUTHORITY_KEYRING`，without widening any other kind；size constraints are exact per kind，identity alone permits 64 MiB and keyring is capped at 1 MiB。The bootstrap mapping retains exact schema `awx-inventory-mapping.v1` and bytes `{"asset_kind":"<LINUX_VM|WINDOWS_VM|BARE_METAL_HOST>","connection_binding_digest":"<sha>","connection_revision":<safe-int>,"integration_id":"<uuid>","inventory_id":<safe-int>,"organization_reference_digest":"<sha>","schema":"awx-inventory-mapping.v1","selection_proof_digest":"<sha>"}`；it is the only initial/VALIDATING Source artifact。The bootstrap Runtime carries mapping only；keyring lives in separate `AWX_ENROLLMENT_AUTHORITY` Runtime and never enters Source resolver。After discovery，the dedicated flow in `docs/contracts/awx-host-identity-enrollment-v1.md` verifies/seals fingerprint、identity and diagnostic successor；Source hook never reads them。Contract/runtime bind hashes/root/count，server-only resolution exposes safe fields/opaque verifier，and unsafe authority/cohort/fingerprint/proof/attestation/artifact shape fails closed。

The mapping has one trusted origin。`000019` additively adds nullable `awx_integration_id uuid`、`awx_organization_reference_digest text`、`awx_asset_kind text` and `awx_connection_binding_digest text` to immutable `connection_revisions`。All four are present iff the joined Connection Profile is `AWX_API`; Integration has an exact same-Tenant/Workspace composite FK，kind is the three-value enum，and SQL recomputes `awx_connection_binding_digest=SHA256(FramedTupleV1("awx-connection-binding.v1",tenant_id,workspace_id,environment_id,connection_id,minimal-decimal revision,awx_integration_id,raw awx_organization_reference_digest,awx_asset_kind))`。Other Providers require all four NULL。The Control Plane resolves the opaque OrganizationReference to its digest before revision creation；no numeric inventory ID or mutable config enters this digest。

The fixed AWX Validation Runner consumes that exact revision through its signed private Capsule, lists the exact organization, and requires exactly one enabled non-smart Inventory with a JCS-safe ID。Its mTLS-authenticated, fenced selection fact digest is `SHA256(FramedTupleV1("awx-inventory-selection-fact.v1",tenant_id,workspace_id,environment_id,integration_id,connection_id,minimal-decimal connection_revision,raw awx_connection_binding_digest,raw organization_reference_digest,minimal-decimal inventory_id,asset_kind,SUCCEEDED))`；the Runner cannot claim cleanup。The Gateway verifies registered workload identity、Run/attempt/fence/request digest and recomputes the fact before atomically staging it；then Broker cleanup proceeds。After cleanup, a terminal transaction seals `awx_selection_proof_digest=SHA256(FramedTupleV1("awx-inventory-selection.v1",raw selection_fact_digest,cleanup_state,raw cleanup_receipt_digest))` while inserting the final check exactly once。A crash at either boundary resumes from persisted run/cleanup state；it never asks the Runner or caller to replay an unpersisted ID。Zero/multiple inventories、organization mismatch、unsafe ID、nonterminal/failed outcome or uncertain cleanup reject validation。The publisher creates the mapping artifact only from that immutable terminal proof and Connection Revision, and SQL recomputes every origin field/hash；generic mutable `integrations.config`、caller payload and `awx_read_template_revisions` are invalid mapping truth sources。

To make that proof restart-safe without exposing private IDs，`000019` first adds write-once nullable `awx_pending_inventory_id bigint`、`awx_pending_asset_kind text`、`awx_pending_organization_reference_digest text` and `awx_pending_selection_fact_digest text` to `connection_validation_runs`。They transition only once from all-NULL to all-present while the exact fenced run is `RUNNING` at the provider-result stage；the trigger recomputes the signed fact and later attempts may only exact-replay it。It also adds nullable private `awx_inventory_id bigint`、`awx_asset_kind text`、`awx_organization_reference_digest text`、`awx_selection_fact_digest text` and `awx_selection_proof_digest text` to `connection_validation_checks`。All five are inserted together only by the Gateway terminal transaction on the existing AWX `FIXED_PROBE/PASSED` row after actual cleanup `REVOKED`, must equal the staged run fields, and `check_digest=awx_selection_proof_digest`；`NO_CREDENTIAL` is rejected。IDs use the safe range，kinds/digests are closed，and the deterministic trigger joins Connection/Integration/cleanup receipt to recompute both digests；direct SQL mismatch fails `23514`。Other Providers/runs/checks require all private fields NULL。API/audit/log projections omit all nine columns；only Gateway recovery、private compiler and 000019 hook may reload them。This is an additive change to predecessor relations, not a seventh owned table。

上方 `BEGIN` block 的顺序是规范：minimum existence check 之后、任何 fingerprint/guard/`ALTER`/`CREATE` 之前，`000019` takes `pg_catalog.pg_advisory_xact_lock(712017001900001)` and the single fully qualified NOWAIT lock statement shown there。The set includes every preserved Kubernetes hook dependency、AWX Integration/Connection/Target/Capability/Runtime/artifact fact、Phase 4 Snapshot/Grant fact、FK target and altered Attempt/Receipt/Audit/Outbox relation，and remains held to `COMMIT`。Any conflict returns `55P03` and rolls back with zero schema/data change；retry starts at a new `BEGIN`。After locking, the migration sets the deparse GUCs and validates the **complete reviewed 000017+000018 predecessor manifest** plus the exact one-signature 000017 hook definition/owner/ACL/language/volatility/security/search-path/no-overload contract。Keeping the hook body while dropping/changing any predecessor relation、column、constraint、trigger or function must fail this preflight before catalog mutation。It then restores `SET LOCAL search_path=public,pg_catalog,pg_temp` before the unqualified SQL snippets and switches back to `pg_catalog,pg_temp` before postflight。Preflight also rejects any anomalous existing `AWX_INVENTORY` Source/Revision；the 000017 predecessor should have blocked its initial commit and the successor cannot adopt an old candidate。随后执行且只执行一次：

~~~sql
CREATE OR REPLACE FUNCTION public.asset_catalog_future_source_gate_admitted(
    candidate public.asset_sources
) RETURNS boolean
~~~

新 body 维持 `LANGUAGE plpgsql STABLE SECURITY INVOKER` 与 `SET search_path = pg_catalog, public, pg_temp`，只使用 `public.`-qualified trusted relations/types and `pg_catalog` builtins/operators，由两个 Source-kind branch 组成；每个 branch 内按 initial `UNAVAILABLE` creation、`VALIDATING` 与 `AVAILABLE|DEGRADED` 区分创建闭包、pre-validation/runtime closure 和 terminal proof：

1. `KUBERNETES_OPERATOR` branch 必须与 `000017` exact function definition 中的 predicate 完全一致，继续要求 `VICTORIAMETRICS_OPERATOR_V1`、typed extension 与对应状态的 exact validation closure；不得因本阶段新增 Provider 而放宽或重算。
2. `AWX_INVENTORY` branch 必须要求 candidate `ACTIVE`、`provider_kind='AWX_API'`，其 exact base revision 使用 versioned `profile_code='AWX_READ_V1'`、typed-extension pair 均为 NULL，并要求 persisted canonical Profile manifest bytes/SHA-256 与 `000019` 固定、由 `AWXReadProfileManifestV1()` 领域 fixture 生成的 bytes/hash 完全相等；Profile code alone never admits。Canonical Provider schema bytes/SHA-256、`asset-source-definition.v2` 与 Phase 1 SQL BindingDigest 也必须重算闭合，且 `revision.integration_id` 是同 Scope installed canonical Integration。该 Integration 在 Source authority child 的唯一 Environment 中必须解析到恰好一个 exact `AVAILABLE` AWX Runtime closure；Connection revision、selection proof、Target/Capability revision、Runtime publication、Bundle/manifest/attestation digest and the exact mapping artifact above must all close in all three state branches。Artifact origin Connection binding、Integration、Organization-reference digest、selection proof、Environment and Runtime Publication must equal the joined facts，and its hash must be in the same publication manifest/bundle/attestation。Initial `UNAVAILABLE` creation 仅接受无 published/validated/checkpoint/run pointer、gate/checkpoint revision/version 为 0 且 checkpoint material NULL 的新 Source，以及唯一 same-transaction `DRAFT` revision 1 (`expected_source_version=1`)、authority child 和 revision-CAS 后 exact Source version 2，并只开放稳定身份创建；`VALIDATING` 只接受 exact newly queued Validation Run 与尚未 terminal 的 `VALIDATING` revision，不要求尚不存在的 `awx-inventory-source-validation.v1` proof；only `AVAILABLE|DEGRADED` additionally requires that exact Source proof、exact `PUBLISHED` revision/digest、terminal `SUCCEEDED/COMPLETED/VALIDATION/VALIDATION_PROOF` Run、actual cleanup exactly `REVOKED` and published/validated binding digest；`NO_CREDENTIAL` is rejected。任一零行、多行、Scope/Environment/Integration/profile-manifest/schema/revision/selection/runtime/artifact/bundle/attestation/validation/cleanup/digest drift 返回 false。

The AWX Source proposed proof is not an opaque reusable receipt。For this branch `asset_source_runs.validation_proof_digest` must equal `SHA256(FramedTupleV1("awx-inventory-source-validation.v1",tenant_id,workspace_id,environment_id,source_id,minimal-decimal source_revision,raw canonical_revision_digest,run_id,minimal-decimal run_gate_revision,integration_id,connection_id,minimal-decimal connection_revision,raw awx_connection_binding_digest,runtime_publication_id,raw runtime_manifest_digest,raw bundle_digest,raw deployment_attestation_digest,raw mapping_artifact_sha256,raw selection_proof_digest,SUCCEEDED))`。`ProposeValidationResult` seals this immutable digest before Source-run Broker cleanup；terminal `Complete` separately requires the same exact Run to have actual cleanup `REVOKED` and matching cleanup receipt/digest。The hook recomputes both layers from joined rows；a later Run or N+1 Runtime/artifact/attestation cannot reuse an old proposed proof, and caller-supplied proof bytes never become truth。

所有其他 Source kind/gate 状态返回 false。Phase 1 live path only calls this hook for `VALIDATING|AVAILABLE|DEGRADED`；deferred INSERT alone calls initial creation，and rows may always converge fail-closed。Provider allowlist/Profile/Runtime alone or caller mapping never admits。Migration fingerprints exact `000019` definition and regresses the full `000017` truth table；pre/postflight verifies signature/body/owner/semantic ACL/language/security/path/no-overload and reviewed Asset surface。Recovery inherits Phase 3's quarantined two-owner choreography and allowed owner set（000019 creates no third owner）：archive retains the Victoria extension procedure owner plus all schema-owner objects/ACLs；before `pg_restore --single-transaction --role=aiops_schema_owner` the recovery coordinator installs the temporary schema-owner→extension-owner `inherit=true,set=true,admin=false` edge and extension-owner `CREATE ON SCHEMA public` grant，then revokes both on every success/failure path before CONNECT；coordinator hard crash follows Phase 3's reacquire-first residue cleanup protocol。Updated schema+role admission verifies the exact persistent graph、all eight tables、14 predecessor columns、18 routines、all four AWX artifact kinds/size contracts and the successor digest before traffic opens。Owner/ACL/helper/artifact/temporary-authority drift or an old body fails startup even when data restores。

所有进入/保持 AWX `VALIDATING|AVAILABLE|DEGRADED` 的 Repository 路径必须在同一 `SERIALIZABLE` transaction 内按固定顺序锁定 Source、base revision、Integration、Connection revision、Target/Capability revision、Runtime publication、its exact `AWX_INVENTORY_MAPPING` artifact、Bundle/manifest/attestation、Validation Run/proof/cleanup，再执行 Source UPDATE；数据库 trigger 对非-serializable future live transition直接拒绝，Hook 在同一 snapshot 内重查全部闭包。Immutable revision/artifact/manifest/attestation/proof 拒绝 UPDATE/DELETE；任何 Runtime availability、active publication、Connection/Target/Capability pointer、artifact selection/Integration mapping 或 revocation 变更必须使用同一全局锁序反向查找并锁定全部依赖 Source，在改变可信事实的同一 transaction 先将其推进到 `SUSPENDED/UNAVAILABLE`。并发测试允许双方顺序提交，但若漂移方提交，Source 必须已原子关门；否则必须有一方 serialization failure/gate rejection，绝不能留下 live Source 引用旧闭包。Kubernetes branch 继续遵守 `000017` 的相同隔离级别、反向关门与锁序，不得在 successor 中降级。

增加两个确定性 constraint trigger，不能留给执行者临时“对齐”：

- `read_credential_lease_reference_guard` 使用一条 `SELECT ... FOR SHARE` 锁定 Attempt、Grant、Grant 的 Asset Snapshot Item、Asset、Capability Definition、Published Target、APPLIED Runtime Publication、READ+enabled Realm 与 AVAILABLE Realm Binding；逐项比较 Environment、Asset revision、Target ref/id、Runtime id/bundle digest、Capability id/revision、Realm id、Grant status/expiry。零行、多行、摘要漂移或 Capability 不在 Snapshot set 都以 SQLSTATE `23514` 拒绝。
- `diagnostic_execution_receipt_reference_guard` 按 `contract_kind` 只允许三条显式分支：`HOST_PROBE` 锁 `host_probe_contract_revisions`、`AWX_TEMPLATE` 锁 `awx_read_template_revisions`、`POSTGRES_QUERY` 锁 `postgres_diagnostic_query_revisions`；每条都验证同 Scope 的 contract id/revision/recomputed digest 与 Capability Definition。`HOST_PROBE` requires `credential_lease_id IS NULL` and receipt `NO_CREDENTIAL`；AWX/PostgreSQL require a same-attempt lease、respectively `READ_AUTOMATION|READ_DATABASE`，and receipt cleanup must equal the locked parent state。A linked issued lease may finish `REVOKED` or accessor-bearing `NO_CREDENTIAL`（remote exact-lease not found still keeps the lease FK/accessor）；issuance-time no-accessor `NO_CREDENTIAL` can only accompany a failed outcome。Failed outcomes may bind `UNCERTAIN|MANUAL_REQUIRED`，but success requires `REVOKED|NO_CREDENTIAL`。随后验证 Evidence 属于同 Investigation、Runner Receipt 属于同 Environment/Task/Attempt 且 hash 相等、Credential Lease shape、Audit Record 的 Environment/resource type/resource id/payload hash 指向本 Receipt。`failure_code` is the exact closed `readtask.FailureCode` enum above；CR/LF、free text、Provider body、endpoint/DSN/Secret canary and Go/SQL enum drift all fail `23514`。未知 kind、缺失必需对象但状态声称存在、或任一不一致均拒绝。

所有候选键在本计划中已明确：Phase 2 提供 Published Target/Capability/Runtime/Realm scoped key，000011 的 Attempt 由本迁移新增 Environment candidate key，000019 同时为 Runner Receipt 与 Audit Record 新增 Environment candidate key。禁止无作用域单列 FK、删 FK、`NOT VALID` 永不验证或只靠应用层检查。

- [ ] **Step 5: 添加 immutable triggers、guarded down 并验证**

Down begins one transaction，runs a read-only minimum-existence check，then takes `pg_catalog.pg_advisory_xact_lock(712017001900001)` and one fully qualified `LOCK TABLE ... IN ACCESS EXCLUSIVE MODE NOWAIT` statement over the **exact Step 3 up lock set** plus the eight owned relations `public.host_probe_contract_revisions`、`public.awx_read_template_revisions`、`public.postgres_diagnostic_query_revisions`、`public.read_credential_leases`、`public.read_credential_cleanup_attempts`、`public.diagnostic_execution_receipts`、`public.awx_host_identity_enrollments` and `public.awx_host_identity_enrollment_attempts`。This definition includes the full predecessor-manifest relation set、every preserved Victoria/credential/connection/validation/realm/target/capability/runtime/Snapshot/Grant/Attempt/Evidence/Receipt/Audit/Outbox fact and all eight owned tables；a manifest→lock-set equality test rejects any omitted relation。Any conflict returns `55P03` and rolls back before fingerprint/guard/hook/schema changes；only a new transaction may retry。After the full lock succeeds, Down sets `quote_all_identifiers=off/search_path=pg_catalog,pg_temp` and validates the complete reviewed 000019 successor manifest，restores `search_path=public,pg_catalog,pg_temp` for guard/restore/drop，then switches back to the deparse pair and validates the complete 000017+000018 predecessor manifest after restoration。The guard、predecessor restore、child-first FK drop、postflight owner/ACL/overload/definition verification and commit remain inside that transaction。Per-relation `55P03` fixtures cover every generated manifest member。

三个合同表与 Receipt 表拒绝 UPDATE/DELETE/TRUNCATE，SQLSTATE 固定 `55000`；凭据两表与 enrollment root/attempt 只允许各自状态机列、版本与时间的受控变化。Down 在任一八表有行时整体拒绝：

~~~sql
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM host_probe_contract_revisions)
     OR EXISTS (SELECT 1 FROM awx_read_template_revisions)
     OR EXISTS (SELECT 1 FROM postgres_diagnostic_query_revisions)
     OR EXISTS (SELECT 1 FROM read_credential_leases)
     OR EXISTS (SELECT 1 FROM read_credential_cleanup_attempts)
     OR EXISTS (SELECT 1 FROM diagnostic_execution_receipts)
     OR EXISTS (SELECT 1 FROM awx_host_identity_enrollments)
     OR EXISTS (SELECT 1 FROM awx_host_identity_enrollment_attempts)
     OR EXISTS (SELECT 1 FROM connection_profiles WHERE provider_kind IN (
          'HOST_PROBE_MTLS','AWX_API','POSTGRESQL'))
     OR EXISTS (SELECT 1 FROM runner_capability_bindings WHERE provider_kind IN (
          'HOST_PROBE_MTLS','AWX_API','POSTGRESQL'))
     OR EXISTS (SELECT 1 FROM capability_definitions WHERE provider_kind IN (
          'HOST_PROBE_MTLS','AWX_API','POSTGRESQL'))
     OR EXISTS (
          SELECT 1 FROM asset_sources
          WHERE source_kind = 'AWX_INVENTORY')
     OR EXISTS (
          SELECT 1 FROM runtime_publication_artifacts
          WHERE artifact_kind IN ('AWX_INVENTORY_MAPPING','AWX_READ_TEMPLATE_FINGERPRINT','AWX_HOST_IDENTITY_BINDINGS','AWX_ENROLLMENT_AUTHORITY_KEYRING'))
     OR EXISTS (
          SELECT 1 FROM connection_validation_checks
          WHERE awx_selection_proof_digest IS NOT NULL)
     OR EXISTS (
          SELECT 1 FROM connection_validation_runs
          WHERE awx_pending_selection_fact_digest IS NOT NULL)
     OR EXISTS (
          SELECT 1 FROM connection_revisions
          WHERE awx_connection_binding_digest IS NOT NULL)
     OR EXISTS (SELECT 1 FROM audit_records WHERE environment_id IS NOT NULL) THEN
    RAISE EXCEPTION USING ERRCODE='55000',
      MESSAGE='unsafe host/postgresql diagnostics rollback: state remains',
      CONSTRAINT='host_postgresql_read_diagnostics_down_guard';
  END IF;
END $$;
~~~

空状态下的 down 顺序固定：上述锁与 guard 必须先拒绝任一 AWX Source、typed Connection projection、pending/final private selection row、enrollment row or any of the four AWX artifacts，不论 gate/publication 状态；因此旧 AWX revision/binding/artifact/proof 不能跨 successor generation。随后在删除任何 `000019` relation 前恢复并复验 exact `000017` hook。Then drop every 000019-owned predecessor/new-table trigger and helper-dependent constraint，child-first drop Receipt→enrollment attempts→enrollment roots→cleanup attempts→leases→three contract tables；先删除 Receipt/Audit dependent FK/UK/trigger，再删除 `audit_records.environment_id`，并恢复/删除 `investigation_task_attempts` 与 `runner_evidence_receipts` 两个 additive unique keys，最后 drop exact 14 predecessor columns plus provider/artifact constraints。Without `CASCADE`，drop the fifteen trigger routines exactly as `public.enforce_host_postgresql_awx_connection_revision()`、`public.enforce_host_postgresql_awx_validation_run_selection_fact()`、`public.enforce_host_postgresql_awx_validation_check_selection_proof()`、`public.enforce_host_postgresql_awx_runtime_artifact()`、`public.enforce_diagnostic_contract_revision()`、`public.read_credential_lease_reference_guard()`、`public.diagnostic_execution_receipt_reference_guard()`、`public.enforce_read_credential_lease_transition()`、`public.enforce_read_credential_cleanup_attempt_transition()`、`public.validate_read_credential_cleanup_closure()`、`public.enforce_awx_host_identity_enrollment_transition()`、`public.enforce_awx_host_identity_enrollment_attempt_transition()`、`public.validate_awx_host_identity_enrollment_closure()`、`public.reject_host_postgresql_immutable_mutation()`、`public.reject_host_postgresql_delete_or_truncate()`，then after every digest dependency is gone drop the three pure functions listed above。Postflight proves net `-18`、all successor columns and all four artifact kinds absent、Provider/size checks restored、unchanged predecessor digests identical and exactly one 000017 hook；不得留下 overload/artifact kind/half-rollback constraint。

Down 回归必须分别证明 `AVAILABLE`、`SUSPENDED`、`UNAVAILABLE` AWX Source 与 orphan mapping-artifact fixture 均使整笔 rollback 且 `000019` body/constraint digest 不变；并发事务持有 Step 3 任一依赖或任一 owned relation 时 down 只能以 `55P03` 零变化失败，释放后从新事务重试；拿齐锁后才启动的 AWX Source、owned-row、gate 或 Runtime/artifact 变更不能越过 guard。只有从未创建 AWX Source/mapping artifact 的空状态可 down，predecessor `000017+000018` reviewed schema-admission manifest 重新通过，Kubernetes Operator positive fixture 仍按 `000017` branch admitted，`AWX_INVENTORY` 则重新 default-false；再次 up 后只能创建新的 AWX Source/revision、Runtime/artifact closure 与 validation proof。

Run:

~~~bash
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/store/postgres -run 'Test(HostPostgreSQLDiagnostics|DiagnosticContracts|DiagnosticCredential)' -count=1
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/store/postgres -run 'TestHostPostgreSQLDatabaseRoleAdmission' -count=1
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/assetcatalog/postgres -run 'TestHostPostgreSQLSchemaAdmission' -count=1
~~~

Expected: PASS；八表所有权、三组 Provider allowlist、复合作用域、跨 Environment Attempt 拒绝、Grant Snapshot closure、polymorphic contract trigger、Evidence/Runner Receipt/Audit 绑定、enrollment authority/cohort/fence/cleanup/seal、不可变、单 Attempt Credential、Receipt 一致性、非空 down guard 与空库 up/down/up 全部通过。

- [ ] **Step 6: Commit**

~~~bash
git add migrations/000019_host_postgresql_read_diagnostics.up.sql migrations/000019_host_postgresql_read_diagnostics.down.sql internal/store/postgres/migrations_integration_test.go internal/store/postgres/database_role_admission.go internal/store/postgres/database_role_admission_test.go internal/assetcatalog/postgres/schema_admission.go internal/assetcatalog/postgres/schema_admission_test.go internal/assetcatalog/postgres/schema_admission_integration_test.go internal/assetcatalog/postgres/migration_recovery_integration_test.go internal/assetcatalog/postgres/recovery_container_test.go internal/assetdiscovery/awx/source_profile.go internal/assetdiscovery/awx/source_profile_test.go internal/diagnosticcontract docs/operations/database-role-bootstrap.md
git commit -m "feat: add host and postgres diagnostic facts"
~~~

### Task 2: 实现版本化合同领域与 PostgreSQL Registry

**Files:**
- Create: `internal/hostdiagnostic/types.go`, `internal/hostdiagnostic/canonical.go`, `internal/hostdiagnostic/registry.go`, `internal/hostdiagnostic/publisher.go`
- Create: `internal/hostdiagnostic/postgres/repository.go`, `internal/hostdiagnostic/postgres/publisher.go`, `internal/hostdiagnostic/postgres/repository_integration_test.go`, `internal/hostdiagnostic/postgres/publisher_integration_test.go`
- Create: `internal/hostdiagnostic/types_test.go`, `internal/hostdiagnostic/registry_test.go`, `internal/hostdiagnostic/publisher_test.go`
- Create: `internal/postgresdiagnostic/types.go`, `internal/postgresdiagnostic/registry.go`, `internal/postgresdiagnostic/types_test.go`
- Create: `internal/postgresdiagnostic/postgres/repository.go`, `internal/postgresdiagnostic/postgres/repository_integration_test.go`

**Interfaces:**
- Consumes: 八表中的三个 contract revision 表、`assetcatalog.Scope`、Phase 2 Published Capability/Runtime safe projection。
- Produces: `hostdiagnostic.Registry.Resolve`、server-only `hostdiagnostic.Publisher.PublishRevision`、`postgresdiagnostic.Registry.Resolve`、不可序列化 `HostExecutionContract`/`QueryExecutionContract` 和公共安全描述。

- [ ] **Step 1: 写 union、redaction、摘要与 Scope 失败测试**

~~~go
func TestHostContractAcceptsExactlyOneProviderAndNoFreeFormFields(t *testing.T) {
    contract := validMTLSHostContract()
    if err := contract.Validate(); err != nil { t.Fatal(err) }
    contract.AWX = validAWXTemplate()
    if err := contract.Validate(); !errors.Is(err, hostdiagnostic.ErrContractRejected) {
        t.Fatalf("dual provider error = %v", err)
    }
}

func TestHostExecutionContractAlwaysMarshalsRedacted(t *testing.T) {
    resolved := resolveHostContractForTest(t)
    encoded, err := json.Marshal(resolved)
    if err != nil { t.Fatal(err) }
    if string(encoded) != `{"redacted":true}` || strings.Contains(resolved.String(), "inventory") {
        t.Fatalf("unsafe projection: %s %s", encoded, resolved)
    }
}

func TestQueryContractRejectsUnknownQueryOrCallerTimeout(t *testing.T) {
    for _, input := range []json.RawMessage{
        []byte(`{"query_id":"postgres.custom.v1"}`),
        []byte(`{"statement_timeout_ms":1}`),
        []byte(`{"sql":"select 1"}`),
    } {
        if _, err := registry.Resolve(ctx, validResolveRequest(input)); !errors.Is(err, postgresdiagnostic.ErrContractRejected) {
            t.Fatalf("Resolve(%s) error = %v", input, err)
        }
    }
}

func TestRegistryNeverFallsBackAcrossScopeOrRevision(t *testing.T) {
    repository := newRegistryIntegrationFixture(t)
    _, err := repository.Resolve(ctx, ResolveRequest{
        Scope: otherScope(), ContractID: contractID, Revision: 2,
        CapabilityDefinitionID: capabilityID, CapabilityDefinitionRevision: 7,
    })
    if !errors.Is(err, store.ErrNotFound) { t.Fatalf("cross scope error = %v", err) }
}
func TestPublisherRejectsUnsignedHTTPCallerAndCallerOwnedBytes(t *testing.T)
func TestPublisherPublishesHostAndAWXContractAuditOutboxAtomically(t *testing.T)
func TestPublisherRejectsFingerprintArtifactDriftAndConcurrentNPlusOne(t *testing.T)
~~~

- [ ] **Step 2: 运行测试并确认领域包不存在**

Run:

~~~bash
go test ./internal/hostdiagnostic ./internal/postgresdiagnostic -count=1
~~~

Expected: FAIL because the packages and types do not exist.

- [ ] **Step 3: 实现精确 Host 合同接口与唯一发布入口**

~~~go
package hostdiagnostic

type Capability string
type Provider string

const (
    ProviderMTLS Provider = "HOST_PROBE_MTLS"
    ProviderAWX  Provider = "AWX_API"
    CapabilitySystemInfo Capability = "HOST_SYSTEM_INFO"; CapabilityCPUMemory Capability = "HOST_CPU_MEMORY_SNAPSHOT"
    CapabilityDiskUsage Capability = "HOST_DISK_USAGE"; CapabilityListeners Capability = "HOST_NETWORK_LISTENERS"
    CapabilitySystemd Capability = "HOST_SYSTEMD_STATUS"; CapabilityWindowsService Capability = "HOST_WINDOWS_SERVICE_STATUS"
    CapabilityBoundedLog Capability = "HOST_BOUNDED_LOG_WINDOW"
)

type ResolveRequest struct {
    Scope assetcatalog.Scope
    AssetID string
    CapabilityDefinitionID string
    CapabilityDefinitionRevision int64
    ContractID string
    ContractRevision int64
    RuntimePublicationID string
    RuntimeDigest string
    Input json.RawMessage
    InputHash string
}

type PublicDescription struct {
    Capability Capability `json:"capability"`
    ContractID string `json:"contract_id"`
    SchemaVersion string `json:"schema_version"`
    ParameterSchema json.RawMessage `json:"parameter_schema"`
    Budget Budget `json:"budget"`
}

type Registry interface {
    Resolve(context.Context, ResolveRequest) (ExecutionContract, error)
    Describe(context.Context, assetcatalog.AssetLocator) ([]PublicDescription, error)
}
type Publisher interface { PublishRevision(context.Context, SignedPublication) (RevisionRef, error) }
~~~

`ExecutionContract` 字段全部私有，仅提供 `Capability()`、`Provider()`、`ContractID()`、`Revision()`、`Digest()`、`InputHash()`、`Budget()`、`Matches(readtask.Descriptor)` 和受包控制的 `MTLS()`/`AWX()` view。其 `MarshalJSON` 固定返回 `{"redacted":true}`，Unmarshal 固定拒绝。

输入严格 union：CPU sample window 只允许 `5|15|30`；disk scope 只允许 `LOCAL|ALL_FIXED`；address family 只允许 `IPV4|IPV6|BOTH`；unit/service/log source 必须从合同内 enum 映射，调用方值不能成为 path/argv；lookback 只允许 `60|300|900`。空对象必须是 canonical `{}`，所有未知键、duplicate key、非 NFC 字符串和 trailing bytes 拒绝。

`SignedPublication` has no public field/JSON decoder and is created only after the server verifies a release/bootstrap signature、actor、purpose、expiry and replay nonce；HTTP/Task/Runner/model cannot construct it。Publisher opens one serializable transaction，locks/reloads Scope、Capability revision、Task 1-owned schema fixtures and，for AWX，one exact APPLIED post-discovery Runtime containing matching `AWX_INVENTORY_MAPPING`、two-template `AWX_READ_TEMPLATE_FINGERPRINT` and `AWX_HOST_IDENTITY_BINDINGS` artifacts；MTLS contracts use only fixed Host fixtures，AWX contracts additionally require exact diagnostic fingerprint branch、identity artifact SHA/root/count、remote attestation and survey。It computes canonical bytes/all digests in Go，passes only comparison values to SQL，inserts immutable revision+Audit+Outbox atomically，returns existing ID only for exact idempotent content，and rejects same-key drift/N+1 races。Enrollment seals only a `PENDING` Runtime outside this Publisher；network rollout/attestation later makes it APPLIED，then this sole contract writer may consume it。

- [ ] **Step 4: 实现 PostgreSQL Query 合同与仓储扫描**

~~~go
package postgresdiagnostic

type QueryID string

const (
    QueryServerHealth QueryID = "postgres.server-health.v1"
    QueryConnections QueryID = "postgres.connection-snapshot.v1"
    QueryLocks QueryID = "postgres.lock-snapshot.v1"
    QueryReplication QueryID = "postgres.replication-snapshot.v1"
    QueryDatabaseSize QueryID = "postgres.database-size.v1"
    QuerySlowSummary QueryID = "postgres.slow-query-summary.v1"
)

type ResolveRequest struct {
    Scope assetcatalog.Scope
    AssetID string
    QueryContractID string
    QueryContractRevision int64
    CapabilityDefinitionID string
    CapabilityDefinitionRevision int64
    TargetID string
    TargetDigest string
    RuntimePublicationID string
    RuntimeDigest string
    Input json.RawMessage
    InputHash string
}

type Registry interface {
    Resolve(context.Context, ResolveRequest) (QueryExecutionContract, error)
    Describe(context.Context, assetcatalog.AssetLocator) ([]PublicDescription, error)
}
~~~

Repository 每次 Resolve 使用 READ ONLY 事务和一条带 `FOR SHARE` 的查询，联结当前 Scope 的 Asset、Capability Definition、Published Target、Runtime Publication、Runner Realm 与 contract revision；要求 Snapshot/Grant 固定 revision 仍存在，且实时状态未 REVOKED/CLOSED。任何重复行、digest 不同、unknown schema 或 query bytes/hash 不一致返回统一 `ErrContractRejected`。

私有 `QueryExecutionContract` 复制 query bytes，离开扫描临时 buffer 后清零；`SQL()` 只返回包内非导出 `queryTemplate` view，外部通过后续受封装 Runner compiler 消费。String/GoString/Format/JSON 永不显示 SQL、Target、Role 或 Query parameters。

- [ ] **Step 5: 跑单元、集成、race 与泄漏扫描**

Run:

~~~bash
go test -race -shuffle=on -count=1 ./internal/hostdiagnostic ./internal/postgresdiagnostic
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test -race -count=1 ./internal/hostdiagnostic/postgres ./internal/postgresdiagnostic/postgres
rg -n -i 'command|argv|env|script|pty|forward|sftp|dsn|password|vault_path|raw_sql' internal/hostdiagnostic internal/postgresdiagnostic
~~~

Expected: tests PASS；`rg` 只命中负向测试、禁止词列表和注释，不命中任何公共 DTO、生产输入或日志格式。

- [ ] **Step 6: Commit**

~~~bash
git add internal/hostdiagnostic internal/postgresdiagnostic
git commit -m "feat: define fixed host and postgres diagnostics"
~~~
