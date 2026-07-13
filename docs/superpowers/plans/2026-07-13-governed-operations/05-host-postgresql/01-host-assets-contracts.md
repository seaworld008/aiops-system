# Host Diagnostic Facts and Contracts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 以固定迁移 `000019_host_postgresql_read_diagnostics` 和纯 Go 领域契约锁定 Host Probe、AWX 模板、PostgreSQL 命名查询、READ 凭据 cleanup 与诊断 Receipt 的不可变事实边界。

**Architecture:** PostgreSQL 只保存版本化合同、生命周期事实和安全摘要；私有执行内容由受信任发布流程写入，浏览器、Task、模型与 Runner 请求都不能创建或覆盖。领域层用不透明 ID、严格 union、JCS/SHA-256 和红acted marshal 把六表投影为后续执行包可消费的窄接口。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、pgx/v5、RFC 8785 JCS、SHA-256、现有 `assetcatalog`、`connectionprofile`、`runtimepublication`、`investigationgrant`、`readtask`、`store`。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- 实现基线固定为 `main@ad50d9f`；执行前创建独立 worktree，不删除或修改用户已有 worktree。
- 迁移名和文件名必须精确为 `000019_host_postgresql_read_diagnostics`；只创建 README 指定的六张新表。允许且必须做本阶段所需的 additive 兼容变更（Provider allowlist、Environment candidate key、Audit Environment projection），但不得改变 Phase 1–4 领域语义或绕过其状态机。
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
- 交付给下一包：`hostdiagnostic.Registry`、`postgresdiagnostic.Registry`、六表 PostgreSQL repository 与稳定 schema/状态常量。
- 本包只建立事实与合同，不发网络请求、不签发凭据、不接入公共 API。

### Task 1: 创建 000019 六表迁移与完整性保护

**Files:**
- Create: `migrations/000019_host_postgresql_read_diagnostics.up.sql`
- Create: `migrations/000019_host_postgresql_read_diagnostics.down.sql`
- Modify: `internal/store/postgres/migrations_integration_test.go`

**Interfaces:**
- Consumes: 000015 `assets`，000016 Connection/Target/Capability/Runtime/Realm，000018 Snapshot/Grant，现有 `investigation_task_attempts`、`evidence`、`runner_evidence_receipts`、`audit_records`。
- Produces: 六张表、不可变触发器、cleanup claim 索引、Receipt 唯一性、guarded down migration。

- [ ] **Step 1: 写失败的迁移、作用域、不可变与 rollback 测试**

在 `migrations_integration_test.go` 增加以下真实 PostgreSQL 18.4+ 测试；不得用 sqlmock 代替迁移验收：

~~~go
func TestHostPostgreSQLDiagnosticsMigrationOwnsExactlySixTables(t *testing.T) {
    database := openMigrationDatabase(t)
    migrateThrough(t, database, 19)
    got := migrationTables(t, database, []string{
        "host_probe_contract_revisions",
        "awx_read_template_revisions",
        "postgres_diagnostic_query_revisions",
        "read_credential_leases",
        "read_credential_cleanup_attempts",
        "diagnostic_execution_receipts",
    })
    if diff := cmp.Diff([]string{
        "awx_read_template_revisions", "diagnostic_execution_receipts",
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
~~~

- [ ] **Step 2: 运行测试并确认 000019 缺失**

Run:

~~~bash
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/store/postgres -run 'Test(HostPostgreSQLDiagnostics|DiagnosticContracts|DiagnosticCredential)' -count=1
~~~

Expected: FAIL，错误明确指出 migration 19 或六张表不存在；不能因环境未设置而把 CI 验收标记为通过。

- [ ] **Step 3: 实现合同事实表**

Up migration 先在事务中验证 000015/000016/000018 前置表，设置 `lock_timeout='5s'` 和限定 search path，再创建合同表。字段与检查至少如下，执行者不得增加自由输入列：

~~~sql
BEGIN;
SET LOCAL lock_timeout = '5s';
SELECT pg_catalog.set_config(
  'search_path', pg_catalog.quote_ident(current_schema()) || ',pg_catalog', true
);

DO $$
BEGIN
  IF to_regclass('public.assets') IS NULL
     OR to_regclass('public.capability_definitions') IS NULL
     OR to_regclass('public.runtime_publications') IS NULL
     OR to_regclass('public.investigation_grants') IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='55000',
      MESSAGE='000015, 000016 and 000018 are required',
      CONSTRAINT='host_postgresql_read_diagnostics_prerequisite';
  END IF;
END $$;

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
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  environment_id uuid NOT NULL,
  id uuid NOT NULL,
  revision bigint NOT NULL CHECK (revision > 0),
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
  input_schema jsonb NOT NULL CHECK (
    jsonb_typeof(input_schema) = 'object'
    AND input_schema->>'type' = 'object'
    AND input_schema->>'additionalProperties' = 'false'
    AND jsonb_typeof(input_schema->'properties') = 'object'
    AND NOT ((input_schema->'properties') ?| ARRAY[
      'command','argv','env','path','glob','script','interpreter','stdin',
      'shell','pty','ssh','winrm','forward','sftp','endpoint','header'
    ])
  ),
  evidence_schema_version text NOT NULL,
  evidence_schema jsonb NOT NULL CHECK (jsonb_typeof(evidence_schema) = 'object'),
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
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  environment_id uuid NOT NULL,
  id uuid NOT NULL,
  revision bigint NOT NULL CHECK (revision > 0),
  capability_definition_id uuid NOT NULL,
  capability_definition_revision bigint NOT NULL,
  provider_kind text NOT NULL CHECK (provider_kind = 'AWX_API'),
  inventory_id bigint NOT NULL CHECK (inventory_id > 0),
  job_template_id bigint NOT NULL CHECK (job_template_id > 0),
  limit_map jsonb NOT NULL CHECK (jsonb_typeof(limit_map) = 'object'),
  extra_vars_schema jsonb NOT NULL CHECK (
    jsonb_typeof(extra_vars_schema) = 'object'
    AND extra_vars_schema->>'type' = 'object'
    AND extra_vars_schema->>'additionalProperties' = 'false'
    AND jsonb_typeof(extra_vars_schema->'properties') = 'object'
    AND NOT ((extra_vars_schema->'properties') ?| ARRAY[
      'command','argv','env','path','script','shell','credential',
      'inventory','job_template','limit','tags','verbosity','timeout'
    ])
  ),
  output_projection_schema jsonb NOT NULL CHECK (jsonb_typeof(output_projection_schema) = 'object'),
  max_poll_seconds integer NOT NULL CHECK (max_poll_seconds BETWEEN 1 AND 120),
  max_result_items integer NOT NULL CHECK (max_result_items BETWEEN 1 AND 200),
  max_result_bytes integer NOT NULL CHECK (max_result_bytes BETWEEN 1024 AND 262144),
  template_digest text NOT NULL CHECK (template_digest ~ '^[a-f0-9]{64}$'),
  status text NOT NULL CHECK (status = 'AVAILABLE'),
  created_by text NOT NULL CHECK (octet_length(created_by) BETWEEN 1 AND 256),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, workspace_id, environment_id, id, revision),
  UNIQUE (tenant_id, workspace_id, environment_id, inventory_id, job_template_id, revision),
  FOREIGN KEY (tenant_id, workspace_id, environment_id,
               capability_definition_id, capability_definition_revision)
    REFERENCES capability_definitions
      (tenant_id, workspace_id, environment_id, id, revision)
);

CREATE TABLE postgres_diagnostic_query_revisions (
  tenant_id uuid NOT NULL,
  workspace_id uuid NOT NULL,
  environment_id uuid NOT NULL,
  id uuid NOT NULL,
  revision bigint NOT NULL CHECK (revision > 0),
  capability_definition_id uuid NOT NULL,
  capability_definition_revision bigint NOT NULL,
  provider_kind text NOT NULL CHECK (provider_kind = 'POSTGRESQL'),
  query_id text NOT NULL CHECK (query_id IN (
    'postgres.server-health.v1', 'postgres.connection-snapshot.v1',
    'postgres.lock-snapshot.v1', 'postgres.replication-snapshot.v1',
    'postgres.database-size.v1', 'postgres.slow-query-summary.v1'
  )),
  input_schema_version text NOT NULL CHECK (input_schema_version = 'postgres-diagnostic-input.v1'),
  input_schema jsonb NOT NULL CHECK (
    jsonb_typeof(input_schema) = 'object'
    AND input_schema->>'type' = 'object'
    AND input_schema->>'additionalProperties' = 'false'
    AND jsonb_typeof(input_schema->'properties') = 'object'
    AND NOT ((input_schema->'properties') ?| ARRAY[
      'sql','query','statement','timeout','statement_timeout','lock_timeout',
      'search_path','role','database','dsn','function','extension','explain_analyze'
    ])
  ),
  result_schema_version text NOT NULL,
  result_schema jsonb NOT NULL CHECK (jsonb_typeof(result_schema) = 'object'),
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

数据库触发器使用 PostgreSQL 18 core binary hashing，与现有迁移保持一致：`pg_catalog.encode(pg_catalog.sha256(NEW.query_template), 'hex') = NEW.query_sha256`，保证 bytes/hash 一致；不得调用不存在的 `pg_catalog.digest`，也不为此引入 `pgcrypto` 扩展。`input_schema`/`result_schema`/`limit_map` 只允许 canonical JSON 对象。集成测试覆盖 bytes/hash mismatch 与错误 schema 拒绝；这里不宣称普通 SQL 等值比较具备常量时间性质。

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
  usage_role text NOT NULL CHECK (usage_role = 'READ_DATABASE'),
  accessor_ciphertext bytea,
  accessor_key_id text CHECK (accessor_key_id IS NULL OR octet_length(accessor_key_id) BETWEEN 1 AND 128),
  accessor_hmac text CHECK (accessor_hmac IS NULL OR accessor_hmac ~ '^[a-f0-9]{64}$'),
  issued_at timestamptz,
  expires_at timestamptz NOT NULL,
  cleanup_state text NOT NULL CHECK (cleanup_state IN (
    'NOT_ISSUED','ISSUED','CLEANUP_PENDING','CLEANUP_CLAIMED',
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
          AND issued_at IS NULL AND cleanup_reason IS NULL)
      OR (cleanup_state = 'NO_CREDENTIAL' AND accessor_ciphertext IS NULL)
      OR (cleanup_state IN ('ISSUED','CLEANUP_PENDING','CLEANUP_CLAIMED','REVOKED')
          AND accessor_ciphertext IS NOT NULL AND issued_at IS NOT NULL)
      OR cleanup_state IN ('UNCERTAIN','MANUAL_REQUIRED')),
  CHECK ((cleanup_state IN ('NOT_ISSUED','ISSUED') AND cleanup_reason IS NULL)
      OR (cleanup_state NOT IN ('NOT_ISSUED','ISSUED') AND cleanup_reason IS NOT NULL)),
  CHECK (expires_at > created_at),
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
  failure_code text,
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
  CHECK ((credential_lease_id IS NULL AND cleanup_state = 'NO_CREDENTIAL')
      OR (credential_lease_id IS NOT NULL AND cleanup_state <> 'NO_CREDENTIAL')),
  CHECK ((outcome = 'SUCCEEDED' AND evidence_id IS NOT NULL
          AND evidence_content_hash IS NOT NULL AND runner_receipt_id IS NOT NULL
          AND failure_code IS NULL AND dlp_state <> 'REJECTED'
          AND cleanup_state IN ('REVOKED','NO_CREDENTIAL'))
      OR (outcome <> 'SUCCEEDED' AND failure_code IS NOT NULL))
);

CREATE INDEX read_credential_cleanup_claim_idx
  ON read_credential_leases (updated_at, id)
  WHERE cleanup_state IN ('CLEANUP_PENDING','UNCERTAIN');
CREATE INDEX diagnostic_receipts_asset_idx
  ON diagnostic_execution_receipts
    (tenant_id, workspace_id, environment_id, asset_id, created_at DESC, id DESC);
~~~

增加两个确定性 constraint trigger，不能留给执行者临时“对齐”：

- `read_credential_lease_reference_guard` 使用一条 `SELECT ... FOR SHARE` 锁定 Attempt、Grant、Grant 的 Asset Snapshot Item、Asset、Capability Definition、Published Target、APPLIED Runtime Publication、READ+enabled Realm 与 AVAILABLE Realm Binding；逐项比较 Environment、Asset revision、Target ref/id、Runtime id/bundle digest、Capability id/revision、Realm id、Grant status/expiry。零行、多行、摘要漂移或 Capability 不在 Snapshot set 都以 SQLSTATE `23514` 拒绝。
- `diagnostic_execution_receipt_reference_guard` 按 `contract_kind` 只允许三条显式分支：`HOST_PROBE` 锁 `host_probe_contract_revisions`、`AWX_TEMPLATE` 锁 `awx_read_template_revisions`、`POSTGRES_QUERY` 锁 `postgres_diagnostic_query_revisions`；每条都验证同 Scope 的 contract id/revision/digest 与 Capability Definition。随后验证 Evidence 属于同 Investigation、Runner Receipt 属于同 Environment/Task/Attempt 且 hash 相等、Credential Lease cleanup 状态一致、Audit Record 的 Environment/resource type/resource id/payload hash 指向本 Receipt。未知 kind、缺失可选对象但状态声称存在、或任一不一致均拒绝。

所有候选键在本计划中已明确：Phase 2 提供 Published Target/Capability/Runtime/Realm scoped key，000011 的 Attempt 由本迁移新增 Environment candidate key，000019 同时为 Runner Receipt 与 Audit Record 新增 Environment candidate key。禁止无作用域单列 FK、删 FK、`NOT VALID` 永不验证或只靠应用层检查。

- [ ] **Step 5: 添加 immutable triggers、guarded down 并验证**

三个合同表与 Receipt 表拒绝 UPDATE/DELETE/TRUNCATE，SQLSTATE 固定 `55000`；凭据两表只允许状态机列、版本与时间的受控变化。Down 在任一六表有行时整体拒绝：

~~~sql
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM host_probe_contract_revisions)
     OR EXISTS (SELECT 1 FROM awx_read_template_revisions)
     OR EXISTS (SELECT 1 FROM postgres_diagnostic_query_revisions)
     OR EXISTS (SELECT 1 FROM read_credential_leases)
     OR EXISTS (SELECT 1 FROM read_credential_cleanup_attempts)
     OR EXISTS (SELECT 1 FROM diagnostic_execution_receipts)
     OR EXISTS (SELECT 1 FROM connection_profiles WHERE provider_kind IN (
          'HOST_PROBE_MTLS','AWX_API','POSTGRESQL'))
     OR EXISTS (SELECT 1 FROM runner_capability_bindings WHERE provider_kind IN (
          'HOST_PROBE_MTLS','AWX_API','POSTGRESQL'))
     OR EXISTS (SELECT 1 FROM capability_definitions WHERE provider_kind IN (
          'HOST_PROBE_MTLS','AWX_API','POSTGRESQL'))
     OR EXISTS (SELECT 1 FROM audit_records WHERE environment_id IS NOT NULL) THEN
    RAISE EXCEPTION USING ERRCODE='55000',
      MESSAGE='unsafe host/postgresql diagnostics rollback: state remains',
      CONSTRAINT='host_postgresql_read_diagnostics_down_guard';
  END IF;
END $$;
~~~

空状态下的 down 顺序固定：删除六表 trigger/index/table；删除 `audit_records_environment_resource_uk`、`audit_records_environment_scope_fk` 和 `environment_id`；删除 Runner Receipt/Attempt 新 candidate key；把 Capability Definition、Runner Binding、Connection Profile 三个 Provider check 恢复为 Phase 3 的 `PROMETHEUS|VICTORIAMETRICS|VICTORIALOGS|VICTORIATRACES`。不得 `CASCADE`，也不得留下接受诊断 Provider 的半回滚约束。

Run:

~~~bash
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/store/postgres -run 'Test(HostPostgreSQLDiagnostics|DiagnosticContracts|DiagnosticCredential)' -count=1
~~~

Expected: PASS；六表所有权、三组 Provider allowlist、复合作用域、跨 Environment Attempt 拒绝、Grant Snapshot closure、polymorphic contract trigger、Evidence/Runner Receipt/Audit 绑定、不可变、单 Attempt Credential、Receipt 一致性、非空 down guard 与空库 up/down/up 全部通过。

- [ ] **Step 6: Commit**

~~~bash
git add migrations/000019_host_postgresql_read_diagnostics.up.sql migrations/000019_host_postgresql_read_diagnostics.down.sql internal/store/postgres/migrations_integration_test.go
git commit -m "feat: add host and postgres diagnostic facts"
~~~

### Task 2: 实现版本化合同领域与 PostgreSQL Registry

**Files:**
- Create: `internal/hostdiagnostic/types.go`
- Create: `internal/hostdiagnostic/canonical.go`
- Create: `internal/hostdiagnostic/registry.go`
- Create: `internal/hostdiagnostic/postgres/repository.go`
- Create: `internal/hostdiagnostic/types_test.go`
- Create: `internal/hostdiagnostic/registry_test.go`
- Create: `internal/hostdiagnostic/postgres/repository_integration_test.go`
- Create: `internal/postgresdiagnostic/types.go`
- Create: `internal/postgresdiagnostic/registry.go`
- Create: `internal/postgresdiagnostic/postgres/repository.go`
- Create: `internal/postgresdiagnostic/types_test.go`
- Create: `internal/postgresdiagnostic/postgres/repository_integration_test.go`

**Interfaces:**
- Consumes: 六表中的三个 contract revision 表、`assetcatalog.Scope`、Phase 2 Published Capability/Runtime safe projection。
- Produces: `hostdiagnostic.Registry.Resolve`、`postgresdiagnostic.Registry.Resolve`、不可序列化 `HostExecutionContract`/`QueryExecutionContract` 和公共安全描述。

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
~~~

- [ ] **Step 2: 运行测试并确认领域包不存在**

Run:

~~~bash
go test ./internal/hostdiagnostic ./internal/postgresdiagnostic -count=1
~~~

Expected: FAIL because the packages and types do not exist.

- [ ] **Step 3: 实现精确 Host 合同接口**

~~~go
package hostdiagnostic

type Capability string
type Provider string

const (
    ProviderMTLS Provider = "HOST_PROBE_MTLS"
    ProviderAWX  Provider = "AWX_API"
    CapabilitySystemInfo Capability = "HOST_SYSTEM_INFO"
    CapabilityCPUMemory Capability = "HOST_CPU_MEMORY_SNAPSHOT"
    CapabilityDiskUsage Capability = "HOST_DISK_USAGE"
    CapabilityListeners Capability = "HOST_NETWORK_LISTENERS"
    CapabilitySystemd Capability = "HOST_SYSTEMD_STATUS"
    CapabilityWindowsService Capability = "HOST_WINDOWS_SERVICE_STATUS"
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
~~~

`ExecutionContract` 字段全部私有，仅提供 `Capability()`、`Provider()`、`ContractID()`、`Revision()`、`Digest()`、`InputHash()`、`Budget()`、`Matches(readtask.Descriptor)` 和受包控制的 `MTLS()`/`AWX()` view。其 `MarshalJSON` 固定返回 `{"redacted":true}`，Unmarshal 固定拒绝。

输入严格 union：CPU sample window 只允许 `5|15|30`；disk scope 只允许 `LOCAL|ALL_FIXED`；address family 只允许 `IPV4|IPV6|BOTH`；unit/service/log source 必须从合同内 enum 映射，调用方值不能成为 path/argv；lookback 只允许 `60|300|900`。空对象必须是 canonical `{}`，所有未知键、duplicate key、非 NFC 字符串和 trailing bytes 拒绝。

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
