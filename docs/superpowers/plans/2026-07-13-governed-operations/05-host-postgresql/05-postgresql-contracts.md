# PostgreSQL Named Diagnostic Query Contracts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把六个 PostgreSQL 诊断能力实现为代码与数据库双重固定的命名查询，锁定 typed 参数、事务设置、结果 schema、行/字节预算和 DLP 投影，彻底排除 caller SQL 与 timeout 覆盖。

**Architecture:** 受信任代码内嵌六个规范 SQL bytes 与 golden digest；000019 revision 必须逐字匹配同 QueryID/schema 的已知 bytes 才能发布和解析。Compiler 只把严格 JSON 参数映射为固定位置参数，另行注入私有 Target allowlist；Query contract 的 SQL 与参数永不序列化。后续 Runner 只能执行编译产物，不能传 SQL。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、pgx/v5、`encoding/json` 严格 decoder、RFC 8785 JCS、SHA-256、现有 `postgresdiagnostic`、`readconnector`、`readtarget`、`readruntime`、`readtask`。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- QueryID 只允许六个固定值；每个 QueryID 的 SQL bytes、参数顺序、结果列、预算与事务设置由代码版本锁定。
- 调用方只提交 capability 对应的 typed JSON；不得提交 SQL、fragment、table、column、operator、function、order、limit、timeout、search_path、role、database name 或 DSN。
- 多 statement、semicolon、DDL、DML、writable CTE、`COPY`、large object、临时表、`LISTEN/NOTIFY`、扩展安装、任意函数、`DO/CALL`、`EXPLAIN ANALYZE` 永远没有执行入口。
- 规范 SQL 中使用的 PostgreSQL 内置函数是逐字固定的代码资产，不是调用方函数能力；新增/修改函数必须新 QueryID revision、安全审查与 golden 更新。
- `POSTGRES_SLOW_QUERY_SUMMARY` 只在预先验证 `pg_stat_statements` 已安装且 Target contract 允许时可用；缺少扩展返回 stable unsupported，不安装扩展、不回退到 query text。
- 事务强制 READ ONLY，`search_path=pg_catalog`，固定 statement/lock/idle timeout；调用方不能缩短、延长或覆盖。
- 行、列、字段、字符串、总 bytes 与 duration 超限即拒绝；只允许合同声明的 bounded truncation，绝不返回 partial SQL stream。
- Query bytes、Target database allowlist、DSN、credential reference、原始数据库错误不得进入 JSON、日志、Trace、Metric label、Temporal、Audit 或 Evidence。
- production registry 从 PostgreSQL 读取并与内嵌资产逐字比对；测试 fake 不得进入 production wiring。
- 包 02 的 PostgreSQL Provider Runtime `AVAILABLE` 只证明 TLS/只读 transport readiness；六个 Query capability 必须形成新的 immutable successor，并保持 `PENDING` 到包 06 executor 和包 08 真实 E2E 独立验收。
- 严格 TDD；每个 Task 独立 commit。

---

## Package Position

- 顺序：5 / 8；前置包 01–04 必须完成。
- 前置接口：`postgresdiagnostic.Registry`、000019 query revision、Published Target/Runtime/Realm、`readtask.Descriptor`。
- 交付给下一包：`KnownQueryRegistry`、`CompiledQuery`、参数编译器、Row projector 与 DLP policy。
- 本包不连接生产数据库目标、不签发凭据；真实执行在包 06。

### Task 11: 固定六个 Query 资产、golden digest 与发布校验

**Files:**
- Create: `internal/postgresdiagnostic/queries.go`
- Create: `internal/postgresdiagnostic/query_assets.go`
- Create: `internal/postgresdiagnostic/query_assets_test.go`
- Create: `internal/postgresdiagnostic/query_golden_test.go`
- Create: `internal/postgresdiagnostic/publisher.go`
- Create: `internal/postgresdiagnostic/publisher_test.go`
- Modify: `internal/postgresdiagnostic/postgres/repository.go`
- Modify: `internal/postgresdiagnostic/postgres/repository_integration_test.go`
- Create: `internal/postgresdiagnostic/testdata/query-digests.json`

**Interfaces:**
- Consumes: 000019 `postgres_diagnostic_query_revisions`、Phase 2 capability revision。
- Produces: `KnownQueries.Resolve(QueryID)`、`Publisher.PublishRevision`、逐字 SQL/digest/schema 校验。

- [ ] **Step 1: 写未知/篡改/多语句/危险 token 的失败测试**

~~~go
func TestKnownQueriesContainsExactlySixVersionedAssets(t *testing.T) {
    got := KnownQueries.IDs()
    want := []QueryID{
        QueryConnections, QueryDatabaseSize, QueryLocks,
        QueryReplication, QueryServerHealth, QuerySlowSummary,
    }
    if diff := cmp.Diff(want, got); diff != "" { t.Fatal(diff) }
}

func TestPublisherRejectsAnyByteDifferentFromKnownQuery(t *testing.T) {
    known := KnownQueries.MustResolve(QueryServerHealth)
    knownSQL := sqlBytesForTest(known)
    defer clear(knownSQL)
    mutations := [][]byte{
        append(bytes.Clone(knownSQL), ';'),
        bytes.Replace(bytes.Clone(knownSQL), []byte("SELECT"), []byte("SELECT pg_sleep(1),"), 1),
        append(bytes.Clone(knownSQL), []byte("\nDELETE FROM audit_records")...),
        bytes.Replace(bytes.Clone(knownSQL), []byte("pg_catalog"), []byte("public"), 1),
    }
    for _, sql := range mutations {
        _, err := publisher.PublishRevision(ctx, publishInput(known.ID(), sql))
        if !errors.Is(err, ErrQueryRejected) { t.Fatalf("mutation error = %v", err) }
    }
}

func TestRepositoryRejectsDatabaseBytesThatDoNotMatchEmbeddedAsset(t *testing.T) {
    fixture := newQueryRepositoryFixture(t)
    fixture.tamperStoredTemplate(QueryLocks, []byte("SELECT 1"))
    _, err := fixture.repository.Resolve(ctx, fixture.request(QueryLocks))
    if !errors.Is(err, ErrQueryRejected) { t.Fatalf("Resolve() error = %v", err) }
}

func TestQueryAssetsNeverSelectSensitiveColumns(t *testing.T) {
    forbidden := regexp.MustCompile(`(?i)\b(query|client_addr|client_hostname|application_name|backend_start|usename|rolname|slot_name|conninfo)\b`)
    for _, query := range KnownQueries.All() {
        sql := sqlBytesForTest(query)
        if matches := forbidden.FindAll(sql, -1); len(matches) != 0 {
            t.Fatalf("%s contains forbidden columns: %q", query.ID(), matches)
        }
        clear(sql)
    }
}
~~~

上述敏感列扫描对 `queryid` 设精确例外，只允许 slow summary 的 `statement.queryid::text AS query_fingerprint_source`，投影前必须 HMAC；不得用宽松 substring 例外放过 `query` 正文列。

- [ ] **Step 2: 运行测试并确认 Query 资产缺失**

Run:

~~~bash
go test ./internal/postgresdiagnostic -run 'Test(KnownQueries|Publisher|Repository|QueryAssets)' -count=1
~~~

Expected: FAIL because `KnownQueries`, Publisher and golden assets do not exist.

- [ ] **Step 3: 实现 KnownQuery 的不可序列化契约**

~~~go
type ColumnType string

const (
    ColumnString ColumnType = "STRING"
    ColumnInteger ColumnType = "INTEGER"
    ColumnNumber ColumnType = "NUMBER"
    ColumnBoolean ColumnType = "BOOLEAN"
)

type ResultColumn struct {
    Name string
    Type ColumnType
    Nullable bool
    MaxBytes int
    Classification string
}

type TransactionPolicy struct {
    StatementTimeout time.Duration
    LockTimeout time.Duration
    IdleTransactionTimeout time.Duration
    MaximumDuration time.Duration
}

type knownQuery struct {
    id QueryID
    sql []byte
    parameters parameterSchema
    columns []ResultColumn
    transaction TransactionPolicy
    maxRows int
    maxBytes int
    requiredExtension string
    digest string
}

type KnownQueryRegistry interface {
    Resolve(QueryID) (KnownQuery, bool)
    IDs() []QueryID
}
~~~

`KnownQuery` 只提供 ID、digest、公开参数 schema、结果列安全描述和预算；SQL bytes 只在同包 publisher/golden 测试中访问。子包 repository 通过 `KnownQueries.MatchesBytes(QueryID, []byte) bool` 逐字验证，不取得可长期保存的 SQL accessor；传入 buffer 随扫描生命周期清零。实现 JSON/String/GoString/Format redaction，Unmarshal 拒绝。Registry 在 `init` 或构造时复核 SQL SHA-256 与嵌入 golden；任一不一致使 Control Plane/Runner 启动 fail closed。

- [ ] **Step 4: 写入六个规范 SQL bytes**

SQL 文件不得外部热加载；使用 `//go:embed` 内嵌只读资产或 Go raw string。规范格式、限定 schema、列名和位置参数固定如下。

`postgres.server-health.v1`：

~~~sql
SELECT
  pg_catalog.current_setting('server_version_num')::integer AS server_version_num,
  pg_catalog.pg_is_in_recovery() AS in_recovery,
  pg_catalog.current_setting('transaction_read_only')::boolean AS transaction_read_only,
  CASE
    WHEN pg_catalog.clock_timestamp() - pg_catalog.pg_postmaster_start_time() < interval '1 hour' THEN 'LT_1H'
    WHEN pg_catalog.clock_timestamp() - pg_catalog.pg_postmaster_start_time() < interval '1 day' THEN 'LT_1D'
    WHEN pg_catalog.clock_timestamp() - pg_catalog.pg_postmaster_start_time() < interval '7 days' THEN 'LT_7D'
    ELSE 'GTE_7D'
  END::text AS uptime_bucket
~~~

`postgres.connection-snapshot.v1`，`$1` 只由 compiler 映射 `ALL|ACTIVE|IDLE|WAITING`：

~~~sql
SELECT
  CASE
    WHEN activity.wait_event_type IS NOT NULL THEN 'WAITING'
    WHEN activity.state = 'active' THEN 'ACTIVE'
    WHEN activity.state LIKE 'idle%' THEN 'IDLE'
    ELSE 'OTHER'
  END::text AS state_bucket,
  pg_catalog.count(*)::bigint AS connection_count
FROM pg_catalog.pg_stat_activity AS activity
WHERE activity.pid <> pg_catalog.pg_backend_pid()
  AND ($1::text = 'ALL' OR
       ($1::text = 'WAITING' AND activity.wait_event_type IS NOT NULL) OR
       ($1::text = 'ACTIVE' AND activity.state = 'active') OR
       ($1::text = 'IDLE' AND activity.state LIKE 'idle%'))
GROUP BY 1
ORDER BY 1
~~~

`postgres.lock-snapshot.v1`，`$1` 为 compiler 映射的 `0|1|5|15` 秒：

~~~sql
SELECT
  lock_fact.locktype::text AS lock_type,
  lock_fact.mode::text AS lock_mode,
  lock_fact.granted,
  CASE
    WHEN lock_fact.granted THEN 'GRANTED'
    WHEN pg_catalog.extract(epoch FROM (pg_catalog.clock_timestamp() - activity.query_start)) < 5 THEN 'LT_5S'
    WHEN pg_catalog.extract(epoch FROM (pg_catalog.clock_timestamp() - activity.query_start)) < 30 THEN 'LT_30S'
    ELSE 'GTE_30S'
  END::text AS wait_bucket,
  pg_catalog.count(*)::bigint AS lock_count
FROM pg_catalog.pg_locks AS lock_fact
LEFT JOIN pg_catalog.pg_stat_activity AS activity ON activity.pid = lock_fact.pid
WHERE lock_fact.granted
   OR pg_catalog.extract(epoch FROM (pg_catalog.clock_timestamp() - activity.query_start)) >= $1::integer
GROUP BY 1, 2, 3, 4
ORDER BY 1, 2, 3, 4
~~~

`postgres.replication-snapshot.v1`，`$1` 为 `ALL|SENDER|SLOT`：

~~~sql
SELECT source_kind, state_bucket, lag_bucket, pg_catalog.count(*)::bigint AS item_count
FROM (
  SELECT
    'SENDER'::text AS source_kind,
    CASE WHEN sender.state IN ('streaming','catchup','startup','backup') THEN pg_catalog.upper(sender.state) ELSE 'OTHER' END::text AS state_bucket,
    CASE
      WHEN sender.replay_lag IS NULL THEN 'UNKNOWN'
      WHEN sender.replay_lag < interval '1 second' THEN 'LT_1S'
      WHEN sender.replay_lag < interval '10 seconds' THEN 'LT_10S'
      ELSE 'GTE_10S'
    END::text AS lag_bucket
  FROM pg_catalog.pg_stat_replication AS sender
  WHERE $1::text IN ('ALL','SENDER')
  UNION ALL
  SELECT
    'SLOT'::text,
    CASE WHEN slot.active THEN 'ACTIVE' ELSE 'INACTIVE' END::text,
    'NOT_APPLICABLE'::text
  FROM pg_catalog.pg_replication_slots AS slot
  WHERE $1::text IN ('ALL','SLOT')
) AS replication_fact
GROUP BY source_kind, state_bucket, lag_bucket
ORDER BY source_kind, state_bucket, lag_bucket
~~~

`postgres.database-size.v1`，`$1` 为 `CURRENT|PUBLISHED`，`$2::text[]` 是私有 Target 中的预发布 database allowlist，调用方不能提供名称：

~~~sql
SELECT
  candidate.ordinal::bigint AS database_ordinal,
  CASE
    WHEN pg_catalog.pg_database_size(candidate.database_name) < 1073741824 THEN 'LT_1_GIB'
    WHEN pg_catalog.pg_database_size(candidate.database_name) < 10737418240 THEN 'LT_10_GIB'
    WHEN pg_catalog.pg_database_size(candidate.database_name) < 107374182400 THEN 'LT_100_GIB'
    ELSE 'GTE_100_GIB'
  END::text AS size_bucket,
  pg_catalog.pg_database_size(candidate.database_name)::bigint AS size_bytes
FROM pg_catalog.unnest($2::text[]) WITH ORDINALITY AS candidate(database_name, ordinal)
WHERE ($1::text = 'CURRENT' AND candidate.database_name = pg_catalog.current_database())
   OR $1::text = 'PUBLISHED'
ORDER BY candidate.ordinal
~~~

`postgres.slow-query-summary.v1`，`$1` 是 minimum calls `10|100|1000`，`$2` 是 top N `5|10|20`：

~~~sql
SELECT
  statement.queryid::text AS query_fingerprint_source,
  statement.calls::bigint AS calls,
  CASE
    WHEN statement.mean_exec_time < 10 THEN 'LT_10MS'
    WHEN statement.mean_exec_time < 100 THEN 'LT_100MS'
    WHEN statement.mean_exec_time < 1000 THEN 'LT_1S'
    ELSE 'GTE_1S'
  END::text AS mean_time_bucket,
  pg_catalog.round(statement.total_exec_time::numeric, 3) AS total_exec_ms
FROM public.pg_stat_statements AS statement
WHERE statement.calls >= $1::bigint
  AND statement.queryid IS NOT NULL
ORDER BY statement.total_exec_time DESC, statement.queryid
LIMIT $2::integer
~~~

Slow query 是唯一允许 `public.pg_stat_statements` 的资产，publish 时必须把该精确 relation 记录为 required extension；运行前以固定 catalog query 验证 extension schema/name/version allowlist。它仍不得读取 `statement.query`。

- [ ] **Step 5: 实现发布事务与 golden 更新规则**

`Publisher.PublishRevision` 必须：授权为内部 signed publication，不接受 HTTP/Task；解析 QueryID；从 KnownQueries 取 exact bytes/schema/budget；拒绝调用者传来的 SQL 不等于 known bytes；验证 capability provider `POSTGRESQL` 且 capability kind 对应；在一个事务插入 revision、audit 和 outbox。Public response 仅返回 ID/revision/QueryID/schema/digest/status。

Golden 文件只保存 `{query_id, query_sha256, parameter_schema_sha256, result_schema_sha256}`，不复制 SQL。修改 SQL 必须先新增 revision、更新安全测试与本计划能力矩阵；测试提供显式 `UPDATE_POSTGRES_QUERY_GOLDEN=1` 本地命令，但 CI 禁止该变量，不能自动接受 diff。

- [ ] **Step 6: 运行单元、真实 PostgreSQL 与提交**

Run:

~~~bash
go test -race -shuffle=on -count=1 ./internal/postgresdiagnostic
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test -race -count=1 ./internal/postgresdiagnostic/postgres -run 'Test(Repository|Publisher)'
~~~

Expected: PASS；六资产、逐字比对、digest、Scope/revision、不可变发布和 sensitive-column scan 全通过。

- [ ] **Step 7: Commit**

~~~bash
git add internal/postgresdiagnostic
git commit -m "feat: publish named postgres diagnostic queries"
~~~

### Task 12: 实现 typed 参数 compiler、私有 Target 绑定和结果投影

**Files:**
- Create: `internal/postgresdiagnostic/input.go`
- Create: `internal/postgresdiagnostic/input_test.go`
- Create: `internal/postgresdiagnostic/compiler.go`
- Create: `internal/postgresdiagnostic/compiler_test.go`
- Create: `internal/postgresdiagnostic/projection.go`
- Create: `internal/postgresdiagnostic/projection_test.go`
- Create: `internal/postgresdiagnostic/dlp.go`
- Create: `internal/postgresdiagnostic/dlp_test.go`
- Modify: `internal/readtarget/types.go`
- Modify: `internal/readtarget/contract.go`
- Modify: `internal/readtarget/manifest_test.go`
- Modify: `internal/readruntime/binder.go`
- Modify: `internal/readruntime/binder_test.go`
- Create: `internal/capability/postgres_diagnostic_publication.go`
- Create: `internal/capability/postgres_diagnostic_publication_test.go`
- Modify: `internal/runtimepublication/service.go`
- Modify: `internal/runtimepublication/service_test.go`

**Interfaces:**
- Consumes: `KnownQuery`、`postgresdiagnostic.QueryExecutionContract`、私有 Published Target、`readtask.Descriptor`。
- Produces: 不可序列化 `CompiledQuery`、`ResultProjector`、DLP 后 `readtask.EvidenceCompletion`，以及绑定 exact Provider Runtime/query/executor contract 的 PostgreSQL Capability successor `PENDING` publication。

- [ ] **Step 1: 写参数矩阵、私有参数与 caller override 失败测试**

~~~go
func TestCompileAcceptsOnlyCapabilityParameterEnums(t *testing.T) {
    cases := []struct { id QueryID; input string; wantArgs []any }{
        {QueryServerHealth, `{}`, nil},
        {QueryConnections, `{"state":"WAITING"}`, []any{"WAITING"}},
        {QueryLocks, `{"minimum_wait_seconds":5}`, []any{5}},
        {QueryReplication, `{"replication_scope":"SENDER"}`, []any{"SENDER"}},
        {QueryDatabaseSize, `{"database_scope":"CURRENT"}`, []any{"CURRENT", []string{"app"}}},
        {QuerySlowSummary, `{"minimum_calls":100,"top_n":10}`, []any{int64(100), 10}},
    }
    for _, tc := range cases {
        compiled, err := compiler.Compile(ctx, request(tc.id, tc.input))
        if err != nil { t.Fatalf("%s: %v", tc.id, err) }
        assertArgsForTestOnly(t, compiled, tc.wantArgs)
    }
}

func TestCompileRejectsSQLAndExecutionOverrides(t *testing.T) {
    forbidden := []string{
        `{"sql":"select 1"}`, `{"query":"select 1"}`, `{"timeout_ms":1}`,
        `{"statement_timeout":"0"}`, `{"lock_timeout":"0"}`,
        `{"search_path":"public"}`, `{"role":"postgres"}`,
        `{"database":"template1"}`, `{"limit":100000}`, `{"function":"pg_sleep"}`,
    }
    for _, input := range forbidden {
        _, err := compiler.Compile(ctx, request(QueryServerHealth, input))
        if !errors.Is(err, ErrInputRejected) { t.Fatalf("%s error = %v", input, err) }
    }
}

func TestCompiledQueryCannotMarshalLogOrUnmarshal(t *testing.T) {
    compiled := compileValid(t)
    encoded, err := json.Marshal(compiled)
    if err != nil || string(encoded) != `{"redacted":true}` { t.Fatalf("%s %v", encoded, err) }
    for _, rendered := range []string{fmt.Sprint(compiled), fmt.Sprintf("%#v", compiled)} {
        assertNotContainsSensitive(t, rendered)
    }
}

func TestProjectorRejectsUnknownColumnOversizeAndDLPFailure(t *testing.T) {
    for _, rows := range []RowSource{
        rowsWithUnknownColumn(), rowsOverLimit(), rowsWithOversizeString(), rowsWithSecretPattern(),
    } {
        _, err := projector.Project(ctx, QueryConnections, rows)
        if !errors.Is(err, ErrResultRejected) { t.Fatalf("error = %v", err) }
    }
}

func TestPostgresCapabilitySuccessorRequiresExactProviderRuntimeAndQueryDigest(t *testing.T)
func TestPostgresCapabilitySuccessorStaysPendingUntilRunnerAndE2EAttestation(t *testing.T)
~~~

- [ ] **Step 2: 运行失败测试**

Run:

~~~bash
go test ./internal/postgresdiagnostic ./internal/readtarget ./internal/readruntime -run 'Test(Compile|Compiled|Projector)' -count=1
~~~

Expected: FAIL because compiler, PostgreSQL private Target fields and projector do not exist.

- [ ] **Step 3: 实现 canonical typed input compiler**

Input structs固定如下，全部 `additionalProperties=false` 等价严格解析，缺省值由合同提供而非自由值：

~~~go
type ConnectionInput struct { State string `json:"state"` }
type LockInput struct { MinimumWaitSeconds int `json:"minimum_wait_seconds"` }
type ReplicationInput struct { ReplicationScope string `json:"replication_scope"` }
type DatabaseSizeInput struct { DatabaseScope string `json:"database_scope"` }
type SlowSummaryInput struct {
    MinimumCalls int64 `json:"minimum_calls"`
    TopN int `json:"top_n"`
}
~~~

允许枚举精确为：State `ALL|ACTIVE|IDLE|WAITING`；MinimumWait `0|1|5|15`；Replication `ALL|SENDER|SLOT`；Database `CURRENT|PUBLISHED`；MinimumCalls `10|100|1000`；TopN `5|10|20`。Server health 只接受 canonical `{}`。Input 必须与 descriptor InputHash、contract parameter schema hash、Runtime digest 一致。

~~~go
type CompileRequest struct {
    Descriptor readtask.Descriptor
    Contract QueryExecutionContract
    Target readtarget.Target
}

type Compiler interface {
    Compile(context.Context, CompileRequest) (CompiledQuery, error)
}
~~~

Database allowlist 仅从 Target 私有 `DatabaseNames()` copy 进入第二参数，并在 use 后清空 slice；调用方只决定 `CURRENT|PUBLISHED`。Target 构造时要求 TLS/SNI/CA、database、READ credential role、Network Policy、READ_DATABASE Realm、read-replica preference 和 allowlist 都来自已发布 revision。Target JSON/String 继续 redacted。

- [ ] **Step 4: 实现不可变 CompiledQuery 与事务策略**

`CompiledQuery` 持有 KnownQuery 的私有 SQL copy、位置参数 copy、Target/contract/runtime/input digest 与固定 transaction policy。外部只能读取 ID、digest、预算和 `Matches(descriptor,target)`。它提供单次 `Consume(func(ExecutionMaterial) error) error`；`ExecutionMaterial` 本身 redacted，并仅在 callback 内通过 `WithSQLAndArgs(func([]byte, []any) error)` 暴露临时 copy，callback 返回后无条件清零。架构测试扫描全仓，要求 `Consume` 与 `WithSQLAndArgs` 的 production call site 只能位于 `internal/postgresrunner`；重复消费返回 `ErrQueryRejected`。

固定策略：server health 1500/100/2500ms；connections 2000/100/3000ms；locks 2500/250/3500ms；replication 2500/250/3500ms；database size 3000/250/4000ms；slow summary 4000/250/5000ms，顺序为 statement/lock/idle timeout，整体 deadline 再比 statement 多 500ms。调用方任何 context deadline 更长仍被缩短，deadline 更短可取消但不能改变 DB `SET LOCAL`。

- [ ] **Step 5: 实现严格列投影、HMAC 与 DLP**

`ResultProjector` 必须在 rows 读取前比对 `FieldDescriptions()` 的列名、顺序和 OID；每行 scan 到固定 Go 类型，拒绝 NULL 漂移、NaN/Inf、numeric overflow、无效 UTF-8、控制字符和超限。先建立 canonical safe rows，再按 JCS bytes 累计总额；达到 cap 时若合同 `AllowTruncation=false` 整体拒绝。

Slow summary 的 `query_fingerprint_source` 立即用 Scope-specific HMAC key 转成 `query_fingerprint`，原 string 清空且永不进入 Evidence。Database ordinal 只显示 `CURRENT` 或 `PUBLISHED_01` 等稳定 alias。所有结果执行通用 secret/token/password/private-key/DSN/URI/email/IP policy；分类字段按合同 redact/HMAC，无法分类返回 `DLP_REJECTED`。

Evidence summary 固定包含：QueryID、schema version、input hash、row count、byte count、truncated、redaction count、collected_at、result digest；不包含 SQL、args、database name、Target 或内部 error。

- [ ] **Step 6: 发布 PostgreSQL Capability successor 但保持运行门关闭**

对六个 Query 分别编译新的 CapabilitySet/Runtime successor，绑定包 02 exact PostgreSQL Provider Runtime、KnownQuery/000019 revision 与 golden digest、parameter/result/DLP schema、READ_DATABASE Realm、Target/Network Policy 和预期 `postgresrunner` executor digest。任何 Query 单独失败只关闭该 Query revision，不得用 server-health 成功推断 slow-summary 可用。

publication 初始固定 `PENDING`；包 06 完成真实 Runner/credential/cleanup 只能把 executor readiness 写入 successor，仍不能直接 `AVAILABLE`。包 08 必须按 exact closure 对每个 Query 运行真实 PostgreSQL、负向矩阵和 Evidence/cleanup 验证后写独立 attestation；任一 drift 关闭对应 Query gate，Provider readiness gate 保持正交。

- [ ] **Step 7: 跑 fuzz、race 与 sensitive projection 测试**

Run:

~~~bash
go test -race -shuffle=on -count=1 ./internal/postgresdiagnostic ./internal/readtarget ./internal/readruntime
go test ./internal/postgresdiagnostic -run '^Fuzz' -fuzz=FuzzStrictInput -fuzztime=20s
go test ./internal/postgresdiagnostic -run '^Fuzz' -fuzz=FuzzProjectRows -fuzztime=20s
~~~

Expected: PASS；fuzz 无 panic/OOM，所有 unsafe input 在编译阶段拒绝，所有 sensitive row 在 Evidence 前拒绝或按合同脱敏。

- [ ] **Step 8: Commit**

~~~bash
git add internal/postgresdiagnostic internal/readtarget internal/readruntime internal/capability/postgres_diagnostic_publication.go internal/capability/postgres_diagnostic_publication_test.go internal/runtimepublication
git commit -m "feat: compile bounded postgres diagnostics"
~~~
