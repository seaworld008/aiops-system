# External CMDB Governed Discovery Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 实现首个非通用 HTTP 代理的 `EXTERNAL_CMDB` 生产 Provider，通过固定 CMDB Catalog v1 协议增量发现资产/关系，保留字段来源、软删除/恢复、Scope 和独立可用门。

**Architecture:** Source Revision 只选择 server-installed `CMDB_CATALOG_V1` profile 和 opaque Credential/Trust/Network references。External CMDB Adapter 只负责固定 `/v1/capabilities`、`/v1/assets`、`/v1/relations` 读协议与 Provider 专属规范化；通用 claim、lease/fence、limiter、cleanup、page commit 和 terminal 状态机由 [Pack 09](./09-discovery-worker-ha-e2e.md) 的已合并 primitives 与 provider-neutral Worker core 唯一拥有。上游页面被规范化、DLP、限额后才通过既有 `PageCommitter` 进入 fenced PostgreSQL projection。不提供 URL template、任意 Header/Body、字段表达式或通用 CMDB 查询。

**Tech Stack:** Go 1.26.5、`net/http`、TLS 1.3/mTLS、OAuth2 client assertion via opaque reference、OpenAPI 3.1 CMDB Catalog v1、PostgreSQL 18.4。

## Global Constraints

- 前置完成 [05-source-ingestion-csv-api.md](./05-source-ingestion-csv-api.md)；只消费其 `discoverysource.Provider`、Source Revision、Run/Fence/Checkpoint 契约。
- 每个 Task 严格执行 `Red → Green → Refactor`：先运行并保留预期失败，再做最小生产实现，随后消除重复、复跑指定验证并按 Task 提交；不得跳过失败或弱化断言。
- `EXTERNAL_CMDB` 不是通用 REST connector；只有 `CMDB_CATALOG_V1` 固定路径、方法、query 参数和响应 Schema。其他厂商必须新增独立 profile/adapter/test/gate。
- 上游凭据必须是最小只读权限；DB/API/UI/Run payload 只保存 `CredentialReferenceID`，原始 Token、client secret、CA、endpoint 只能存在 Worker 进程内并在本次 lease 结束时清理。
- Checkpoint 是 `(snapshot_epoch,updated_at,external_id,asset_cursor,relation_cursor)` 的加密投影；audit 只留 hash/version。
- 每页最多 500 assets、2,000 relations、4 MiB、15 秒；每来源 5 req/s burst 10，全 Workspace 20 req/s，`429/503` 尊重最大 60 秒 `Retry-After` 并持久化 backpressure。
- 只有完整 snapshot 结束或经已验证 TLS/runtime binding 收到 fixed-wire `deleted=true` tombstone 才标记 `STALE`；该 wire contract 没有对象级签名字段，断页、超时、部分成功不进行 missing detection。
- CMDB 不得覆盖 Owner、Service、Criticality、DataClassification 或人工标签；跨来源候选只创建 Conflict。
- 真实协议 E2E 使用 TLS socket 和严格 wire fixture；上线前还必须通过非生产 CMDB endpoint canary，不能仅凭 mock 开门。
- Task 18B 必须等待 [Pack 09 Task 28A](./09-discovery-worker-ha-e2e.md#task-28a-provider-neutral-worker-core-and-claim-runtime-seam) 的稳定 `Produces` 合并，只做 External-CMDB-specific durable reconciliation/lifecycle integration；它不得读取 Task 28A/28B/28C 未合并内部实现，也不得重新实现 Queue、Worker、lease/fence、Limiter、CleanupBroker 或 PageCommitter 通用状态机。
- 完成后进入 [07-source-vsphere.md](./07-source-vsphere.md)。

---

### Task 17: Fixed CMDB Catalog v1 client, identity probe, and safe schema

**Files:**
- Create: `api/openapi/external-cmdb-catalog-v1.yaml`
- Create: `internal/assetsource/externalcmdb/client.go`
- Create: `internal/assetsource/externalcmdb/protocol.go`
- Create: `internal/assetsource/externalcmdb/validate.go`
- Create: `internal/assetsource/externalcmdb/normalize.go`
- Create: `internal/assetsource/externalcmdb/client_test.go`
- Create: `internal/assetsource/externalcmdb/normalize_test.go`
- Create: `internal/assetsource/externalcmdb/protocol_contract_test.go`

**Interfaces:**
- Consumes: `discoverysource.Provider`, non-serializable `BoundRuntime`, exact source revision/fence/limits.
- Produces: `externalcmdb.New(ClientFactory) (discoverysource.Provider, error)` for `SourceKind=EXTERNAL_CMDB`, `ProviderKind=CMDB_CATALOG_V1`.
- Wire operations are only `GET /v1/capabilities`, `GET /v1/assets`, and `GET /v1/relations`.

- [ ] **Step 1: Write failing protocol and identity tests**

~~~go
func TestValidateRequiresPinnedAuthorityAndReadOnlyCapabilities(t *testing.T) {
	server := newCatalogTLSServer(t, catalogCapabilities{
		Protocol: "cmdb-catalog/v1", AuthorityID: "cmdb-staging-01",
		Permissions: []string{"assets.read", "relations.read"},
	})
	provider := newProviderForServer(t, server, expectedAuthority("cmdb-production-01"))
	proof, err := provider.Validate(context.Background(), server.Runtime(), validValidationRequest())
	if err != nil || proof.Outcome != assetcatalog.ValidationOutcomeFailed || proof.Code != "AUTHORITY_REJECTED" {
		t.Fatalf("Validate = (%#v, %v)", proof, err)
	}
}

func TestClientHasNoCallerSelectedMethodPathOrHeader(t *testing.T) {
	typeOfRequest := reflect.TypeOf(discoverysource.DiscoverRequest{})
	for _, forbidden := range []string{"URL", "Endpoint", "Path", "Method", "Header", "Body", "Query"} {
		if _, ok := typeOfRequest.FieldByName(forbidden); ok {
			t.Fatalf("DiscoverRequest exposes %s", forbidden)
		}
	}
}
~~~

Run: `go test ./internal/assetsource/externalcmdb -count=1`

Expected: FAIL because the CMDB provider and protocol contract do not exist.

- [ ] **Step 2: Define the closed protocol and validation proof**

The protocol contract allows only stable fields:

~~~text
Capability: protocol_version, authority_id, permissions, snapshot_epoch, max_page_size,
            supports_delta, supports_tombstone, server_time
Asset: external_id, type_code, display_name, object_revision_positive_int64, updated_at,
       deleted, tombstone_reason, attributes{allow-listed code:string}
Relation: external_id, from_external_id, to_external_id, type_code,
          object_revision_positive_int64, updated_at, deleted
Page: items, next_cursor, snapshot_epoch, final_page, complete_snapshot
~~~

No response may include secrets, arbitrary nested objects, executable text, HTML, endpoint, credential or opaque vendor payload. `object_revision` is canonical decimal `1..MaxInt64`, not an opaque token. `CMDB_CATALOG_V1` Source Profile is `SINGLE_ENVIRONMENT`: the immutable authority scope must resolve to exactly one same-Workspace Environment, Adapter assigns that Environment to every item/relation, and the wire protocol cannot choose it. `Validate` performs TLS/SNI/CA and optional client-certificate verification, authority ID equality, clock skew ≤60s, protocol equality, read-only permission exactness, one max-limit asset probe and schema/DLP checks. Its pre-cleanup Provider proof exposes only the fixed safe check codes/counts/digests, including `CREDENTIAL_OPEN`; Broker revocation/cleanup is proved later and independently by `ATTEMPT_CLEANED` plus terminal receipts.

- [ ] **Step 3: Implement strict client and normalization**

Use a dedicated `http.Client` with TLS 1.3 minimum, no environment proxy, redirect rejection, 5s connect/15s request deadlines, max 64 KiB headers and exact content type. Decode with `DisallowUnknownFields`, limit body before decode and reject duplicate JSON keys. OAuth/mTLS material comes from `BoundRuntime`; logs receive only operation/result/latency/Trace ID.

Map CMDB type codes through a closed table to Asset Kind; unknown types become rejected items, never guessed. Each object maps exactly to `OBJECT_TIME_SEQUENCE{OrderTime=updated_at UTC microsecond,OrderSequence=object_revision,ProviderVersionSHA256=SHA256(FramedTupleV1("cmdb-object-version.v1",object_revision))}` using the Pack 01 byte encoding. `snapshot_epoch` belongs only to checkpoint lineage and complete-snapshot closure and is deliberately excluded from the per-object Provider-version digest, so the same object version cannot collide merely because a new snapshot began. `external_id` is only the stable identity/page-order tie-break and never freshness. Neither Provider field is stored in or compared as Catalog integer `source_revision`. Adapter provenance contains only `(field_code,CMDB_V1_*_FIELD,SOURCE,confidence=100)`; Repository injects Source ID/provider/definition revision/Catalog time. Map relation types through the approved relationship enum and closed path code. A deleted record yields only identity, exact freshness, tombstone reason and provenance; it never physically deletes history.

- [ ] **Step 4: Verify and commit**

Run:

~~~bash
gofmt -w $(rg --files internal/assetsource/externalcmdb -g '*.go')
go test -race ./internal/assetsource/externalcmdb -count=1
go test ./api/openapi -run ExternalCMDB -count=1
~~~

Expected: PASS for TLS identity, read-only capability, closed Schema, size/time limits, DLP, unknown-type rejection, tombstone and forbidden request surface.

~~~bash
git add api/openapi/external-cmdb-catalog-v1.yaml internal/assetsource/externalcmdb
git commit -m "feat(assetdiscovery): add fixed external cmdb provider"
~~~

## Task 18 ownership correction: merged Provider protocol, then Worker core, then CMDB integration

旧 Task 18 同时声称拥有 Provider paging、PageCommitter/projection、Queue、Worker、lease/fence、HA 和 recovery；[Pack 09](./09-discovery-worker-ha-e2e.md) 又把相同通用状态机交给 Task 27/28，形成并行 owner。当前主线代码已经给出更窄的稳定边界，后续实现顺序冻结为：

| 能力/文件族 | 唯一 owner | 后继规则 |
|---|---|---|
| `discoverysource.PageCommitter`、PostgreSQL projection/receipt/checkpoint transaction | 已合并 [M1E](./13-m1e-page-commit-transaction.md) / PR #53 | Task 18B 只调用并扩展其唯一 integration test，不复制 ABI/SQL |
| `discoveryqueue.Queue` 与 PostgreSQL Run lifecycle | 已合并 Pack 09 Task 27 / PR #55 | Task 18B/Task 28 只消费 |
| `discoverycleanup.CleanupBroker` | 已合并 Pack 09 Task 27 / PR #57 | Task 18B/Task 28 只消费 |
| `discoverylimit.Limiter` 与 PostgreSQL permit ledger | 已合并 Pack 09 Task 27 / PR #64 | Task 18B/Task 28 只消费 |
| `CMDB_CATALOG_V1` Provider paging/checkpoint/`Page|Delay` | Task 18A，已由 PR #98 合并并由 PR #99 修正 complete-checkpoint next-run restart | Task 18B 不修改其通用阶段机 |
| provider-neutral claim/runtime/cleanup/terminal loop | [Pack 09 Task 28A](./09-discovery-worker-ha-e2e.md#task-28a-provider-neutral-worker-core-and-claim-runtime-seam) | 必须先合并；Task 18B 只通过稳定 seam 注入 CMDB |
| External-CMDB-specific durable reconciliation/lifecycle integration + neutral metadata descriptor | 本包 Task 18B | 不拥有通用 Queue/Worker/SQL 状态机；Control Plane/Worker 只消费同一 `internal/sourceprofile` descriptor |
| shared recoverable cleanup-session transport + same-attempt authority | [Pack 09 Task 28B](./09-discovery-worker-ha-e2e.md#task-28b-recoverable-cleanup-session-transport-and-attempt-authority) | 在 Task 18B 后合并；修复现有 process-local Broker 不能跨 Worker 找回 attempt 的事实 |
| 完整 Provider registry、production constructor 与 `cmd/discovery-worker` | [Pack 09 Task 28C](./09-discovery-worker-ha-e2e.md#task-28c-production-constructor-and-provider-registry) | 只消费已合并 Task 18B/28B 与其他 Provider `Produces` |
| Control Plane profile install + validation admission | 本包 Task 19A | 只 import neutral descriptor；不得 import External CMDB Provider/network graph |

这只是所有权纠偏，不回写完成度 checkbox。Task 18A 的 merged code 可以作为稳定 `Produces`；旧 Task 18 仍须等 Task 18B G2 和两 Worker/HA/restart/recovery G3 全部取得证据后才可勾选。Task 19A/19B、真实 CMDB canary 和 G4 仍独立 deferred，`EXTERNAL_CMDB/CMDB_CATALOG_V1` 始终保持 `UNAVAILABLE/CLOSED`。

### Task 18A: merged CMDB paging/checkpoint protocol foundation

**Stable files（已合并，只读消费）:**

- `internal/assetsource/externalcmdb/discover.go`
- `internal/assetsource/externalcmdb/discover_test.go`
- `internal/assetsource/externalcmdb/protocol_integration_test.go`
- `testdata/asset-source/external-cmdb/capabilities.json`
- `testdata/asset-source/external-cmdb/assets-page-1.json`
- `testdata/asset-source/external-cmdb/assets-page-2.json`
- `testdata/asset-source/external-cmdb/relations.json`

**Consumes:**

- 已合并 Task 17 fixed client/normalization 和 package-private typed `providerRetryAfter(error)`。
- `discoverysource.Provider`、process-local `BoundRuntime`/`Checkpoint`、closed concrete `Page|Delay`。

**Produces:**

- 固定 `CAPABILITIES → ASSETS → RELATIONS → COMPLETE` paging；complete checkpoint 在下一 Run 从新的 capabilities/snapshot restart，不把旧 snapshot positions 带入下一 Run。
- `CMDB_CATALOG_V1` 私有 canonical checkpoint、asset/relation 各自 `(updated_at,external_id)` 顺序与 exact boundary replay、authority/snapshot epoch consistency、strict Schema/DLP/budget 和真实 TLS wire fixture。
- 只有严格 `(0,60s]` 的 typed `Retry-After` 转换为 `Delay{Reason: PROVIDER_RETRY_AFTER}`；wire `0` 或越界值关闭 Provider contract。
- partial/transport/schema/snapshot/cursor failure 只返回错误或 bounded Delay；不写 PostgreSQL、不做 missing detection，也不声称 tombstone/restore 已进入 Catalog。

Task 18A 不拥有 Queue、Worker、lease/fence、Limiter、CleanupBroker、PageCommitter、missing/stale projection、HA 或 production registry。PR #98/#99 的存在不等于旧 Task 18 或 Source gate 已完成。

### Task 18B: External CMDB durable reconciliation and lifecycle integration

**Batch:** C0/C1/C2 mixed，1–2 日，单独 worktree/PR；必须从 Task 28A 已合并的最新 `origin/main` 开始。

**Exact files:**

- Create: `internal/sourceprofile/external_cmdb.go`
- Create: `internal/sourceprofile/external_cmdb_test.go`
- Create: `internal/assetsource/externalcmdb/reconciliation.go`
- Create: `internal/assetsource/externalcmdb/reconciliation_test.go`
- Create: `internal/discoveryworker/external_cmdb_integration_test.go`
- Modify: `internal/assetcatalog/postgres/page_committer_integration_test.go`

源文件核验确认 `internal/assetcatalog/postgres/discovery_integration_test.go` 不存在，因此本任务明确不创建该模糊 parallel owner。CMDB page/relation/checkpoint/receipt transaction 断言由 Task 18B 顺序扩展已存在且唯一的 `page_committer_integration_test.go`；执行期间该文件不得有第二 owner。`external_cmdb_integration_test.go` 使用外部测试包消费 Task 28A 稳定 seam，不得把 CMDB import 或 fixture helper写入 provider-neutral core 文件。

`internal/sourceprofile/external_cmdb.go` 是唯一中立 metadata/domain owner：它只依赖 `internal/assetcatalog`，产生 immutable `CMDB_CATALOG_V1` profile registration、canonical descriptor digest 和 safe runtime-binding requirements；不得 import `internal/assetsource/externalcmdb`、`internal/discoveryworker`、`net/http`、credential resolver 或任何 endpoint/runtime material。`reconciliation.go` 只把该已合并 descriptor 组合成 External-CMDB-specific fact-policy/runtime factory，供既有 PageCommitter resolver seam 和后继 Task 28C Worker registry 消费；它不得实现 claim/lease/fence/cleanup/terminal transition。Control Plane Task 19A 与 Worker registry 必须消费同一 descriptor/digest，禁止两边重建 profile 语义。

**Consumes（全部只读已合并 `Produces`）:**

- Task 17 和 Task 18A 的 External CMDB Provider、normalization、private checkpoint 与 TLS fixtures。
- M1E `discoverysource.PageCommitter`/`postgres.NewPageCommitter(...)` 和 package-private projection transaction。
- Task 27 的 `discoveryqueue.Queue` PostgreSQL lifecycle、`discoverycleanup.CleanupBroker`、`discoverylimit.Limiter` 和 M1D `CheckpointCodec`。
- 已合并 Task 28A 的 provider-neutral `Worker` 与 process-local claim-runtime seam。
- `000015` 十二表及现有 `assetcatalog.SourceProfileRegistry` registration seam；不改 migration、公共 OpenAPI、Web 或 production assembly。

**Produces:**

- 一个只绑定 exact `EXTERNAL_CMDB/CMDB_CATALOG_V1` 的 immutable neutral profile descriptor/digest，以及消费它的 reconciliation/fact-policy/runtime-factory descriptor；后继 Task 28C Worker registry 与 Task 19A Control Plane registration 只能消费该已合并 neutral descriptor，不能重建其语义。
- 真实 PostgreSQL 18.4 TLS 下，从 CMDB `Page|Delay` 经 Task 28A Worker core、Task 27 Queue/Limiter/CleanupBroker 到既有 PageCommitter 的 provider-specific durable integration 证据。
- Task 19B gate 可消费的 safe G2 evidence references；不产生 Control Plane validation admission、`AVAILABLE` decision、production registry、binary 或 HA 签名。

**Classification:**

- **C0:** stale fence zero-side-effect、receipt-first exact replay/changed digest、page+relation+checkpoint+receipts one transaction、cleanup-before-delay、same-attempt runtime/proof binding、complete-snapshot missing boundary 和 credential/runtime zeroization。
- **C1:** injected Worker core → CMDB Provider → PageCommitter/Queue/Limiter/CleanupBroker 的关闭态纵向切片。
- **C2:** 仅 External CMDB profile/fact policy、TLS fixture 与 provider-specific lifecycle cases；不得扩展公共 Source/Worker DTO。

**RED → GREEN:**

- [ ] RED：partial/timeout 后 Run 失败但 `missing=0/stale=0`；任何提前 implicit missing 都使真库断言失败。
- [ ] RED：CMDB Provider 只能使用 `ReserveCleanupAttempt → CleanupBroker.OpenAttempt` 后由同一 `SessionOpener`/session cell 产生的 `BoundRuntime`；Run/attempt/epoch/runtime binding 任一漂移、resolver 独立打开 credential/session，或用另一 attempt cleanup proof 关闭实际 runtime，均在首个 HTTP call 前 fail closed 且零写。
- [ ] RED：stale fence 在 Provider call 前后、`ApplyPage` 和 terminal 边界均零 Observation/relation/checkpoint/receipt/Audit/Outbox 副作用。
- [ ] RED：page、canonical relation page（含 empty）、sealed checkpoint、`PAGE_APPLIED`、`RELATION_PAGE_COMMITTED` 和 work-result 任一 fault injection 都整笔回滚。
- [ ] RED：exact response-loss replay 返回原 persisted result；changed item/relation/checkpoint/final flag digest fail closed 且零新增写。
- [ ] RED：只有 `(FinalPage=true,CompleteSnapshot=true)` 已同事务提交后才能 implicit missing；partial、timeout、delta final 或 rejected item 均不能触发。
- [ ] RED：已验证 TLS/runtime binding 下的 fixed-wire `deleted=true` tombstone 才 soft-stale，reappearance restore append Observation/Audit/Outbox；不得虚构对象签名语义，不物理删除历史，也不自动绕过后续 connection validation。
- [ ] RED：crash-before-commit 无写、commit-response-loss receipt-first replay、expired single-worker reclaim 只按 persisted intent 继续；不重复 Provider mutation。
- [ ] RED：`Delay` outcome 不调用 `ApplyPage`、不推进 checkpoint/count；必须先持久 delay intent、停止 Provider、完成 Broker cleanup/receipt，再调用 Queue `Delay`。
- [ ] GREEN：只实现 CMDB registration/fact-policy glue，并通过 Task 28A seam 组合已合并 primitives；禁止复制 Queue/Worker/PageCommitter SQL 或状态枚举。

**G2 — required, no Skip:**

Task 18B 新增的真库测试在 `AIOPS_TEST_POSTGRES_DSN` 缺失时必须 `Fatal`，不得 `Skip`。项目 harness 必须验证 PostgreSQL `18.4`、TLS on/TLS 1.3 和独立 migration/application identity；任何环境缺失、`--- SKIP` 或 `go test -json` 的 `"Action":"skip"` 都不能记录为 PASS。

~~~bash
test -n "${AIOPS_TEST_POSTGRES_DSN:-}"
go test -race ./internal/assetsource/externalcmdb \
  ./internal/discoveryworker ./internal/assetcatalog/postgres \
  -run '^TestExternalCMDBTask18B' -count=1
go test -race ./internal/discoverysource ./internal/discoveryqueue \
  ./internal/discoverycleanup ./internal/discoverylimit \
  ./internal/discoverycheckpoint -count=1
git diff --check
~~~

G2 必须逐项证明上述 partial/timeout、same-attempt runtime/proof binding、stale fence、one-transaction page/relation/checkpoint/receipt、exact/changed replay、complete-only missing、fixed-wire tombstone/restore、crash/response-loss/reclaim 和 cleanup-before-Delay；只跑 Provider unit/TLS fixture 不能替代真库门。

**Deferred G3/G4:**

- **G3:** 只能在 Task 28B recoverable session client 与 Task 28C production binary 已合并后，连接通过 opaque lab binding 预置的真实外部 shared authority 执行：两个真实 Worker 竞争同一 PostgreSQL Source、kill lease owner、replacement Worker 以 exact Run/attempt/epoch recovery-only open 找回同一外部 session 后 revoke、fence takeover、Worker/数据库 restart、checkpoint retained-key recovery、crash-after-page/cleanup-before-terminal 和 reconnect/recovery。Task 28B/Task 29 都不实现或启动 authority server；缺 binding/不可达/mTLS 失败/Skip 均不得 PASS。未执行前旧 Task 18 不得勾选，Task 18B 最多为 `BUILT_CLOSED`；现有 process-local Broker 单独不构成跨进程证据。
- **G4:** 真实非生产 External CMDB endpoint、真实 credential/trust/network binding、rate/backpressure、24h 内 canary、完整安全/DLP/HA/恢复/发布资格。未签名前 Source/Profile gate 继续 `UNAVAILABLE/CLOSED`。

### Task 19A: Control Plane CMDB profile installation and validation admission

**Batch:** C0/C1，1–2 日；只能在 Task 18B neutral descriptor 与 Task 28C safe runtime-admission manifest 已合并后开始，必须先于 Task 19B canary。

**Exact files:**

- Create: `internal/sourceprofile/validation_admission.go`
- Create: `internal/sourceprofile/validation_admission_test.go`
- Modify: `internal/assetcatalog/postgres/repository.go`
- Modify: `internal/assetcatalog/postgres/source_revisions.go`
- Modify: `internal/assetcatalog/postgres/source_revisions_test.go`
- Modify: `internal/assetcatalog/postgres/source_revisions_integration_test.go`
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Modify: `cmd/control-plane/main.go`
- Modify: `cmd/control-plane/main_test.go`

源文件核验确认 `cmd/control-plane/main.go` 当前调用只安装 builtin `MANUAL_V1` 的 `assetpostgres.New(...)`，且 `sourceValidationRuntimeClosed` 硬关闭所有非 `MANUAL_V1` validation。Task 19A 是这两个 backend seam 的唯一 owner；Task 18B/28C/19B 不得并行修改上述文件。

**Consumes（只读已合并）:**

- Task 18B `internal/sourceprofile` neutral `CMDB_CATALOG_V1` registration/canonical descriptor digest；Control Plane 不 import `internal/assetsource/externalcmdb`。
- Task 28C safe content-addressed runtime-admission manifest，只含 exact Provider/Profile/descriptor/runtime-recovery capability digest；不含 endpoint、credential、socket、key 或 runtime material。
- 既有 `assetcatalog.NewSourceProfileRegistry`、`assetpostgres.NewWithSourceProfileRegistry`、Source/Revision exact facts与 `AIOPS_TEST_POSTGRES_DSN` PostgreSQL harness。

**Produces:**

- Neutral `SourceValidationRuntimeAdmission`：只对 exact descriptor、runtime manifest、current Source/Profile/Revision/binding digest 与 validation gate prerequisites 全等的 `EXTERNAL_CMDB/CMDB_CATALOG_V1` 返回 admitted；missing/stale/drifted dependency 返回 unavailable。
- Control Plane 用同一 neutral descriptor装配 `SourceProfileRegistry` 并把 registry + runtime admission 注入 PostgreSQL Repository；硬编码 `sourceValidationRuntimeClosed` 被 repository-owned exact admission check 取代。`MANUAL_V1` 既有同步完成语义保持不变，其他未注册 Provider 继续 fail closed。
- AST/import boundary：`cmd/control-plane` 与 `internal/sourceprofile` 不可达 External CMDB Provider HTTP-client/credential/session/network graph；Control Plane 自身既有 HTTP server 不在此禁令内。Worker registry 与 Control Plane 只比较同一 canonical descriptor digest，不各自重建语义。

**Classification:**

- **C0:** exact profile/runtime/gate admission、zero mutation on missing/drift、Control Plane no-provider-network/secret graph。
- **C1:** Registry/Repository/Control Plane production assembly 与 validation request admission。
- **C2:** 无；不拥有 Provider runtime、Worker registry、Source availability decision、OpenAPI/Web 或 migration。

**RED → GREEN:**

- [ ] RED：AST/import test 证明 `cmd/control-plane` 与 `internal/sourceprofile` import graph 不含 `internal/assetsource/externalcmdb`、Provider SDK/HTTP client、credential/session transport；另证 `internal/sourceprofile` 本身不 import `net/http`。metadata package 不暴露 endpoint/credential/runtime material。
- [ ] RED：descriptor、safe runtime manifest、exact binding digest 或 gate prerequisite 任一缺失/漂移时 validation 返回 `ErrUnavailable`，Run/Revision/Source/Audit/Outbox 零写；不得用测试直写伪造可验证状态。
- [ ] RED：只有 exact CMDB registration + runtime admission 可从公共 validate path 创建 `VALIDATING` Run；unknown/non-registered Provider 仍关闭，replay/changed digest 与并发漂移 fail closed。
- [ ] GREEN：以 neutral descriptor 装配 `NewWithSourceProfileRegistry` 和 injected runtime admission，删除 broad profile-code allowlist；Control Plane 始终不读取 endpoint、credential 或 `BoundRuntime`。

**G2 — required, no Skip:**

~~~bash
test -n "${AIOPS_TEST_POSTGRES_DSN:-}"
go test -race ./internal/sourceprofile ./internal/assetcatalog/postgres \
  ./cmd/control-plane -run 'CMDBProfile|ValidationAdmission|ImportBoundary' -count=1
go vet ./internal/sourceprofile ./internal/assetcatalog/postgres ./cmd/control-plane
git diff --check
~~~

G2 必须使用 PostgreSQL 18.4 TLS harness；缺环境或 Skip 不得算 PASS。它证明公共 Control Plane create/validate path、exact registry/runtime admission、zero-write negatives、idempotent replay 和 AST/import closure；直接 SQL 改状态、直接构造 Repository fake 或 Provider unit test 不能替代。

**Deferred G3/G4:** Task 19A 只允许排队真实 validation，不产生 successful validation、publish/sync、`AVAILABLE` 或 canary 证据。Task 19B、Task 29/G3 与 G4 未完成前 External CMDB 继续 `UNAVAILABLE/CLOSED`。

### Task 19B: Per-source availability gate, real staging canary, and operating proof

**Files:**
- Create: `internal/assetsource/externalcmdb/gate.go`
- Create: `internal/assetsource/externalcmdb/gate_test.go`
- Create: `scripts/verify-external-cmdb-source.sh`
- Create: `docs/operations/asset-sources/external-cmdb.md`
- Create: `web/e2e/source-external-cmdb.spec.ts`
- Modify: `web/src/features/asset-sources/AssetSourcesPage.tsx`
- Modify: `web/src/features/asset-sources/SourceRunTimeline.tsx`

**Interfaces:**
- Consumes: exact published revision, validation proof, protocol/DLP/HA receipts and production source safe projection.
- Produces gate key `EXTERNAL_CMDB/CMDB_CATALOG_V1/<source_id>/<revision_digest>` and status `UNAVAILABLE|VALIDATING|AVAILABLE|DEGRADED|SUSPENDED`.
- Script reads only opaque bindings `AIOPS_SOURCE_ID`, `AIOPS_SOURCE_REVISION`, `AIOPS_DISCOVERY_LAB_BINDING`; it never accepts endpoint or secret flags.

- [ ] **Step 1: Write failing complete-gate tests**

~~~go
func TestExternalCMDBGateRequiresAllCurrentProofs(t *testing.T) {
	proofs := validCMDBProofSet()
	if decision := EvaluateGate(proofs); decision.Status != assetcatalog.SourceGateAvailable {
		t.Fatalf("decision = %#v", decision)
	}
	proofs.HAFailoverDigest = ""
	if decision := EvaluateGate(proofs); decision.Status != assetcatalog.SourceGateUnavailable || decision.ReasonCode != "SOURCE_HA_PROOF_MISSING" {
		t.Fatalf("decision = %#v", decision)
	}
}
~~~

Run: `go test ./internal/assetsource/externalcmdb -run Gate -count=1`

Expected: FAIL because provider gate evaluation does not exist.

- [ ] **Step 2: Implement gate evidence and automatic closure**

`AVAILABLE` requires current source/revision/binding digests, successful identity/trust/credential-open/fixed-probe Provider validation, the separate exact Broker cleanup receipt, contract+negative+DLP tests, real TLS protocol receipt, two-replica fence failover receipt, rate/backpressure receipt and a non-production external CMDB canary less than 24 hours old. Any credential/trust/network/profile/revision change, repeated auth/schema failures, checkpoint ambiguity or protocol drift closes the gate before another claim；cleanup uncertainty specifically produces terminal `FAILED + SUSPENDED` and cannot be downgraded to `DEGRADED|UNAVAILABLE`. A plain upstream outage sets `DEGRADED` and applies backoff；it never silently switches endpoint.

- [ ] **Step 3: Execute staging canary and UI/E2E verification**

The script validates profile and source IDs, invokes Control Plane validate/publish/sync APIs with recent OIDC obtained by the approved operator flow, waits for terminal run, verifies counts/digests/provenance/tombstone/recovery and downloads only the signed safe receipt. It must not print environment values or enable shell tracing.

Run:

~~~bash
go test -race ./internal/assetsource/externalcmdb -count=1
scripts/verify-external-cmdb-source.sh
corepack pnpm@10.34.0 --dir web test:e2e -- --grep "external cmdb source"
~~~

Expected: positive staging canary and negative wrong-authority/bad-CA/tampered-gate-receipt/rate-limit/schema/DLP/fence cases PASS; UI displays independent Source/Revision/Gate/checkpoint states and no endpoint/credential/raw payload.

- [ ] **Step 4: Commit**

~~~bash
git add internal/assetsource/externalcmdb/gate.go internal/assetsource/externalcmdb/gate_test.go \
  scripts/verify-external-cmdb-source.sh docs/operations/asset-sources/external-cmdb.md \
  web/e2e/source-external-cmdb.spec.ts web/src/features/asset-sources/AssetSourcesPage.tsx \
  web/src/features/asset-sources/SourceRunTimeline.tsx
git commit -m "feat(assetdiscovery): gate external cmdb sources"
~~~
