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
| Gate evidence schema/domain/admission contract | 本包 Task 19A2a | 12 files；migration/schema/role/domain only，独立真实 G2/PR/merge |
| Gate persistence + runtime admission rechecks | 本包 Task 19A2b | 11 files；只消费已合并 19A2a，实现 Repository/Queue/PageCommitter expiry/drift 与 HA durable facts |
| Qualification lane/API + generic production assembly | 本包 Task 19A2c | 19 files；只消费已合并 19A2a/19A2b + Task 28A seam；不得复制 Worker loop |
| Provider-neutral two-worker HA/cleanup/restart/response-loss receipt + metrics | [Pack 09 Task 29A](./09-discovery-worker-ha-e2e.md#task-29a-provider-neutral-two-worker-ha-receipt-and-telemetry) | 不消费 canary、不写 gate、不产 final matrix |
| External CMDB qualification canary、gate evaluator/decision + operating proof | 本包 Task 19B | 消费 Task 19A2a/19A2b/19A2c + Task 29A 已合并 receipts；唯一调用 CMDB `AdmitGate` |
| Signed final Provider matrix + final E2E/CI | [Pack 09 Task 29B](./09-discovery-worker-ha-e2e.md#task-29b-signed-provider-matrix-and-final-e2e-ci) | 只聚合完成的 per-source gate/canary/HA receipts，不重建它们 |

这只是所有权纠偏，不回写完成度 checkbox。Source Gate qualification 的唯一无环顺序冻结为 `Task 28C → Task 19A → Task 19A2a → Task 19A2b → Task 19A2c → Task 29A → Task 19B → Task 29B`，每一 Batch 都由新窗口独立真实 G2/PR/merge，所有后继只消费已合并 `Produces`；不得把 Task 19B 提前到 Task 28C/19A/19A2a/19A2b/19A2c/29A 之前。Task 18A 的 merged code 可以作为稳定 `Produces`；旧 Task 18 仍须等 Task 18B G2 和两 Worker/HA/restart/recovery G3 全部取得证据后才可勾选。Task 19A/19A2a/19A2b/19A2c/29A/19B/29B、真实 CMDB canary 和 G4 均 deferred，`EXTERNAL_CMDB/CMDB_CATALOG_V1` 始终保持 `NOT_STARTED/UNAVAILABLE/CLOSED`。

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

- **G3:** 只能在 Task 28B recoverable session client 与 Task 28C production binary 已合并后，连接通过 opaque lab binding 预置的真实外部 shared authority 执行：两个真实 Worker 竞争同一 PostgreSQL Source、kill lease owner、replacement Worker 以 exact Run/attempt/epoch recovery-only open 找回同一外部 session 后 revoke、fence takeover、Worker/数据库 restart、checkpoint retained-key recovery、crash-after-page/cleanup-before-terminal 和 reconnect/recovery。Task 28B/Task 29A 都不实现或启动 authority server；缺 binding/不可达/mTLS 失败/Skip 均不得 PASS。未执行前旧 Task 18 不得勾选，Task 18B 最多为 `BUILT_CLOSED`；现有 process-local Broker 单独不构成跨进程证据。
- **G4:** 真实非生产 External CMDB endpoint、真实 credential/trust/network binding、rate/backpressure、24h 内 canary、完整安全/DLP/HA/恢复/发布资格。未签名前 Source/Profile gate 继续 `UNAVAILABLE/CLOSED`。

### Task 19A: Control Plane CMDB profile installation and validation admission

**Batch:** C0/C1，1–2 日；只能在 Task 18B neutral descriptor 与 Task 28C safe runtime-admission manifest 已合并后开始，必须先于 Task 19A2a，且合并后才可被后继消费。

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

源文件核验确认 `cmd/control-plane/main.go` 当前调用只安装 builtin `MANUAL_V1` 的 `assetpostgres.New(...)`，且 `sourceValidationRuntimeClosed` 硬关闭所有非 `MANUAL_V1` validation；同时 `internal/assetcatalog/postgres/source_revisions.go` 当前 broad Publish mutation 会直接写 `gate_status='AVAILABLE'`。Task 19A 是这些 backend seam 的下一位唯一 owner：它必须保留 `MANUAL_V1` 直接开门特例，并把每个需要真实资格的 non-MANUAL publication 原子收敛为 `PUBLISHED + UNAVAILABLE`。Task 18B/28C/19A2a/19A2b/19A2c/19B 不得与本任务并行修改上述文件。

**Consumes（只读已合并）:**

- Task 18B `internal/sourceprofile` neutral `CMDB_CATALOG_V1` registration/canonical descriptor digest；Control Plane 不 import `internal/assetsource/externalcmdb`。
- Task 28C safe content-addressed runtime-admission manifest，只含 exact Provider/Profile/descriptor/runtime-recovery capability digest；不含 endpoint、credential、socket、key 或 runtime material。
- 既有 `assetcatalog.NewSourceProfileRegistry`、`assetpostgres.NewWithSourceProfileRegistry`、Source/Revision exact facts与 `AIOPS_TEST_POSTGRES_DSN` PostgreSQL harness。

**Produces:**

- Neutral `SourceValidationRuntimeAdmission`：只对 exact descriptor、runtime manifest、current Source/Profile/Revision/binding digest 与 validation gate prerequisites 全等的 `EXTERNAL_CMDB/CMDB_CATALOG_V1` 返回 admitted；missing/stale/drifted dependency 返回 unavailable。
- Control Plane 用同一 neutral descriptor装配 `SourceProfileRegistry` 并把 registry + runtime admission 注入 PostgreSQL Repository；硬编码 `sourceValidationRuntimeClosed` 被 repository-owned exact admission check 取代。`MANUAL_V1` 既有同步完成语义保持不变，其他未注册 Provider 继续 fail closed。
- Profile-discriminated publication closure：`MANUAL_V1` 继续在既有同步 transaction 内进入 `AVAILABLE`；`EXTERNAL_CMDB/CMDB_CATALOG_V1` 及所有需要真实资格的 non-MANUAL profile 只能进入 exact `PUBLISHED + UNAVAILABLE`，清除旧 non-MANUAL checkpoint binding、保持普通 `RequestSync` 关闭且不写 future gate evidence。Task 19A2a 只冻结 evidence pointer 的 schema guard；Task 19A2b 才是 publication/reference drift 时自动清除该 pointer 的唯一 persistence/recheck owner。Task 19A 不创建 qualification receipt 或 gate-open decision。
- AST/import boundary：`cmd/control-plane` 与 `internal/sourceprofile` 不可达 External CMDB Provider HTTP-client/credential/session/network graph；Control Plane 自身既有 HTTP server 不在此禁令内。Worker registry 与 Control Plane 只比较同一 canonical descriptor digest，不各自重建语义。

**Classification:**

- **C0:** exact profile/runtime/gate admission、zero mutation on missing/drift、Control Plane no-provider-network/secret graph。
- **C1:** Registry/Repository/Control Plane production assembly、validation request admission 与 non-MANUAL publish-closed mutation。
- **C2:** 无；不拥有 Provider runtime、Worker registry、Source availability decision、OpenAPI/Web 或 migration。

**RED → GREEN:**

- [ ] RED：AST/import test 证明 `cmd/control-plane` 与 `internal/sourceprofile` import graph 不含 `internal/assetsource/externalcmdb`、Provider SDK/HTTP client、credential/session transport；另证 `internal/sourceprofile` 本身不 import `net/http`。metadata package 不暴露 endpoint/credential/runtime material。
- [ ] RED：descriptor、safe runtime manifest、exact binding digest 或 gate prerequisite 任一缺失/漂移时 validation 返回 `ErrUnavailable`，Run/Revision/Source/Audit/Outbox 零写；不得用测试直写伪造可验证状态。
- [ ] RED：只有 exact CMDB registration + runtime admission 可从公共 validate path 创建 `VALIDATING` Run；unknown/non-registered Provider 仍关闭，replay/changed digest 与并发漂移 fail closed。
- [ ] RED：同一 Publish repository 的 `MANUAL_V1` fixture 仍到 `AVAILABLE`，而 exact CMDB fixture 只能到 `PUBLISHED + UNAVAILABLE`；后者随即 `RequestSync` 必须返回 `SOURCE_GATE_UNAVAILABLE` 且 Run/Audit/Outbox 零写。任何把 CMDB publication 直接写为 `AVAILABLE` 的实现保持 RED。
- [ ] GREEN：以 neutral descriptor 装配 `NewWithSourceProfileRegistry` 和 injected runtime admission，删除 broad profile-code allowlist，并按 installed Profile 分支 publication closure；Control Plane 始终不读取 endpoint、credential 或 `BoundRuntime`。

**G2 — required, no Skip:**

~~~bash
test -n "${AIOPS_TEST_POSTGRES_DSN:-}"
go test -race ./internal/sourceprofile ./internal/assetcatalog/postgres \
  ./cmd/control-plane -run 'CMDBProfile|ValidationAdmission|PublishClosed|ImportBoundary' -count=1
go vet ./internal/sourceprofile ./internal/assetcatalog/postgres ./cmd/control-plane
git diff --check
~~~

G2 必须使用 PostgreSQL 18.4 TLS harness；缺环境或 Skip 不得算 PASS。它证明公共 Control Plane create/validate path、exact registry/runtime admission、zero-write negatives、idempotent replay 和 AST/import closure；直接 SQL 改状态、直接构造 Repository fake 或 Provider unit test 不能替代。

**Deferred G3/G4:** Task 19A 只开放 exact validation/publication admission，不执行真实 validation、qualification、HA、canary、gate open 或 ordinary sync。Task 19A2a/19A2b/19A2c/29A/19B/29B 与 G3/G4 未完成前 External CMDB 继续 `NOT_STARTED/UNAVAILABLE/CLOSED`。

### Task 19A2a: Source Gate schema, domain, and admission contract

**Batch:** C0，1–2 日；独立新窗口、独立真实 G2/PR/merge，只能消费已合并 Task 19A，必须完整合并后 Task 19A2b 才可开始。不得与 Task 19A2b/19A2c 共享文件或要求一次整体合并。

**Exact future files:**

- Modify: `migrations/000015_assets_catalog.up.sql`
- Modify: `migrations/000015_assets_catalog.down.sql`
- Create: `internal/assetcatalog/postgres/migration_qualification_contract_integration_test.go`
- Modify: `internal/assetcatalog/postgres/schema_admission.go`
- Modify: `internal/assetcatalog/postgres/schema_admission_test.go`
- Modify: `internal/assetcatalog/postgres/schema_admission_integration_test.go`
- Modify: `internal/store/postgres/database_role_admission.go`
- Modify: `internal/store/postgres/database_role_admission_test.go`
- Modify: `internal/assetcatalog/types.go`
- Modify: `internal/assetcatalog/types_test.go`
- Create: `internal/assetcatalog/source_gate.go`
- Create: `internal/assetcatalog/source_gate_test.go`

上述 12 个 future files 是 Task 19A2a 的完整且唯一实现清单；与 Task 19A2b/19A2c 零重叠。它只冻结 migration、schema/role admission、domain 与 pure Source Gate contract，不实现 PostgreSQL Repository、Queue predicate、HTTP、Worker、signer 或 production assembly。`000015` 仍只有既有十二表，禁止增加第十三张 evidence 表或创建新 migration number。

**Consumes（全部已合并）:**

- Task 19A 的 exact profile/validation admission，以及 non-MANUAL `PUBLISHED + UNAVAILABLE` publication closure。
- Task 1/13 的 `000015` 十二表、Source/Revision/Run domain 与 schema/role admission。Task 19A2a 不 import Task 28A/28B/28C execution graph、External CMDB network client 或任何 Provider-specific canary predicate。

**Produces:**

- Schema/domain enums `RunKind=QUALIFICATION`、`WorkResultKind=QUALIFICATION_PROOF`、closed evidence kind `TWO_WORKER_HA|PROVIDER_CANARY`，以及 safe `GateEvidenceSet/GateEvaluator/GateDecision`、`SourceGateRepository`、`QualificationFactSnapshot`、`EvidenceVerifier` 与 `QualificationOutcomeSink` pure contracts；这些接口本身不产生 registry、sink instance 或 signer。
- Existing twelve-table schema extension、named checks/deferred closure、least-privilege ACL、schema/role admission and dump/restore manifest。Task 19A2b 只能消费这些已合并 columns/contracts 实现 persistence，不得重定义字段、digest 或 evidence kind。

**Exact twelve-table extension and safe receipt:**

`asset_sources` 只新增 all-null-or-all-present tuple `gate_evidence_run_id/gate_evidence_digest/gate_evidence_expires_at`，指向当前 Provider canary qualification Run；`asset_source_runs` 增加 qualification evidence kind、composite Scope digest、revision/binding/runtime-manifest/lab-binding digests、prior-receipts digest、result digest、expiry、opaque signing-key ID、signature 和 final receipt digest。Terminal qualification row 是 append-only evidence truth；source pointer 只是 current gate projection。Receipt digest 固定为 domain-separated `FramedTupleV1` over exact Tenant/Workspace/Source、revision/canonical binding、Provider/Profile descriptor、runtime manifest、lab-binding digest、evidence kind、prior receipts、closed result、issued/expiry and signing-key ID，signature 覆盖该 digest；raw binding ID、endpoint、credential/reference value、Provider object/payload/cursor 和错误正文都不入帧、不落库。

`TWO_WORKER_HA` 还要求 all-null-or-all-present safe digest-only tuple：`ha_owner_worker_identity_digest`、`ha_takeover_worker_identity_digest`、`ha_owner_process_instance_digest`、`ha_takeover_process_instance_digest`、`ha_takeover_receipt_digest`、`ha_restart_receipt_digest`、`ha_session_recovery_receipt_digest`、`ha_cleanup_receipt_digest`、`ha_response_loss_receipt_digest` 与 `ha_fact_chain_digest`。owner/takeover identity digests 必须不同；所有列只接受 lowercase SHA-256，并由 domain-separated exact Run/Source/Revision/fence/attempt/terminal receipt facts推导。`PROVIDER_CANARY` 必须让该 tuple 全 NULL，并只通过 prior-receipts digest绑定已封存 HA receipt。任何 raw worker/boot ID、hostname、endpoint、credential、session handle、日志文本或 caller boolean 都不是 HA fact。

Qualification Run 的 page/relation/count/effective-snapshot/Source-checkpoint/success-pointer closure 必须为零或 unchanged；named checks、deferred closure、schema admission、dump/restore 和 least-privilege ACL 共同拒绝 direct SQL 伪造投影、HA fact 或 gate open。应用 workload 对 gate-evidence/HA columns 不获得任意 column UPDATE。测试 fake、临时 bypass、通用 shell/HTTP payload、手工 receipt 文件和 matrix status 都不是证据。

**RED → GREEN:**

- [ ] RED：migration 允许 terminal `QUALIFICATION_PROOF` safe receipt，但强制 Observation/Asset/Relationship/page/count/effective-snapshot/Source checkpoint/success pointers 为零或 unchanged；任一 forged projection、unknown evidence kind、raw endpoint/credential/payload-shaped evidence 或 incomplete signature tuple 在 commit 前拒绝。
- [ ] RED：`TWO_WORKER_HA` 缺任一 digest、owner/takeover identity 相同、event-chain digest 不匹配、caller/raw identity-shaped field、或 `PROVIDER_CANARY` 携带 HA tuple 时，domain 与数据库 commit 都拒绝。
- [ ] GREEN：只实现 schema/domain/admission contract；不新增 PostgreSQL gate Repository、qualification predicate、handler、Worker mode、production config、registry 或 signer。

**G2 — required, no Skip:**

~~~bash
test -n "${AIOPS_TEST_POSTGRES_DSN:-}"
go test -race ./internal/assetcatalog ./internal/assetcatalog/postgres \
  ./internal/store/postgres \
  -run 'QualificationSchema|GateEvidenceContract|HAFactContract|SchemaAdmission|DatabaseRole' -count=1
go vet ./internal/assetcatalog/... ./internal/store/postgres
git diff --check
~~~

G2 必须使用 PostgreSQL 18.4 TLS、真实 migration/application identities、up/down/up、schema/role admission、HA tuple/direct-SQL negatives 与 pure domain tests；缺 DSN 或任一 Skip 不得 PASS。Task 19A2a 以自己的单一精确 commit/PR 合并后只产生 schema/domain `BUILT_CLOSED`，不产生 Repository、qualification Run、Provider HA/canary receipt或 `AVAILABLE`。

**Deferred G3/G4:** Task 19A2b persistence、Task 19A2c lane/assembly、Task 29A two-worker HA、Task 19B External CMDB canary/gate、Task 29B final matrix 与所有真实资格执行继续 deferred。此任务不勾任何 Provider/Worker checkbox，全部保持 `NOT_STARTED/UNAVAILABLE/CLOSED`。

### Task 19A2b: Source Gate persistence and runtime admission rechecks

**Batch:** C0，1–2 日；Task 19A2a 合并后由独立新窗口执行，独立真实 G2/PR/merge，必须完整合并后 Task 19A2c 才可开始。它只读消费 Task 19A2a `Produces`，与 Task 19A2a/19A2c exact files 零重叠。

**Exact future files:**

- Create: `internal/assetcatalog/postgres/source_gate.go`
- Create: `internal/assetcatalog/postgres/source_gate_test.go`
- Create: `internal/assetcatalog/postgres/source_gate_integration_test.go`
- Modify: `internal/assetcatalog/postgres/source_revisions.go`
- Modify: `internal/assetcatalog/postgres/page_committer.go`
- Modify: `internal/assetcatalog/postgres/source_reads.go`
- Modify: `internal/assetcatalog/postgres/source_reads_test.go`
- Modify: `internal/discoveryqueue/postgres/repository.go`
- Create: `internal/discoveryqueue/postgres/qualification.go`
- Create: `internal/discoveryqueue/postgres/qualification_test.go`
- Create: `internal/discoveryqueue/postgres/qualification_integration_test.go`

上述 11 个 future files 是 Task 19A2b 的完整且唯一清单。它只给已合并 Task 19A/M1E/Task 27 Repository types 增加 sequential persistence/recheck，不创建第二 Repository、DB pool、transaction owner、claim state machine、HTTP 或 production assembly。

**Consumes（全部已合并）:**

- Task 19A2a exact schema/domain/admission contracts and HA digest tuple。
- Task 19A publication-closed Source mutation、M1E PageCommitter 与 Task 27 Queue/terminal receipt persistence；不得修改 Task 28A loop 或 Provider package。

**Produces:**

- Generic serializable `RequestQualification/AdmitGate` persistence、qualification-only Queue predicate、safe Source reads、expiry/CAS/drift/direct-SQL guards and Audit/Outbox closure。
- Ordinary `RequestSync` and data `Claim/Reclaim/Heartbeat/PageCommitter` continue to require `AVAILABLE` and, for qualification-required profiles, reload the same current unexpired gate-evidence tuple using database time；expiry/drift yields zero Run/Catalog mutation and effective closed admission before stored projection reconciliation。
- Exact server-generated HA Queue/run receipt closure：existing Claim/Reclaim/recovery/cleanup/terminal paths—not caller input—derive and persist domain-separated `HA_OWNER_CLAIM`、`HA_TAKEOVER_COMMITTED`、`HA_RESTART_RECOVERED`、`HA_SESSION_RECOVERED`、`HA_CLEANUP_CONFIRMED` and pre-terminal `HA_RESPONSE_LOSS_REPLAYED` digests。Worker/process digests may come only from Task 28C authenticated workload/startup context，never Queue command JSON、HTTP、script flags or arbitrary worker-name config。The response-loss fact must replay an exact persisted recovery/cleanup command receipt before finalization，avoiding any self-reference to the final HA receipt。The terminal qualification loader then reloads distinct worker/process digests、exact fence increment、Task 28B recovery receipt、cleanup proof and that pre-terminal replay receipt，recomputes `ha_fact_chain_digest` and seals all facts with the existing `TERMINAL_COMMITTED` closure；no API accepts a prebuilt HA fact set。

`AdmitGate` 不信任 caller decision。它按固定锁序在一个 `SERIALIZABLE READ WRITE` transaction 内重载 exact Source/Revision/validation、terminal canary Run、其 prior `TWO_WORKER_HA` Run、installed Profile/runtime manifest、signing key/expiry，并调用已注册 Provider-neutral evaluator；复验签名、content digest、Scope/Source/Revision/binding/lab-binding、CAS 和 `clock_timestamp()` 后，才写 `AVAILABLE`、gate epoch +1、current evidence pointer/digest/expiry、Audit 和 Outbox。任一缺失、过期、drift、changed replay、并发 mutation、unknown evaluator 或 cleanup uncertainty 整笔回滚并保持 `UNAVAILABLE|SUSPENDED`。Evidence/reference drift 的反向 mutation 使用相同锁序原子关门。

**RED → GREEN:**

- [ ] RED：ordinary RequestSync、Claim/Reclaim/Heartbeat/PageCommitter 在 receipt expiry/drift crossing 后全部零写；exact current evidence 才继续。
- [ ] RED：HA owner/takeover/restart/recovery/cleanup/response-loss 任一 durable receipt 缺失、identity 不 distinct、fence 非 exact increment、changed replay 或 caller fact injection 时，qualification fact reload 与 terminal seal preparation 均拒绝。
- [ ] RED：`AdmitGate` 缺 Provider evaluator、current validation、`TWO_WORKER_HA`、`PROVIDER_CANARY`、cleanup proof、signature 或未过期窗口任一事实时零 mutation；并发 drift 只允许一方提交。
- [ ] GREEN：只实现 existing Repository methods/predicates and exact receipt reload；不新增 Worker loop、signer、HTTP handler 或 production config。

**G2 — required, no Skip:**

~~~bash
test -n "${AIOPS_TEST_POSTGRES_DSN:-}"
go test -race ./internal/assetcatalog/postgres ./internal/discoveryqueue/postgres \
  -run 'SourceGatePersistence|QualificationFacts|AdmitGate|Expiry|Drift|ResponseLoss' -count=1
go vet ./internal/assetcatalog/postgres ./internal/discoveryqueue/postgres
git diff --check
~~~

G2 必须使用 PostgreSQL 18.4 TLS、真实 migration/application identities、serializable concurrency、response-loss replay 与 direct-SQL negatives；缺 DSN、Skip、memory repository 或绕过 Repository 不得 PASS。Task 19A2b 独立合并后只产生 persistence `BUILT_CLOSED`，不装配 Worker/API/signer，不产生 HA/canary receipt或 `AVAILABLE`。

**Deferred G3/G4:** Task 19A2c lane/assembly、Task 29A/19B/29B 与所有真实资格执行继续 deferred；所有 Provider/Worker 保持 `NOT_STARTED/UNAVAILABLE/CLOSED`。

### Task 19A2c: Qualification lane, API, and production assembly

**Batch:** C0/C1，1–2 日；Task 19A2b 合并后由独立新窗口执行，独立真实 G2/PR/merge，必须完整合并后 Task 29A 才可开始。它只读消费 Task 19A2a/19A2b `Produces`，与两者 exact files 零重叠。

**Exact future files:**

- Create: `internal/assetcatalog/source_gate_management.go`
- Create: `internal/assetcatalog/source_gate_management_test.go`
- Create: `internal/discoveryworker/qualification.go`
- Create: `internal/discoveryworker/qualification_test.go`
- Modify: `api/openapi/control-plane-v1.yaml`
- Modify: `api/openapi/control_plane_v1_test.go`
- Modify: `web/src/shared/api/schema.d.ts`
- Create: `internal/httpapi/source_qualifications.go`
- Create: `internal/httpapi/source_qualifications_test.go`
- Modify: `internal/httpapi/asset_sources.go`
- Modify: `internal/httpapi/asset_sources_test.go`
- Create: `cmd/control-plane/source_gate.go`
- Create: `cmd/control-plane/source_gate_test.go`
- Modify: `cmd/control-plane/main.go`
- Modify: `cmd/control-plane/main_test.go`
- Create: `cmd/discovery-worker/qualification.go`
- Create: `cmd/discovery-worker/qualification_test.go`
- Modify: `cmd/discovery-worker/production.go`
- Modify: `cmd/discovery-worker/production_test.go`

上述 19 个 files 是 Task 19A2c 的完整且唯一清单。它不修改 migration、schema/domain/PostgreSQL gate/qualification predicate files，不拥有 Task 29A metrics/HA verifier、Task 19B Provider evaluator/canary 或 Task 29B matrix/CI。

**Mandatory Task 28A seam preflight — fail closed:**

实现第一步必须在 Task 19A2c 的新窗口只读核对已合并 Task 28A exact files `internal/discoveryworker/worker.go`、`worker_test.go`、`claim_runtime.go`、`claim_runtime_test.go`。`internal/discoveryworker/qualification.go` 只能是该 stable Worker 的 thin execution-mode/outcome adapter：claim、Reserve/Open/Resolve、heartbeat、fence revalidation、panic/cancel、cleanup、Delay/Complete/Fail 与 response-loss replay 仍逐字走唯一 Task 28A Worker loop；qualification adapter 只选择 Task 19A2b predicate、zero-projection outcome sink 和 `QUALIFICATION_PROOF` terminal command。

若 merged seam 不能在不调用 PageCommitter 的前提下表达 qualification outcome，Task 19A2c 必须停止且不得编辑上述 19 文件。主管理另开一个最小 sequential C0 seam corrective，只允许修改 Task 28A 的这四个 exact files，独立新窗口、定向 RED/G2、单一 PR/merge，用一个 closed `VALIDATION|DATA|QUALIFICATION` mode + typed outcome sink 扩展同一 loop；它不得创建第二 Worker/runner、第二 claim/cleanup/terminal 实现或 Provider-specific branch。该 corrective 合并后重新启动 Task 19A2c；不能为赶进度在 `internal/discoveryqualification/runner.go` 或任何新 package 复制状态机，该文件明确禁止创建。

**Consumes（全部已合并）:**

- Task 19A2a schema/domain/pure contracts and Task 19A2b qualification predicate、durable fact loader、`SourceGateRepository`/`GateEvaluator` serializable persistence。
- Task 28A unique Worker/claim-runtime execution seam、Task 28B same-attempt authority、Task 28C immutable Provider registry/production binary/runtime manifest，以及 Task 18B neutral Provider descriptor。
- No Task 29A receipt or Provider-specific canary；Task 19A2c only makes their later production entry possible。

**Produces:**

- A thin qualification mode wired into the one Task 28A fenced execution loop。It consumes exact `ACTIVE + PUBLISHED + UNAVAILABLE` claim、server-resolved opaque lab binding and Task 28C registry，executes bounded Provider read/protocol/DLP through the same Reserve/Open/Resolve/heartbeat/cleanup/terminal sequence，then calls the sole Task 19A2c zero-projection outcome sink。It never calls PageCommitter、writes Observation/Asset/Relationship、runs missing/stale、or changes Source checkpoint/`last_success`/`last_complete_snapshot`。
- Single-OpenAPI fixed operations `POST /api/v1/workspaces/{workspace_id}/asset-sources/{source_id}/revisions/{revision}:qualify` and `POST .../{revision}:admit-gate`，served only by a separate mTLS workload qualification listener—not the OIDC browser router and never `effective_actions`。Closed body contains only evidence kind、expected Source/version/gate/revision/prior-receipt digests；Idempotency-Key remains a header，and server assembly resolves the opaque lab binding。Endpoint、CredentialReference/value、credential、raw Provider payload/cursor and arbitrary Header/Body are rejected。
- The sole generic production assembly for the Task 19A2b repository、immutable `EvidenceVerifier` registry、qualification listener/mode and `QualificationOutcomeSink`/signer。The sink accepts only terminal Run coordinates/fence/evidence kind，reloads the complete Task 19A2b durable fact snapshot，selects one immutable registered verifier，recomputes result/fact-chain/receipt digests，then uses the sole signer and CAS persistence；no caller may submit HA facts、signature or decision。`cmd/discovery-worker/qualification.go` owns symlink-safe signer loading through existing workload-secret bootstrap and exposes the later registration seam used by Task 29A；Control Plane receives public keys/digests only。Task 19B may later modify only `cmd/control-plane/source_gate.go` sequentially to register neutral CMDB gate evaluator；it cannot alter persistence or execution loop。

**RED → GREEN:**

- [ ] RED：architecture test proves `internal/discoveryworker/qualification.go` contains no independent claim/Reserve/Open/Resolve/heartbeat/cleanup/Delay/Complete/Fail loop and `internal/discoveryqualification/runner.go` does not exist；all such calls originate from the one Task 28A Worker path。
- [ ] RED：CMDB publication 后 ordinary Queue claim/`RequestSync` 因 `UNAVAILABLE` 零写失败；only mTLS qualification operation may create/execute `QUALIFICATION`。OIDC bearer、browser router、unknown evidence kind、caller lab binding/endpoint/header/payload all reject。
- [ ] RED：outcome sink with missing/duplicate verifier、caller-supplied HA fact、fact reload drift、signer failure、changed response-loss replay or Task 28A fence/cleanup bypass produces zero receipt；qualification success leaves Catalog/checkpoint/success pointers unchanged。
- [ ] RED：production constructors fail closed on missing Task 19A2b repository、Task 28A mode seam、Task 28B authority、Task 28C registry/runtime manifest、mTLS identity、verifier registry or signing-key manifest；no test fake is production reachable。
- [ ] GREEN：only thin adapter/API/immutable verifier-registry/outcome-sink/signer assembly is added on top of merged persistence and unique Worker loop；browser action surface and ordinary data predicate remain unchanged。

**G2 — required, no Skip:**

~~~bash
test -n "${AIOPS_TEST_POSTGRES_DSN:-}"
go test -race ./internal/assetcatalog ./internal/discoveryworker \
  ./internal/httpapi ./cmd/control-plane ./cmd/discovery-worker \
  -run 'Qualification|GateEvidence|AdmitGate|WorkerLoop|ImportBoundary' -count=1
go test ./api/openapi -run 'Qualification|SourceGate' -count=1
corepack pnpm@10.34.0 --dir web generate:api:check
go vet ./internal/discoveryworker ./internal/httpapi ./cmd/control-plane ./cmd/discovery-worker
git diff --check
~~~

G2 必须使用 PostgreSQL 18.4 TLS、真实 Task 19A2b persistence、Task 28A/28B/28C production dependencies 和 both constructors；缺 DSN、Skip、memory repository、test-only handler、second runner/loop、mutable/duplicate verifier registry 或 missing signing-key manifest 不得 PASS。Task 19A2c 以自己的单一精确 commit/PR 合并后最多为 `BUILT_CLOSED`，不产生 Provider HA/canary receipt 或 `AVAILABLE`。

**Deferred G3/G4:** Task 29A/19B/29B 与所有真实资格执行继续 deferred；所有 Provider/Worker 保持 `NOT_STARTED/UNAVAILABLE/CLOSED`。

### Task 19B: Per-source availability gate, real staging canary, and operating proof

**Batch:** C0/C2，1–2 日 implementation plus deferred G4 execution；只能消费已合并 Task 19A2a、Task 19A2b、Task 19A2c 和 Task 29A，必须先于 Task 29B。它不得修改 Task 19A2a schema/domain、Task 19A2b persistence、Task 19A2c API/Worker loop/assembly（除下述 registration seam）或 Task 29A exact files。

**Exact files:**
- Create: `internal/sourceprofile/external_cmdb_gate.go`
- Create: `internal/sourceprofile/external_cmdb_gate_test.go`
- Create: `internal/assetsource/externalcmdb/gate.go`
- Create: `internal/assetsource/externalcmdb/gate_test.go`
- Modify: `cmd/control-plane/source_gate.go`
- Modify: `cmd/control-plane/source_gate_test.go`
- Create: `scripts/verify-external-cmdb-source.sh`
- Create: `docs/operations/asset-sources/external-cmdb.md`
- Create: `web/e2e/source-external-cmdb.spec.ts`
- Modify: `web/src/features/asset-sources/AssetSourcesPage.tsx`
- Modify: `web/src/features/asset-sources/SourceRunTimeline.tsx`

**Interfaces:**
- Consumes only merged safe facts：Task 19A exact validation + closed publication、Task 19A2a `GateEvidenceSet/GateEvaluator` contracts、Task 19A2b `SourceGateRepository` persistence、Task 19A2c `PROVIDER_CANARY` qualification lane/signer assembly、Task 29A current signed `TWO_WORKER_HA` receipt、Task 18B protocol/DLP/rate/provenance descriptors。Provider evaluator receives no endpoint、credential、runtime handle or raw payload。
- Produces the unique External CMDB `PROVIDER_CANARY` receipt and neutral evaluator/decision for gate key `EXTERNAL_CMDB/CMDB_CATALOG_V1/<source_id>/<revision_digest>`；only Task 19A2b `AdmitGate` persists status `AVAILABLE` and current evidence pointer。Task 19B does not write SQL or create a second gate repository。
- `cmd/control-plane/source_gate.go` was created by merged Task 19A2c as the generic assembly seam；Task 19B is its only sequential successor owner and may add exactly the neutral CMDB evaluator registration, without changing Task 19A2b persistence or Task 19A2c listener/Worker execution。No Task 29A/29B file overlaps this list.
- Script reads only opaque bindings `AIOPS_SOURCE_ID`, `AIOPS_SOURCE_REVISION`, `AIOPS_DISCOVERY_LAB_BINDING` and approved operator/workload identity bindings；it never accepts endpoint、credential、token、Header/Body 或 raw receipt flags and never enables shell tracing.

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

- [ ] **Step 2: Implement neutral evaluator, current receipt closure, and assembly**

The neutral evaluator requires exact current Scope/Source/Revision/binding、Task 28C descriptor/runtime manifest、successful identity/trust/credential-open/fixed-probe Validation、separate Broker cleanup、contract+negative+DLP、real TLS protocol、rate/backpressure、Task 29A `TWO_WORKER_HA` and this Task's `PROVIDER_CANARY` receipt less than 24 hours old. Both qualification receipts must bind the same Source/Revision/binding/runtime/lab-binding digest and valid signing-key chain；the canary's prior-receipts digest must include that exact HA receipt. Missing/expired/drifted/tampered proof yields only stable closed reason code and never a caller-supplied status.

Any credential/trust/network/profile/revision/runtime-manifest/signing-key change, repeated auth/schema failure, checkpoint ambiguity or protocol drift uses Task 19A2b's same-lock-order closure to make the gate unavailable before another ordinary claim；cleanup uncertainty specifically produces terminal `FAILED + SUSPENDED` and cannot be downgraded to `DEGRADED|UNAVAILABLE`. A plain upstream outage after opening sets `DEGRADED` and applies backoff；it never switches endpoint or reuses old evidence. The evaluator has no persistence method and cannot open another Provider row/family.

**G2 — local code/evaluator gate, required and independent of lab:**

```bash
go test -race ./internal/sourceprofile ./internal/assetsource/externalcmdb \
  ./cmd/control-plane -run 'ExternalCMDBGate|Qualification|AdmitGate' -count=1
go vet ./internal/sourceprofile ./internal/assetsource/externalcmdb ./cmd/control-plane
git diff --check
```

G2 uses only deterministic safe receipt/evaluator fixtures and merged generic persistence/assembly interfaces。It must not require or probe a lab binding、mTLS endpoint、real CMDB、browser or Task 29A G3 artifact，and it must not invoke `scripts/verify-external-cmdb-source.sh` or Playwright。Missing evaluator registration、changed/expired receipt、unsafe field、persistence method、second gate owner or assembly drift must fail。A passing G2 permits only the closed code/evaluator PR to merge as `BUILT_CLOSED`。

- [ ] **Step 3: Commit the G2-verified closed code/evaluator batch**

```bash
git add internal/sourceprofile/external_cmdb_gate.go internal/sourceprofile/external_cmdb_gate_test.go \
  internal/assetsource/externalcmdb/gate.go internal/assetsource/externalcmdb/gate_test.go \
  cmd/control-plane/source_gate.go cmd/control-plane/source_gate_test.go \
  scripts/verify-external-cmdb-source.sh docs/operations/asset-sources/external-cmdb.md \
  web/e2e/source-external-cmdb.spec.ts web/src/features/asset-sources/AssetSourcesPage.tsx \
  web/src/features/asset-sources/SourceRunTimeline.tsx
git commit -m "feat(assetdiscovery): gate external cmdb sources"
```

- [ ] **Step 4: Execute deferred G4 staging qualification and browser E2E**

The exact flow is `validate → publish closed → qualification-only canary → verify all current receipts → atomic AdmitGate → AVAILABLE → ordinary RequestSync`。The script first uses the approved recent-OIDC operator flow only for validate and publish, proves publication returned `PUBLISHED + UNAVAILABLE` and that an ordinary `RequestSync` is still rejected, then switches to the Task 19A2c fixed mTLS workload listener. It requests only `PROVIDER_CANARY` for the current path/CAS/digests；server-side opaque lab binding selects the preprovisioned non-production CMDB. The unique Task 28A Worker loop through Task 19A2c's thin qualification adapter performs fixed read/protocol/DLP/cleanup with zero Catalog projection and uses the sole outcome sink/signer to seal the safe receipt；no second runner exists. The script then calls the fixed `:admit-gate` operation, whose Task 19A2b repository reloads Task 29A HA + this canary and evaluator facts atomically. Only after the returned source is `AVAILABLE` may it request ordinary sync and verify counts/digests/provenance/tombstone/recovery as operating proof. It downloads only safe receipts and never prints environment values.

**Deferred G4 qualification — required before availability, no Skip:**

```bash
test -n "${AIOPS_SOURCE_ID:-}"
test -n "${AIOPS_SOURCE_REVISION:-}"
test -n "${AIOPS_DISCOVERY_LAB_BINDING:-}"
scripts/verify-external-cmdb-source.sh
corepack pnpm@10.34.0 --dir web test:e2e -- --grep "external cmdb source"
```

Expected: positive staging canary and negative pre-gate sync、wrong-authority/bad-CA/tampered-or-expired HA/canary receipt、rate-limit/schema/DLP/fence/CAS cases PASS；qualification creates zero Catalog projection，atomic gate precedes the first ordinary sync，and UI displays independent Source/Revision/Gate/checkpoint/evidence-expiry states with no trigger button、endpoint、credential or raw payload.

This G4 block is never part of the daily Task 19B G2。Missing opaque lab binding、operator/workload identity、mTLS、real CMDB、Task 29A current signed receipt、signing keys or browser dependency must fail rather than Skip。Until G4 passes, no Source becomes `AVAILABLE` and the Task 19B checkbox remains unchecked。

**Deferred G3/G4 in this corrective:** 本 PR 只修计划契约，不执行上述任务、G3 或 G4，不勾 checkbox，不写 status；External CMDB/Worker 继续 `NOT_STARTED/UNAVAILABLE/CLOSED`。
