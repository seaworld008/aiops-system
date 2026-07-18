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
| Gate evidence schema/domain/admission contract | 本包 Task 19A2a | 12 files；exact 3+23 nullable columns、four-column identity FK、named deferred closure、15-frame receipt 与 terminal seal；migration/schema/role/domain only |
| Gate persistence + runtime admission rechecks | 本包 Task 19A2b | 11 files；只消费已合并 19A2a + exact-2 validation corrective，以另一个 serializable transaction 实现 `AdmitGate`/runtime rechecks |
| Qualification lane/API + generic production assembly | 本包 Task 19A2c | 19 files；只消费已合并 19A2a/19A2b + Task 28A seam；不得复制 Worker loop |
| Provider-neutral two-worker HA/cleanup/restart/response-loss receipt + metrics | [Pack 09 Task 29A](./09-discovery-worker-ha-e2e.md#task-29a-provider-neutral-two-worker-ha-receipt-and-telemetry) | 不消费 canary、不写 gate、不产 final matrix |
| External CMDB qualification canary、gate evaluator/decision + operating proof | 本包 Task 19B | 消费 Task 19A2a/19A2b/19A2c + Task 29A 已合并 receipts；唯一调用 CMDB `AdmitGate` |
| Signed final Provider matrix + final E2E/CI | [Pack 09 Task 29B](./09-discovery-worker-ha-e2e.md#task-29b-signed-provider-matrix-and-final-e2e-ci) | 只聚合完成的 per-source gate/canary/HA receipts，不重建它们 |

这只是所有权纠偏，不回写完成度 checkbox。已合并 Task 28C/19A 后，Source Gate successor contract 的唯一无环顺序冻结为 `docs-contract corrective → 修正/重基 PR #134 → merge PR #134 → fresh Task 19A2a → exact-2 validation corrective → Task 19A2b → Task 19A2c → Task 29A → Task 19B → Task 29B`。本 corrective 合并后，主管理窗口必须从最新 `main` 另开 exact-3 manager-only PR，只修改 `docs/status/current.md`、`docs/superpowers/plans/2026-07-13-governed-operations/coverage-matrix.md`、`docs/superpowers/plans/2026-07-13-governed-operations/01-assets/09-discovery-worker-ha-e2e.md`，把同一顺序和 `Consumes` 发布到三个必读入口，不改 ABI、完成度或 checkbox；该 exact-3 合并前轨道停在 docs corrective，PR #134 修正/merge 与 A2a 均不得启动。每一 Batch 都由最新 `main` 的 fresh window 独立真实 G2/PR/merge；PR #134、fixture、旧 dirty worktree 或未合并实现不能反向成为 ABI 事实源。不得把 19A2b/19A2c/29A/19B/29B 提前；Task 18A merged code 仍只是稳定 `Produces`，旧 Task 18 继续等待 G3。所有 Source Gate 后继、真实 CMDB canary 和 G4 均 deferred，`EXTERNAL_CMDB/CMDB_CATALOG_V1` 始终保持 `NOT_STARTED/UNAVAILABLE/CLOSED`。

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

**Batch:** C0，1–2 日；本五文档 docs-contract corrective 与修正/重基后的 PR #134 必须先依次合并。随后从最新 `main` 创建 fresh worktree，独立真实 G2/PR/merge，只消费已合并 Task 19A 与规范 ABI；PR #134 只提供其纠正后的 fixture/test 前置，不得反向定义字段或 closure。Task 19A2a 完整合并后必须先完成独立 exact-2 validation corrective，Task 19A2b 才可开始。不得与 Task 19A2b/19A2c 共享文件或要求一次整体合并，也不得搬运旧 dirty A2a worktree。

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
- [设计规范 §5.2.1](../../../specs/2026-07-13-operational-assets-controlled-access-design.md#521-source-gate-qualification-唯一持久-abi) 的 exact 3+23 columns、four-column FK、15-frame receipt、A2a terminal seal/A2b gate-open transaction boundary；本任务包只能逐字实现，不能增删、改名或另造时间/identity。

**Produces:**

- Schema/domain enums `RunKind=QUALIFICATION`、`WorkResultKind=QUALIFICATION_PROOF`、closed evidence kind `TWO_WORKER_HA|PROVIDER_CANARY`，以及 safe `GateEvidenceSet/GateEvaluator/GateDecision`、`SourceGateRepository`、`QualificationFactSnapshot`、`EvidenceVerifier` 与 `QualificationOutcomeSink` pure contracts；这些接口本身不产生 registry、sink instance 或 signer。
- Existing twelve-table schema extension、named checks/deferred closure、least-privilege ACL、schema/role admission and dump/restore manifest。Task 19A2b 只能消费这些已合并 columns/contracts 实现 persistence，不得重定义字段、digest 或 evidence kind。

**Exact twelve-table extension and safe receipt:**

`asset_sources` exactly 新增以下 3 个 nullable columns，禁止第四列、alias 或兼容副本：

```text
gate_evidence_run_id uuid
gate_evidence_digest text
gate_evidence_expires_at timestamptz
```

三列必须 all-null 或 all-present。qualification-required Profile 的 `AVAILABLE|DEGRADED` 必须 all-present，其余 gate 状态必须 all-null；同一已批准 binding 的 checkpoint-lineage rollover 在 `DEGRADED` 执行期保留 current pointer，转入 `UNAVAILABLE|VALIDATING|SUSPENDED`、binding/reference/signing-key drift 或 expiry reconciliation 则必须在同一事务原子清空。`MANUAL_V1` 是 direct-`AVAILABLE` 特例并始终保持三列全 `NULL`。唯一 identity constraint 命名为 `asset_sources_gate_evidence_run_fk`：

```text
FOREIGN KEY (tenant_id, workspace_id, id, gate_evidence_run_id)
REFERENCES asset_source_runs (tenant_id, workspace_id, source_id, id)
DEFERRABLE INITIALLY DEFERRED
```

`gate_evidence_digest` 和 `gate_evidence_expires_at` 是 closure payload，不得进入 FK identity。named constraint trigger `asset_sources_gate_evidence_closure_guard` 必须 `DEFERRABLE INITIALLY DEFERRED`。

`asset_source_runs` exactly 新增以下 23 个 nullable columns；前 13 个是 qualification tuple，后 10 个是 Pack 06 已冻结的 HA tuple：

```text
qualification_evidence_kind text
qualification_scope_digest text
qualification_binding_digest text
qualification_profile_descriptor_digest text
qualification_runtime_manifest_digest text
qualification_lab_binding_digest text
qualification_prior_receipts_digest text
qualification_result_digest text
qualification_receipt_issued_at timestamptz
qualification_receipt_expires_at timestamptz
qualification_signing_key_id text
qualification_signature text
qualification_receipt_digest text
ha_owner_worker_identity_digest text
ha_takeover_worker_identity_digest text
ha_owner_process_instance_digest text
ha_takeover_process_instance_digest text
ha_takeover_receipt_digest text
ha_restart_receipt_digest text
ha_session_recovery_receipt_digest text
ha_cleanup_receipt_digest text
ha_response_loss_receipt_digest text
ha_fact_chain_digest text
```

`qualification_evidence_kind` 只有 `TWO_WORKER_HA|PROVIDER_CANARY`。所有 `*_digest` 只接受 lowercase 64-character SHA-256 hex；`qualification_signature` 只接受 canonical unpadded base64url，decode/re-encode 必须逐字相等且不得含 `=`。`qualification_receipt_issued_at` 是 cleanup 后 receipt seal 的独立时刻，绝不能复用 pre-cleanup `work_result_recorded_at`；issued/expiry 必须 finite 且 expiry > issued。non-`QUALIFICATION` Run 的 23 列全 `NULL`；terminal `TWO_WORKER_HA` 的 10 个 HA columns all-present，owner/takeover worker 与 process digests 各自 distinct；`PROVIDER_CANARY` 的 10 列全 `NULL`，只用 `qualification_prior_receipts_digest` 绑定 exact prior HA receipt。

qualification lifecycle 唯一为 `queue immutable binding → WorkResult → cleanup REVOKED → receipt seal → terminal closure → Task 19A2b AdmitGate`。queue 时 evidence kind、scope/binding/profile/runtime/lab/prior digests 已 present 且不可变；WorkResult 只追加 result digest。cleanup proof 完成前 issued/expiry/key/signature/receipt digest 与全部 HA columns 必须为 `NULL`。取得 proof 后，同一个最终 `SERIALIZABLE READ WRITE` logical closure 才可原子记录 `cleanup_status=REVOKED`、封存 receipt、按 kind 填 HA tuple、提交 terminal Run 与 exact `ASSET_SOURCE_RUN/TERMINAL_COMMITTED` receipt；此 transaction 结束时 Source pointer 仍全 `NULL`、gate 仍关闭。A2a 不能调用 `AdmitGate` 或写 `AVAILABLE`。

qualification receipt 是 exactly 15-frame `FramedTupleV1`，帧序固定：

```text
01 domain = "asset-source-qualification-receipt.v1"
02 tenant_id
03 workspace_id
04 source_id
05 source_revision as minimal decimal
06 qualification_binding_digest as raw 32 bytes
07 qualification_profile_descriptor_digest as raw 32 bytes
08 qualification_runtime_manifest_digest as raw 32 bytes
09 qualification_lab_binding_digest as raw 32 bytes
10 qualification_evidence_kind
11 qualification_prior_receipts_digest as raw 32 bytes
12 qualification_result_digest as raw 32 bytes
13 qualification_receipt_issued_at as UTC RFC3339 fixed-six-digit microseconds
14 qualification_receipt_expires_at in the same format
15 qualification_signing_key_id
```

`qualification_receipt_digest` 是上述 tuple bytes 的 SHA-256 lowercase hex；signature 覆盖其 raw 32 bytes。`qualification_scope_digest` 是额外 exact composite-Scope guard，不替代 Tenant/Workspace/Source 三个 identity frames。raw binding ID、endpoint、credential/reference value、Provider object/payload/cursor、Header/Body 和错误正文都不入帧、不落库。

deferred trigger 在 commit 时必须重载并逐值复验 exact Tenant/Workspace/Source、published revision、canonical binding、terminal successful `QUALIFICATION/QUALIFICATION_PROOF/PROVIDER_CANARY` Run、`REVOKED` cleanup、receipt digest/signature/expiry、same binding/runtime/lab 的 exact prior terminal `TWO_WORKER_HA`、zero page/relation/count/effective-snapshot/Source-checkpoint/success projection；Source payload digest/expiry 必须分别等于 canary Run receipt digest/expiry。`source.gate_revision = qualification_run.gate_revision + 1` 只在 `AdmitGate` 首次写 pointer 的 commit 精确成立；后续同 binding checkpoint-lineage rollover 可以推进 Source epoch，但 closure 必须从 admission epoch 重载同 Source/Revision/binding 的完整、无间隙、逐 epoch terminal rollover receipt chain，且当前 `DEGRADED`/`AVAILABLE` 必须分别对应已封存的进入/成功 terminal 边。partial tuple、cross-Scope/source、wrong kind、nonterminal、expired、digest/signature/expiry mismatch、错误 revision/binding、缺 HA、HA identity 不 distinct、epoch 回退/跳跃或 receipt-chain 缺口均必须 commit fail。

application/workload 对全部 3+23 columns 不得有 direct column UPDATE，尝试必须返回 `42501`。只有 migration-owner 可在 disposable `_test.go` database 中为 closure/recovery 构造 structurally-valid final `AVAILABLE` fixture；synthetic pointer + `AVAILABLE` 必须在同一最终 serializable transaction，且仍通过 schema/deferred closure。该 fixture 不能成为 A2a/A2b、G2/G4 或 availability 证据，也不能进入 production assembly。测试 fake、临时 bypass、手工 receipt 文件和 matrix status 都不是证据。

**RED → GREEN:**

- [ ] RED：catalog manifest 精确断言 Source 3 列、Run 23 列的 name/type/nullability，且只有 named four-column deferred FK；6-column FK、digest/expiry identity、缺列/多列/别名或非 deferred 形态均失败。
- [ ] RED：queue binding → WorkResult → final cleanup/receipt/terminal closure 的每个允许状态通过；cleanup 前 issued/expiry/key/signature/receipt/HA 任一 present、issued time 复用 `work_result_recorded_at`、cleanup 后未同事务 terminal/`TERMINAL_COMMITTED` 或 A2a 写 Source pointer/`AVAILABLE` 均 commit fail。
- [ ] RED：固定 15-frame canonical vectors、minimal-decimal revision、raw32 digests、UTC microsecond time、unpadded-base64url signature 与 raw32 receipt-digest signature coverage；帧增删/换序、padded signature、uppercase/non-64 hex 或 timestamp alias 全拒绝。
- [ ] RED：named deferred closure 接受 structurally exact current canary 和保留该 current pointer 的完整同 binding rollover receipt chain；partial/cross-Scope/wrong-kind/nonterminal/expired/mismatch/错误 binding/revision/缺 HA/非零 projection、epoch 回退/跳跃或 chain 缺口全部 commit fail；rollover 执行期 `DEGRADED` 与成功 terminal `AVAILABLE` 保留 pointer，`SUSPENDED` 原子清 pointer，`MANUAL_V1` direct `AVAILABLE` 保持 pointer 全 NULL。
- [ ] RED：application/workload 对 3+23 任一 direct write 返回 `42501`。migration-owner synthetic final `AVAILABLE` 只允许 disposable `_test.go` closure/recovery fixture，pointer + status 必须同一最终 serializable transaction，且测试明确禁止把它计作 A2a/A2b/G2/G4/availability evidence。
- [ ] GREEN：只实现 schema/domain/admission contract；不新增 PostgreSQL gate Repository、qualification predicate、handler、Worker mode、production config、registry 或 signer。

**G2 — required, no Skip:**

~~~bash
test -n "${AIOPS_TEST_POSTGRES_DSN:-}"
go test -race ./internal/assetcatalog ./internal/assetcatalog/postgres \
  ./internal/store/postgres \
  -run 'QualificationSchema|QualificationLifecycle|QualificationReceipt|GateEvidenceContract|GateEvidencePointer|HAFactContract|SchemaAdmission|DatabaseRole' -count=1
go vet ./internal/assetcatalog/... ./internal/store/postgres
git diff --check
~~~

G2 必须使用 PostgreSQL 18.4 TLS、真实 migration/application identities、up/down/up、schema/role admission、3+23 catalog manifest、four-column FK/deferred trigger、15-frame vectors、lifecycle、HA tuple/direct-SQL negatives 与 pure domain tests；缺 DSN 或任一 Skip 不得 PASS。migration-owner fixture 只证明结构 closure/recovery，不得列入 A2a 行为 PASS。Task 19A2a 以自己的单一精确 commit/PR 合并后只产生 schema/domain `BUILT_CLOSED`，不产生 Repository、真实 qualification Run、Provider HA/canary receipt或 `AVAILABLE`。

**Deferred G3/G4:** Task 19A2b persistence、Task 19A2c lane/assembly、Task 29A two-worker HA、Task 19B External CMDB canary/gate、Task 29B final matrix 与所有真实资格执行继续 deferred。此任务不勾任何 Provider/Worker checkbox，全部保持 `NOT_STARTED/UNAVAILABLE/CLOSED`。

### Post-A2a exact-2 domain-validation corrective

**Batch:** sequential C0；Task 19A2a merge 后必须从最新 `main` 创建 fresh worktree，先完成本 corrective 的 fail-first pure behavior tests、受影响 unit/race、fresh G1、独立 P0/P1 review 与单独 PR/merge，之后 Task 19A2b 才可开始。它只消费已合并 A2a domain types/ABI，不读取 PR #134、fixture、旧 dirty worktree或未合并 A2b 实现。

**Exact two files:**

- Modify: `internal/assetcatalog/validation.go`
- Create: `internal/assetcatalog/validation_test.go`

上述两文件是完整且唯一所有权。禁止修改 migration、schema/role admission、PostgreSQL Repository、Queue、HTTP/OpenAPI/Web、Worker、signer、production config 或任何 Provider package；发现需改这些 surface 时整批停止并返回契约复核。

**Pure validation contract:**

- `Source.Validate` 对三列 gate tuple 实施 all-null-or-all-present、UUID/lowercase-64-hex/finite-UTC expiry shape、qualification-required `AVAILABLE|DEGRADED` 必须 all-present、其余 gate 状态必须 all-null，以及 `MANUAL_V1` direct-`AVAILABLE` 始终 all-null 特例。它不读取 wall clock；current expiry 与 drift 的数据库时间重载仍只属于 A2b。
- `SourceRun.Validate` 强制非 `QUALIFICATION` Run 的 23 列全 `NULL`；`QUALIFICATION` 必须 zero Catalog/checkpoint/success projection、只使用 `QUALIFICATION_PROOF`，并逐 lifecycle 验证 queue immutable binding、WorkResult、cleanup `REVOKED` 后 receipt seal、terminal closure 的 nullability。cleanup 前 receipt time/key/signature/digest 与 HA tuple 必须全空；terminal `TWO_WORKER_HA` 要求 exact HA all-present/distinct，terminal `PROVIDER_CANARY` 要求 HA all-null；失败/cleanup uncertainty 不得伪造成功 receipt。
- Domain validation 只拒绝不可能 shape，不签名、不持久、不解释 current evaluator/receipt-chain，也不调用 `AdmitGate`。数据库 deferred closure 与 A2b current-time/CAS/runtime rechecks 仍是独立必需门。

**RED → GREEN:**

- [ ] RED：table-driven `Source.Validate` 覆盖 partial tuple、错误 UUID/digest/expiry、各 gate status、qualification-required 与 `MANUAL_V1`；任一 fail-open 先失败。
- [ ] RED：table-driven `SourceRun.Validate` 覆盖 non-qualification 携带 evidence、qualification 非零 projection、错误 WorkResult/lifecycle、cleanup 前 seal、HA partial/non-distinct、canary 携带 HA 与 failed Run 伪造 receipt；任一 fail-open 先失败。
- [ ] GREEN：只在 `validation.go` 做最小 pure validation，实现后全部 table cases 通过；不得为了绿灯弱化 A2a types、迁移或数据库约束。

**Required verification, no Skip:**

~~~bash
go test ./internal/assetcatalog -run 'Source.*Validate|SourceRun.*Validate|Qualification|GateEvidence' -count=1
go test -race ./internal/assetcatalog -run 'Source.*Validate|SourceRun.*Validate|Qualification|GateEvidence' -count=1
go test ./internal/assetcatalog/...
go vet ./internal/assetcatalog/...
git diff --check
~~~

随后执行 fresh G1。PR 必须恰为上述两文件，并取得 exact-head 独立 P0/P1 review；此 corrective 只产生 domain-validation `BUILT_CLOSED`，不计 A2a/A2b/G2/G4 或 availability 证据。G3/G4 与全部真实 qualification/HA/canary/gate 继续 deferred，所有 Provider/Worker 保持 `UNAVAILABLE/CLOSED`。

### Task 19A2b: Source Gate persistence and runtime admission rechecks

**Batch:** C0，1–2 日；Task 19A2a 与 post-A2a exact-2 validation corrective 都合并后，才由最新 `main` 的独立新窗口执行，独立真实 G2/PR/merge，必须完整合并后 Task 19A2c 才可开始。它只读消费已合并 A2a `Produces`，与 Task 19A2a/19A2c exact files 零重叠。

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

- Generic serializable `RequestQualification/AdmitGate` persistence、qualification-only Queue predicate、safe Source reads、expiry/CAS/drift/direct-SQL guards and Audit/Outbox closure。`RequestQualification` queues only the immutable evidence kind + scope/binding/profile/runtime/lab/prior tuple；result、issued/expiry/key/signature/receipt and HA columns remain NULL until their required lifecycle points。
- Ordinary `RequestSync` and data `Claim/Reclaim/Heartbeat/PageCommitter` continue to require `AVAILABLE` and, for qualification-required profiles, reload the same current unexpired gate-evidence tuple using database time；expiry/drift yields zero Run/Catalog mutation and effective closed admission before stored projection reconciliation。
- Exact server-generated HA Queue/run receipt closure：existing Claim/Reclaim/recovery/cleanup/terminal paths—not caller input—derive and persist domain-separated `HA_OWNER_CLAIM`、`HA_TAKEOVER_COMMITTED`、`HA_RESTART_RECOVERED`、`HA_SESSION_RECOVERED`、`HA_CLEANUP_CONFIRMED` and pre-terminal `HA_RESPONSE_LOSS_REPLAYED` digests。Worker/process digests may come only from Task 28C authenticated workload/startup context，never Queue command JSON、HTTP、script flags or arbitrary worker-name config。The response-loss fact must replay an exact persisted recovery/cleanup command receipt before finalization，avoiding any self-reference to the final HA receipt。The terminal qualification loader then reloads distinct worker/process digests、exact fence increment、Task 28B recovery receipt、cleanup proof and that pre-terminal replay receipt，recomputes `ha_fact_chain_digest` and seals all facts with the existing `TERMINAL_COMMITTED` closure；no API accepts a prebuilt HA fact set。

qualification finalization 与 `AdmitGate` 是两个不可合并的 serializable transactions。前者只在 cleanup proof 已成功后原子记录 `REVOKED`、exact 15-frame receipt、terminal Run/`TERMINAL_COMMITTED`，并必须以 Source pointer 全 NULL、gate closed 提交。`AdmitGate` 不信任 caller decision；它在另一个 `SERIALIZABLE READ WRITE` transaction 按固定锁序重载 exact Source/Revision/validation、terminal canary Run、其 prior `TWO_WORKER_HA` Run、installed Profile/runtime manifest、signing key/expiry，并调用已注册 Provider-neutral evaluator。只有全部签名、content digest、Scope/Source/Revision/binding/lab-binding、CAS 与 `clock_timestamp()` 复验成功，才可同事务写 all-present Source pointer、`AVAILABLE`、`source.gate_revision=canary_run.gate_revision+1`、Audit 和 Outbox；named deferred trigger必须在 commit 再复验。任一缺失、过期、drift、changed replay、并发 mutation、unknown evaluator 或 cleanup uncertainty 整笔回滚并保持 `UNAVAILABLE|SUSPENDED`。Evidence/reference drift 的反向 mutation使用相同锁序原子关门并清空三列 pointer。

**RED → GREEN:**

- [ ] RED：`RequestQualification` 只写 immutable queue binding；任何 result/receipt/HA 预填、queue binding 后 mutation 或非 qualification path 携带 23-column tuple 均拒绝。
- [ ] RED：ordinary RequestSync、Claim/Reclaim/Heartbeat/PageCommitter 在 receipt expiry/drift crossing 后全部零写；exact current evidence 才继续，stored pointer reconciliation 同事务关闭 gate并清空 pointer。
- [ ] RED：HA owner/takeover/restart/recovery/cleanup/response-loss 任一 durable receipt 缺失、identity 不 distinct、fence 非 exact increment、changed replay 或 caller fact injection 时，qualification fact reload 与 terminal seal preparation 均拒绝。
- [ ] RED：qualification finalization commit 后 pointer 仍 NULL/gate closed；任何把 terminal seal 与 gate open 合并的 transaction 拒绝。`AdmitGate` 缺 Provider evaluator、current validation、`TWO_WORKER_HA`、terminal `PROVIDER_CANARY`、`REVOKED` cleanup、signature 或未过期窗口任一事实时零 mutation；成功时 pointer + `AVAILABLE` + exact run epoch + Audit + Outbox 同事务，并发 drift 只允许一方提交。
- [ ] RED：partial/cross-Scope/wrong-kind/nonterminal/expired/payload mismatch/错误 revision or binding/缺 HA pointer commit 全失败；application/workload direct write 为 `42501`。测试不得用 migration-owner synthetic pointer + `AVAILABLE` 冒充 `AdmitGate`。
- [ ] GREEN：只实现 existing Repository methods/predicates and exact receipt reload；不新增 Worker loop、signer、HTTP handler 或 production config。

**G2 — required, no Skip:**

~~~bash
test -n "${AIOPS_TEST_POSTGRES_DSN:-}"
go test -race ./internal/assetcatalog/postgres ./internal/discoveryqueue/postgres \
  -run 'SourceGatePersistence|QualificationFacts|AdmitGate|Expiry|Drift|ResponseLoss' -count=1
go vet ./internal/assetcatalog/postgres ./internal/discoveryqueue/postgres
git diff --check
~~~

G2 必须使用 PostgreSQL 18.4 TLS、真实 migration/application identities、serializable concurrency、response-loss replay 与 direct-SQL negatives；positive gate test 必须调用 application Repository `AdmitGate`，不得由 migration-owner 直接合成 pointer + `AVAILABLE`。缺 DSN、Skip、memory repository 或绕过 Repository 不得 PASS。Task 19A2b 独立合并后只产生 persistence `BUILT_CLOSED`，不装配 Worker/API/signer，不产生真实 HA/canary receipt或运行时 `AVAILABLE`。

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
- The sole generic production assembly for the Task 19A2b repository、immutable `EvidenceVerifier` registry、qualification listener/mode and `QualificationOutcomeSink`/signer。The sink accepts only terminal Run coordinates/fence/evidence kind，reloads the complete Task 19A2b durable fact snapshot，selects one immutable registered verifier，recomputes result/fact-chain/receipt digests，then uses the sole signer and CAS persistence；no caller may submit HA facts、signature or decision。It may seal only after exact `REVOKED` cleanup，generates `qualification_receipt_issued_at` independently from `work_result_recorded_at`，and commits receipt + terminal/`TERMINAL_COMMITTED` while leaving the Source pointer NULL/gate closed。`cmd/discovery-worker/qualification.go` owns symlink-safe signer loading through existing workload-secret bootstrap and exposes the later registration seam used by Task 29A；Control Plane receives public keys/digests only。Task 19B may later modify only `cmd/control-plane/source_gate.go` sequentially to register neutral CMDB gate evaluator；it cannot alter persistence or execution loop。

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
bash -n scripts/verify-external-cmdb-source.sh
corepack pnpm@10.34.0 --dir web typecheck
corepack pnpm@10.34.0 --dir web lint
corepack pnpm@10.34.0 --dir web build
git diff --check
```

G2 uses only deterministic safe receipt/evaluator fixtures and merged generic persistence/assembly interfaces。`bash -n` 只静态解析 future verifier 而不执行它；三个 pnpm 命令只运行 `web/package.json` 已存在的 `typecheck`、`lint` 与 production `build` scripts。G2 must not require or probe a lab binding、mTLS endpoint、real CMDB、browser or Task 29A G3 artifact，and it must not execute `scripts/verify-external-cmdb-source.sh`、Playwright or `test:e2e`。Missing evaluator registration、changed/expired receipt、unsafe field、persistence method、second gate owner or assembly drift must fail。A passing G2 permits only the closed code/evaluator PR to merge as `BUILT_CLOSED`。

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
