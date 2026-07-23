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
| Gate persistence + runtime admission rechecks | 本包 Task 19A2b | 11 files；只消费已合并 19A2a + post-A2a exact-2 validation corrective，以另一个 serializable transaction 实现 primitive consumer、`AdmitGate`/current trust rechecks |
| Qualification lane/API + generic production assembly | 本包 Task 19A2c | 23 files；只消费已合并 19A2a/19A2b + Task 28A seam；不得复制 Worker loop |
| Provider-neutral two-worker HA/cleanup/restart/response-loss receipt + metrics | [Pack 09 Task 29A](./09-discovery-worker-ha-e2e.md#task-29a-provider-neutral-two-worker-ha-receipt-and-telemetry) | 不消费 canary、不写 gate、不产 final matrix |
| External CMDB qualification canary、gate evaluator/decision + operating proof | 本包 Task 19B | 消费 Task 19A2a/19A2b/19A2c + Task 29A 已合并 receipts；唯一调用 CMDB `AdmitGate` |
| Signed final Provider matrix + final E2E/CI | [Pack 09 Task 29B](./09-discovery-worker-ha-e2e.md#task-29b-signed-provider-matrix-and-final-e2e-ci) | 只聚合完成的 per-source gate/canary/HA receipts，不重建它们 |

这只是所有权纠偏，不回写完成度 checkbox。已合并 Task 28C/19A 后，Source Gate successor contract 的当前唯一无环顺序冻结为 `reachability docs corrective → manager exact-3 contract sync → source-gate capability-identity harness C0 → pre-A2a exact-2 routine/test-boundary corrective → manager exact-3 evidence sync → global routine ACL exact-11 contract + status sync → pre-A2a formal-fixture compatibility exact-9 corrective → pre-A2a identity-FK fixture compatibility exact-9B docs-only contract checkpoint → [DEVELOPMENT_PAUSED] → resumed fresh test-only identity-FK fixture corrective → fresh Task 19A2a exact-12 → post-A2a exact-2 validation corrective → Task 19A2b → Task 19A2c → Task 29A → Task 19B → Task 29B`。global routine ACL exact11已由PR #152合并，formal-fixture exact9已由PR #153合并为`main@c0b620e6fff9de0b746504f5fb7231fcb4a213c4`、tree`0af13374448f1386593291631e10a07add41440b`。PR #153后的fresh formal A2a暴露独立identity-FK fixture冲突：合法top-level`ALTER TABLE ... ADD CONSTRAINT`与inline named constraint分别被merged discriminator/extractor拒绝。截止2026-07-23，本轮只冻结下述exact9B exact8 docs合同并暂停开发；原Phase B test-only实现`NOT_STARTED`且不是本交付，docs-only exact9B不解阻A2a。全部partial A2a均为`STOPPED/NOT PASS`，停止的`cb00`及其他dirty/stopped A2a worktree/WIP/snapshot永不作为输入，任何未完成实现不提交、不合并。恢复后的唯一入口是从届时最新`origin/main`创建fresh、独立test-only identity-FK fixture corrective并完成RED→GREEN、完整验证、独立复核、PR/merge；之后才允许fresh Task19A2a exact12。pre-A2a exact-2 global helper与PR #153 auxiliary matrix保持安全真值且不得收窄；fresh A2a仍消费本Pack唯一exact72 identity manifest与production digest。每一实现Batch只消费最新`main`；不得提前19A2b/19A2c/29A/19B/29B。所有Source Gate后继、真实CMDB canary和G4均deferred，`EXTERNAL_CMDB/CMDB_CATALOG_V1`与全部Source/Provider/Worker始终保持`NOT_STARTED/UNAVAILABLE/CLOSED`。

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

### Pre-Task 19A2a: mutation-authority reachability and test boundary

**Batch:** sequential C0。fresh formal A2a 在真实 Go RED→GREEN、ACL RED 与 PostgreSQL 18.4 TLS schema RED 后发现三项权威合同缺口：protected 3+23 columns 没有 A2b 可达的正向 mutation authority；`000015` 没有 current public-key/runtime registry 却被要求完成密码学验签；qualification-required Profile 没有冻结的持久判别。该未提交尝试必须停止并保持为诊断证据，不能 stage/commit、不能成为后继实现输入。当前唯一顺序固定为：

```text
reachability docs corrective
→ manager exact-3 contract sync
→ source-gate capability-identity harness C0
→ pre-A2a exact-2 routine/test-boundary corrective
→ manager exact-3 evidence sync
→ global routine ACL exact-11 contract + status sync
→ pre-A2a formal-fixture compatibility exact-9 corrective
→ pre-A2a identity-FK fixture compatibility exact-9B docs-only contract checkpoint
→ [DEVELOPMENT_PAUSED]
→ resumed fresh test-only identity-FK fixture corrective
→ fresh Task 19A2a exact-12
→ post-A2a exact-2 validation corrective
→ Task 19A2b → Task 19A2c → Task 29A → Task 19B → Task 29B
```

第一次 manager exact-3 contract sync 先把 status 入口改为 capability harness；后续 harness只预置身份/DSN/certificate与双向ACL helper，不修改migration或授予函数。该helper只有在future owned exact38/global exact110 postflight都通过时才授予capability`CONNECT|USAGE`；predecessor72/owned36、down、unknown或partial均revoke并证明absent。pre-A2a exact-2合并后manager evidence sync记录其证据；global routine ACL exact11 corrective已由 PR #152 以同一原子提交冻结72↔110/rollback/recovery合同并同步current/coverage/Pack09入口。PR #152后的fresh A2a确认exact3/trigger/drop fixture blocker，PR #153 exact9已将其关闭并合并为`main@c0b620e6fff9de0b746504f5fb7231fcb4a213c4`、tree`0af13374448f1386593291631e10a07add41440b`。其后fresh formal A2a又确认identity FK无论以合法top-level ADD CONSTRAINT或inline named constraint表达都必然被merged fixture拒绝。截至2026-07-23只冻结exact9B docs-only合同并暂停开发，test-only实现保持`NOT_STARTED`；恢复后须新建fresh独立corrective并完成RED→GREEN/复核/PR/merge。全部partial A2a均为`STOPPED/NOT PASS`，停止的`cb00`和其他dirty/stopped A2a worktree/WIP/snapshot不得续用或复制，任何未完成实现不提交、不合并；docs-only exact9B不实现A2a/G2。

pre-A2a exact-2 的完整且唯一文件为：

- Modify: `internal/assetcatalog/postgres/migration_corrective_test.go`
- Modify: `internal/assetcatalog/postgres/migration_closure_adversarial_integration_test.go`

**Consumes（全部已合并）:** 前序八文档 reachability contract、第一次 manager exact-3 contract sync、capability-identity harness C0、Task 19A 的 closed publication admission，以及现有 exact-36/fixture-owner test boundary；不得读取未提交 formal A2a。

**Produces:** 只把 successor routine manifest 从 existing exact 36 冻结为 exact 38、锁定两条新 routine 的 canonical signature/owner/language/volatility/strict/security/search-path/session-user/ACL/down lifecycle、冻结 Sources/Runs 列级 INSERT/UPDATE 边界，并把 fixture synthetic signature 明确限制为 canonical structural shape。它要求 ordinary runtime/workload 两条都不可执行、sealer 只能 seal、admitter只能 admit、交叉调用与任一 relation privilege均失败。该已合并pre-A2a exact-2不修改 migration、schema/role admission、domain、Repository、Worker、API、status 或能力状态；其targeted fail-first tests、fresh G1、独立 P0/P1 review 与单独 PR/merge 后，manager evidence sync已记录harness/pre-A2a merged证据。global routine ACL exact11已由PR #152原子同步合同与status/coverage/Pack09，formal-fixture blocker已由PR #153 exact9关闭；其后暴露的identity-FK blocker仅在恢复开发后由fresh test-only corrective顺序关闭，该后继实现合并前formal A2a禁止重启。

### Pre-Task 19A2a: formal-fixture compatibility exact-9 corrective

**State:** merged by PR #153 as `main@c0b620e6fff9de0b746504f5fb7231fcb4a213c4`，tree `0af13374448f1386593291631e10a07add41440b`。该sequential C0 exact9只消费PR #152并按Phase A exact8→独立复核→Phase B exact1 test-only RED/GREEN/G1→独立复核→单一commit/PR/merge完成。

**Exact files:**

- Phase A exact8：`docs/status/current.md`、`docs/superpowers/specs/2026-07-13-operational-assets-controlled-access-design.md`、`docs/superpowers/plans/2026-07-13-governed-operations-program.md`、`docs/superpowers/plans/2026-07-15-fast-development-validation-program.md`、`docs/superpowers/plans/2026-07-13-governed-operations/coverage-matrix.md`、`docs/superpowers/plans/2026-07-13-governed-operations/01-assets/README.md`、本 Pack 06、Pack 09。
- Phase B exact1：Modify only `internal/assetcatalog/postgres/migration_corrective_test.go`。

上述九文件是exact9的完整且唯一历史所有权；它未修改migration、Task 19A2a exact12其他文件、OpenAPI/generated types、production code、CI/scripts/env、operations或任何其他文件。Task 19A2a exact12继续禁止修改pre-A2a helper。

**Observed merged conflict:** `correctiveSourceGateColumnsFixture` 当前无条件把 exact3 columns 追加到 `public.asset_sources`；`TestAssetCatalogCorrectiveSourceGateSuccessorTriggerManifest` 又无条件追加 `asset_sources_gate_evidence_closure_guard` 并向 down 注入其 exact drop。当前 predecessor `000015` 尚未内建这三个正式对象，故测试可通过；formal A2a 必须把 exact3/trigger/drop直接写入 `000015`，届时同一 fixture 会重复列、trigger 与 drop，正式 migration 必然不能满足自己的 manifest。该冲突只由已合并 `origin/main` 对象确认；停止的 partial A2a 永不作为输入或证据。

**Produces:** fixture construction 必须 state-aware/idempotent，且只接受两个完整合法输入状态：

1. predecessor baseline 尚未内建 exact3 columns、exact closure trigger 与 exact down drop：fixture按原合同合成三者；
2. formal A2a 已内建 exact3 columns、exact closure trigger 与 exact down drop：fixture逐项验证后直接复用，不追加或重写任何对象。

partial、duplicate、renamed、wrong type、wrong trigger、wrong relation、wrong lifecycle、dynamic DDL 或 up/down 不一致必须 fail closed。不得删除、跳过或弱化现有 adversarial cases；不得收窄 global exact72/110、owned exact38、ACL/owner/grantor/grantability、C-order、down manifest、trigger-before-table-drop、显式 revoke/restore 或 negative matrix。Phase B 只修 test fixture construction，不改变 migration、ABI、schema/domain、运行能力或验收口径。

**Required verification:** Phase B fail-first RED 必须由已-formal up/down fixture 状态真实触发，不能用文本匹配或无关编译错误冒充；GREEN 后运行定向 normal/race、受影响完整 runnable unit/static suite与 fresh G1。exact9 不以 PostgreSQL 18.4 G2 冒充 A2a；Task 19A2a 的五身份、global110/runtime72、up/down/up、双实例 restore 与其余 required G2 仍全部由后继 fresh exact12 执行。exact9 合并不提升 completion、Provider/Worker/Capability、G2/G4 或 checkbox，所有相关状态保持 `NOT_STARTED/UNAVAILABLE/CLOSED`。

### Pre-Task 19A2a: identity-FK fixture compatibility exact-9B corrective

**Pause state (2026-07-23):** `DOCS_CONTRACT_FROZEN / DEVELOPMENT_PAUSED / IMPLEMENTATION_NOT_STARTED`。

**Batch:** 本轮 exact9B 只消费已合并PR #153的`main@c0b620e6fff9de0b746504f5fb7231fcb4a213c4`、tree`0af13374448f1386593291631e10a07add41440b`，并只把下列exact8权威文档收口为docs-only暂停检查点。用户已决定暂停开发，原计划Phase B test-only实现永久停止于本轮并保持`NOT_STARTED`，不是本检查点或其后文档PR的交付；当前没有可提交或合并的实现。docs-only exact9B不等于corrective完整完成，也不允许formal A2a启动。

**Exact files:** 本暂停检查点只有上节同一exact8文档；不得修改`internal/assetcatalog/postgres/migration_corrective_test.go`、migration、Task19A2a exact12文件、OpenAPI/generated types、production code、CI/scripts/env、operations或任何其他文件。恢复开发后另从届时最新`origin/main`创建fresh、独立test-only identity-FK fixture corrective，由它单独拥有该测试fixture；该未来所有权不是本轮交付。

**Observed merged conflict:** Pack06要求唯一identity constraint为：

```text
CONSTRAINT asset_sources_gate_evidence_run_fk
FOREIGN KEY (tenant_id, workspace_id, id, gate_evidence_run_id)
REFERENCES asset_source_runs (tenant_id, workspace_id, source_id, id)
DEFERRABLE INITIALLY DEFERRED
```

`gate_evidence_digest`与`gate_evidence_expires_at`是closure payload，不进入FK。PR #153 merged `correctiveSourceGateTriggerRequired` 对任何包含`gate_evidence_`的`public.asset_sources` ALTER只接受ADD COLUMN，所以合法top-level `ALTER TABLE ... ADD CONSTRAINT`报`unreviewed gate-evidence ALTER`；merged formal→baseline extractor把table-inline named constraint视为`unreviewed gate-evidence table element`。因此formal A2a无论采用哪种合法表达都必然失败；A2a exact12禁止修改fixture，不能隐藏、转义或绕过该合同。停止的`cb00`与其他dirty/stopped partial A2a worktree/WIP/snapshot均为`STOPPED/NOT PASS`且永不作为输入，任何未完成实现不提交、不合并。

**Frozen future implementation contract:** fixture FK parser/state extractor只识别两种合法表达：table-inline named constraint，或top-level `ALTER TABLE public.asset_sources ADD CONSTRAINT`。最终有效formal状态必须有且仅有上述named exact four-column FK，constraint/source/reference name、schema/table、column order、reference order、mapping和`DEFERRABLE INITIALLY DEFERRED`逐项精确。baseline必须完全没有该FK；formal→baseline必须只剥离该唯一精确FK且不改变其他对象，baseline→formal重建后必须重跑完整formal manifest并逐字等价。

**Fail-closed matrix:** missing、partial或duplicate FK；wrong name、quoted alias或大小写别名；wrong source/reference columns、order、mapping、table或schema；6-column FK；digest/expiry进入identity；`NOT DEFERRABLE`、`INITIALLY IMMEDIATE`或缺失任一deferred属性；dynamic DDL；任何ALTER/DROP/VALIDATE/rename/disable lifecycle；额外gate constraint；up/down mismatch。实现不得使用宽松contains、简单删除first match、隐藏/转义标识符或跳过既有matrix。PR #153 exact3/trigger/drop auxiliary matrix、既有adversarial cases、global exact72/110、owned exact38、ACL/owner/grantor/grantability、C-order、down manifest、trigger-before-table-drop与显式revoke/restore全部保持原强度。

**Resumed implementation gate (`NOT_STARTED`):** 恢复开发后的唯一入口是从届时最新`origin/main`创建fresh、独立test-only identity-FK fixture corrective。其synthetic formal fixture必须包含exact3+exact named FK+trigger+down，并使当前完整successor/auxiliary matrix因FK未审而真实失败；inline与top-level两种合法表达分别覆盖。GREEN只实现严格FK parser/state-aware fixture与可逆baseline extraction，并新增上述完整负例；随后运行targeted normal/race、全部`TestAssetCatalogCorrective*` normal/race、可审计nonintegration suite、vet、diff-check与fresh G1，取得独立复核并经单独PR合并。真实PostgreSQL G2不属于该test-only corrective且不得冒充formal A2a；docs-only exact9B与未来实现均不提升completion、Provider/Worker/Capability、G2/G4或checkbox，所有相关状态保持`NOT_STARTED/UNAVAILABLE/CLOSED`。只有该后继实现合并后才允许fresh formal A2a。

### Task 19A2a: Source Gate schema, domain, and admission contract

**Batch:** C0，1–2 日；上述前置、global routine ACL exact-11 contract + status sync、pre-A2a formal-fixture compatibility exact9、exact9B docs-only checkpoint与恢复后的fresh test-only identity-FK fixture corrective必须先依次合并。随后从包含该test-only corrective merge的最新`origin/main`创建新的fresh worktree，从RED重新实现并重证，逐项消费本Pack唯一exact72 identity manifest与production digest、global110/runtime72、up/down、五身份和required双实例restore；不能读取、复制、cherry-pick或继承任何旧dirty A2a worktree/WIP/snapshot。全部partial A2a均为`STOPPED/NOT PASS`，停止的`cb00`不得成为输入。独立真实G2/PR/merge只消费已合并Task19A、已合并fixture corrective与规范ABI；fixture/test boundary不得反向定义字段、closure或生产证据，且本exact12禁止修改`internal/assetcatalog/postgres/migration_corrective_test.go`。Task19A2a完整合并后必须先完成独立post-A2a exact-2 validation corrective，Task19A2b才可开始。不得与Task19A2b/19A2c共享文件或要求一次整体合并。

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
- 已合并 capability-identity harness 只提供 sealer/admitter exact login/DSN test fixture；A2a 才在 migration/admission 内授予各自单一 routine，普通 application/runtime 继续零 Source Gate EXECUTE。
- [设计规范 §5.2.1](../../../specs/2026-07-13-operational-assets-controlled-access-design.md#521-source-gate-qualification-唯一持久-abi) 的 exact 3+23 columns、four-column FK、15-frame receipt、A2a terminal seal/A2b gate-open transaction boundary；本任务包只能逐字实现，不能增删、改名或另造时间/identity。

**Produces:**

- Schema/domain enums `RunKind=QUALIFICATION`、`WorkResultKind=QUALIFICATION_PROOF`、closed evidence kind `TWO_WORKER_HA|PROVIDER_CANARY`，以及 safe `GateEvidenceSet/GateEvaluator/GateDecision`、`SourceGateRepository`、`QualificationFactSnapshot`、`EvidenceVerifier` 与 `QualificationOutcomeSink` pure contracts；process-local `QualificationOutcome` 的 exact safe fields 只有 Run locator、evidence kind 与 sealed `LeaseFence`，不得用 caller-supplied `FenceEpoch` 替代，且整个 outcome 拒绝 JSON/Text/Binary/log serialization。上述接口本身不产生 registry、sink instance 或 signer。
- Existing twelve-table schema extension、named checks/deferred closure、least-privilege ACL、schema/role admission and dump/restore manifest。Task 19A2b 只能消费这些已合并 columns/contracts 实现 persistence，不得重定义字段、digest 或 evidence kind。
- Existing36新增两条non-overloaded primitives后`000015` owned exact38；application-schema global exact110=fixed predecessor72+Asset38。Predecessor authority为78 definitions/6 replacements/final72（68 trigger+4 helper），pre-up无direct grant而是normalized PUBLIC72；unknown73rd、missing、overload或ACL/owner/grantor/grantability drift在DDL前整笔回滚。唯一固定 identity list、serialization与production digest见本包 [Canonical predecessor exact72 runtime EXECUTE manifest](#canonical-predecessor-exact72-runtime-execute-manifest)；up的显式revoke/grant、application admission与exact-12 test必须逐项等于该列表并使用其production expected digest，禁止从运行时catalog或migration文本动态生成一个新清单后自行接受。up后PUBLIC0、runtime direct/effective90、workload direct0/effective90、capability edges仅seal/admit；down先revoke新增runtime72 edges，再删除owned38并恢复PUBLIC72，最终catalog/ACL等于pre-up；禁止schema-wide grant/revoke或恢复未知对象。两条新routine既有properties/session/lock/CAS边界不变。

#### Canonical predecessor exact72 runtime EXECUTE manifest

本节是 predecessor exact72 identity list 与 production expected digest 的唯一事实源；规范、Task1、README与runbook只能链接本节，不得复制或派生平行列表。下列 schema-qualified canonical signatures 是从已审 `000001..000014` 的78次定义、6次同identity replacement得到的72个最终identity，按UTF-8 bytes `COLLATE "C"`严格递增，无重复、无overload：

```text
public.bind_investigation_task_attempt_runtime()
public.bump_runner_scope_revision()
public.capture_credential_revocation_system_recovery()
public.enforce_action_queue_credential_cleanup()
public.enforce_credential_revocation_heartbeat_sequence()
public.enforce_credential_revocation_transition()
public.enforce_hypothesis_runtime_mutation()
public.enforce_incident_runtime_mutation()
public.enforce_investigation_runtime_transition()
public.enforce_investigation_task_attempt_lifecycle()
public.enforce_runner_certificate_lifecycle()
public.enforce_runner_result_receipt_insert()
public.enforce_tool_invocation_runtime_mutation()
public.guard_credential_revocation_system_receipt_insert()
public.investigation_json_object_document_valid(bytea, integer)
public.investigation_runtime_hypothesis_set_valid(uuid, uuid, uuid)
public.investigation_runtime_incident_signal_set_valid(uuid, uuid, uuid)
public.investigation_text_array_bounded(text[], integer, integer)
public.reject_action_queue_removal()
public.reject_action_queue_submission_identity_mutation()
public.reject_action_queue_terminal_mutation()
public.reject_audit_mutation()
public.reject_correlated_signal_mutation()
public.reject_credential_confirmation_mutation()
public.reject_credential_revocation_receipt_mutation()
public.reject_credential_revocation_removal()
public.reject_credential_revocation_reparenting()
public.reject_credential_revocation_system_receipt_mutation()
public.reject_evidence_runtime_mutation()
public.reject_feedback_runtime_mutation()
public.reject_hypothesis_evidence_runtime_mutation()
public.reject_investigation_idempotency_mutation()
public.reject_investigation_plan_binding_mutation()
public.reject_investigation_reparenting()
public.reject_investigation_runtime_identity_mutation()
public.reject_investigation_signal_correlation_mutation()
public.reject_investigation_task_attempt_removal()
public.reject_investigation_task_attempt_runtime_binding_mutation()
public.reject_legacy_execution_lease_activation()
public.reject_runner_certificate_removal()
public.reject_runner_evidence_receipt_mutation()
public.reject_runner_result_receipt_mutation()
public.reject_runner_scope_binding_update()
public.reject_tool_invocation_runtime_binding_mutation()
public.reject_tool_invocation_runtime_removal()
public.require_new_investigation_create_ledger_v2()
public.require_new_investigation_plan_binding()
public.require_new_tool_invocation_runtime_binding()
public.validate_action_queue_finalizing_receipt()
public.validate_credential_confirmation_parent_shape()
public.validate_credential_confirmation_shape()
public.validate_credential_revocation_action_marker()
public.validate_credential_revocation_completion_receipt()
public.validate_credential_revocation_confirmation()
public.validate_credential_revocation_receipt_claim()
public.validate_credential_revocation_receipt_final_shape()
public.validate_credential_revocation_system_receipt_final_shape()
public.validate_investigation_runtime_hypothesis_set()
public.validate_investigation_runtime_terminal_tasks()
public.validate_investigation_signal_correlation_insert()
public.validate_investigation_task_attempt_completion()
public.validate_investigation_task_attempt_insert()
public.validate_runner_evidence_receipt_insert()
public.validate_runtime_evidence_insert()
public.validate_runtime_evidence_task_projection()
public.validate_runtime_feedback_projection()
public.validate_runtime_hypothesis_evidence()
public.validate_runtime_hypothesis_evidence_insert()
public.validate_runtime_hypothesis_feedback()
public.validate_runtime_hypothesis_parent_set()
public.validate_runtime_incident_signal_projection()
public.validate_tool_invocation_runtime_parent_lifecycle()
```

每项的runtime direct edge payload exactly是six-element JSON array，顺序 `[grantee, canonical_signature, privilege_type, is_grantable, grantor, owner]`；例如 `["aiops_control_plane_runtime","public.reject_audit_mutation()","EXECUTE",false,"aiops_schema_owner","aiops_schema_owner"]`。Signature在PostgreSQL18.4、`quote_all_identifiers=off`、`search_path=pg_catalog,pg_temp`下由显式schema/OID的namespace、`proname`、`pg_get_function_identity_arguments`拼成。Canonical encoder固定UTF-8无BOM/空白/换行，`false`为literal；只将引号转义为`\"`、反斜杠为`\\`、U+0000..U+001F为lowercase `\u00xx`，其余有效scalar直接UTF-8，非法输入拒绝；SQL/Go不得使用`jsonb::text`或通用encoder默认格式。Domain逐字为`source-gate-predecessor-runtime-execute-manifest.v1`；按上列signature C-order，production framing为`int4send(51)||domain||int8send(72)||Σ(int4send(payload byte length)||payload)`，完整frame为10,617 bytes，对其全部bytes取lowercase SHA-256，唯一production expected digest逐字为 `088e21a85ed39b3be463f80a09a5ca3b35aa244143e3f07e9a940013c2b049d0`。One-entry `public.reject_audit_mutation()` encoding vector仍是189-byte frame与SHA-256 `4c58b76019db0f92871b972c7dabbd677ac01d97ac85ae3bbb6fe9f3822d8cc3`，只证明encoder/framing；它不得替代production digest。Migration SQL与Go admission/test必须分别硬编码并复算同一个production常量，显式枚举必须逐项等于上列72项；任何运行时快照、缺失、额外、重排、签名别名或“生成后接受”都fail closed。

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

`qualification_evidence_kind` 只有 `TWO_WORKER_HA|PROVIDER_CANARY`。所有 `*_digest` 只接受 lowercase 64-character SHA-256 hex；`qualification_signature` 只接受 canonical unpadded base64url，decode/re-encode 必须逐字相等且不得含 `=`。`qualification_receipt_issued_at` 是 cleanup 后 receipt seal 的独立时刻，绝不能复用 pre-cleanup `work_result_recorded_at`；first-write 只能使用同一 final seal transaction 的 `pg_catalog.transaction_timestamp()`，以 UTC fixed-six microseconds 入帧，SQL逐值要求 issued相等且不早于 durable cleanup receipt time。issued/expiry 必须 finite且 expiry > issued。maximum TTL 是 closed mapping：`TWO_WORKER_HA → 24 hours`、`PROVIDER_CANARY → 24 hours`；seal按 locked kind强制 `expiry <= issued + 24 hours`，future/backdated issued、unknown/oversize均拒绝。non-`QUALIFICATION` Run 的 23 列全 `NULL`；terminal `TWO_WORKER_HA` 的 10 个 HA columns all-present，owner/takeover worker 与 process digests 各自 distinct；`PROVIDER_CANARY` 的 10 列全 `NULL`，只用 `qualification_prior_receipts_digest` 绑定 exact prior HA receipt。

qualification lifecycle 唯一为 `queue immutable binding → WorkResult → RecordCleanup(REVOKED) → receipt seal + terminal closure → Task 19A2b AdmitGate`。queue 时 evidence kind、scope/binding/profile/runtime/lab/prior digests 已 present 且不可变；WorkResult 只追加 durable `work_result_digest`，existing Run trigger 在 exact qualification transition 中唯一派生同值 `qualification_result_digest`，caller不能直接更新该 protected column。existing `RecordCleanup` 先独立持久 `REVOKED` 与 exact `ATTEMPT_CLEANED` receipt；其完成前 issued/expiry/key/signature/receipt digest 与全部 HA columns 必须为 `NULL`。随后唯一最终 `SERIALIZABLE READ WRITE` receipt-seal primitive只接 Scope/Run/CAS/fence + signing-key ID/issued/expiry/signature，按 target Run→prior Runs→Source→Revision锁序重载 durable WorkResult、cleanup与 HA/Audit receipts。完成 session/isolation guard并锁 target Run后，已封存 terminal tuple 的全部 input逐值相等才可在后续 transaction零写 replay，changed replay拒绝；未封存 first-write branch必须要求 issued精确等于本 transaction的 DB time且不早于 cleanup receipt，再重算 15-frame digest和 HA fact chain、强制 locked kind maximum TTL并要求 canary expiry不晚于 locked exact prior HA expiry。随后原子写 issued/expiry/key/signature、派生 receipt digest、按 kind 派生的 HA tuple、fixed `SUCCEEDED/COMPLETED` terminal fields、terminal command digest/completion/version、capacity/fence closure与 exact `ASSET_SOURCE_RUN/TERMINAL_COMMITTED` Audit。seal不写 cleanup、Source pointer/status或 Outbox；cleanup uncertainty/failure继续由 existing Queue `Fail` path处理。未封存的 ambiguous retry在新 transaction取新 DB time并重签；此 transaction 结束时 Source pointer仍全 `NULL`、gate仍关闭。A2a 不能调用 gate-admit primitive或写 `AVAILABLE`。

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

deferred trigger 在 commit 时必须重载并逐值复验 exact Tenant/Workspace/Source、published revision、canonical binding、terminal successful `QUALIFICATION/QUALIFICATION_PROOF/PROVIDER_CANARY` Run、`REVOKED` cleanup、15-frame receipt digest、canonical signature shape、issued不早于 durable cleanup receipt、issued/expiry/closed maximum TTL、same binding/runtime/lab 的 exact prior terminal `TWO_WORKER_HA`、zero page/relation/count/effective-snapshot/Source-checkpoint/success projection；Source payload digest/expiry 必须分别等于 canary Run receipt digest/expiry。`source.gate_revision = qualification_run.gate_revision + 1` 只在 `AdmitGate` 首次写 pointer 的 commit 精确成立；后续同 binding checkpoint-lineage rollover 可以推进 Source epoch，但 closure 必须从 admission epoch 重载同 Source/Revision/binding 的完整、无间隙、逐 epoch terminal rollover receipt chain，且当前 `DEGRADED`/`AVAILABLE` 必须分别对应已封存的进入/成功 terminal 边。partial tuple、cross-Scope/source、wrong kind、nonterminal、expired、oversize TTL、digest/shape/expiry mismatch、错误 revision/binding、缺 HA、HA identity 不 distinct、epoch 回退/跳跃或 receipt-chain 缺口均必须 commit fail。first-write same-transaction issued equality由 seal primitive强制而不能由事后 trigger冒充。A2a closure 不拥有 current public-key、installed Profile/runtime registry，不得把 canonical signature shape 冒充密码学验签或 current key/runtime drift 复验；这些 current checks 只属于 A2b/A2c。

runtime 不得拥有 Sources/Runs relation-level `INSERT|UPDATE`。Source 使用 legacy column grants并排除三列 pointer，故三列 direct INSERT/UPDATE 为 `42501`。Run column INSERT 只包含 legacy initial columns + exact 7 queue-binding columns；其余 16 receipt/HA columns direct INSERT 为 `42501`。Run column UPDATE 只包含 legacy lifecycle columns，23 个 qualification/HA columns direct UPDATE 全为 `42501`。两 capability identities没有任何 relation/sequence ACL；ordinary application/runtime 两条 primitive均 `42501`，sealer/admitter交叉调用同样 `42501`。关门/reference drift/expiry 由 ordinary Repository 在 expected Source version/gate revision 下按 Source→published Revision 合法子序列锁定并更新允许的关闭态字段，由 existing trigger 原子清 pointer；它不等待或反向锁 Run，也不新增第三条 primitive。只有 exact `MANUAL/MANUAL_V1/published MANUAL_V1` 是无 pointer 特例；exact non-MANUAL 且 provider/profile 均非 `MANUAL_V1` 是 qualification-required，missing/mixed 返回 unknown 并用 `IS TRUE` fail closed，该 durable branch内联 existing deferred trigger而不新增 named predicate。只有 migration-owner 可在 disposable `_test.go` database 中为 closure/recovery 构造 structurally-valid final `AVAILABLE` fixture；synthetic pointer + `AVAILABLE` 必须在同一最终 serializable transaction，且仍通过 schema/deferred closure。该 fixture及 synthetic signature只能证明 structure，不能成为验签、A2a/A2b、G2/G4 或 availability 证据，也不能进入 production assembly。测试 fake、临时 bypass、手工 receipt 文件和 matrix status 都不是证据。

**RED → GREEN:**

- [ ] RED：catalog manifest 精确断言 Source 3 列、Run 23 列的 name/type/nullability，且只有 named four-column deferred FK；6-column FK、digest/expiry identity、缺列/多列/别名或非 deferred 形态均失败。
- [ ] RED：queue binding → WorkResult → final cleanup/receipt/terminal closure 的每个允许状态通过；cleanup 前 issued/expiry/key/signature/receipt/HA 任一 present、issued time 复用 `work_result_recorded_at`、first-write issued早/晚于同一 transaction DB time或早于 durable cleanup receipt、cleanup 后未同事务 terminal/`TERMINAL_COMMITTED` 或 A2a 写 Source pointer/`AVAILABLE` 均 commit fail。已封存 tuple 的 exact旧 input可在后续 transaction零写 replay，changed replay仍拒绝。
- [ ] RED：固定 15-frame canonical vectors、minimal-decimal revision、raw32 digests、UTC microsecond DB-issued time、unpadded-base64url signature 与 raw32 receipt-digest signature coverage；帧增删/换序、padded signature、uppercase/non-64 hex、timestamp alias、future/backdated issued、unknown kind、`expiry > issued+24h` 或 canary expiry 晚于 prior HA expiry全拒绝。
- [ ] RED：named deferred closure 接受 structurally exact current canary 和保留该 current pointer 的完整同 binding rollover receipt chain；partial/cross-Scope/wrong-kind/nonterminal/expired/mismatch/错误 binding/revision/缺 HA/非零 projection、epoch 回退/跳跃或 chain 缺口全部 commit fail；rollover 执行期 `DEGRADED` 与成功 terminal `AVAILABLE` 保留 pointer，`SUSPENDED` 原子清 pointer，`MANUAL_V1` direct `AVAILABLE` 保持 pointer 全 NULL。
- [ ] RED：Source 三列 direct INSERT/UPDATE、Run 23 列 direct UPDATE 与非 queue-binding 16 列 direct INSERT 返回 `42501`；exact 7 queue-binding INSERT 可达且任何 receipt/HA 预填被权限或 closure拒绝。migration-owner synthetic final `AVAILABLE` 只允许 disposable `_test.go` closure/recovery fixture，pointer + status 必须同一最终 serializable transaction，且测试明确禁止把它计作验签、A2a/A2b/G2/G4/availability evidence。
- [ ] RED：owned exact38只接受两条fixed primitive；global manifest严格验证pre-up72、runtime exact72 direct edge count/hash、up110 direct/effective/PUBLIC/owner/grantor/grantability、unexpected111、wrong predecessor ACL、down72 restored与up/down/up。The application identity must exercise predecessor key DML across the action-queue、credential-revocation and investigation/runtime/evidence surfaces after up、down and re-up，thereby firing the predecessor trigger graph and all four helper paths；after up and re-up it also exercises Asset/Audit/Outbox ordinary behavior。Permission success alone cannot replace behavior assertions。任一PUBLIC EXECUTE、capability交叉edge、runtime edge缺失/额外、workload direct edge、overload、错误owner/grantor/grantability/properties/session-user、schema-wide revoke/grant或缺失显式down revoke/restore均RED。receipt-seal/gate-admit的durable-fact派生、lock/CAS和payload拒绝边界保持不变。
- [ ] RED：`QualificationOutcome` exact field/method reflection只允许 locator/evidence kind/sealed `LeaseFence`，拒绝 public token/hash accessor、caller epoch或任一序列化/日志面；A2b 后续必须能在不修改 A2a domain files 的前提下消费 raw fence完成 `Matches`。
- [ ] GREEN：只实现 schema/domain/admission contract和上述两条 typed SQL primitive；不新增 PostgreSQL gate Repository、named qualification predicate、handler、Worker mode、production config、registry 或 signer。

**G2 — required, no Skip:**

~~~bash
test -n "${AIOPS_TEST_POSTGRES_DSN:-}"
test -n "${AIOPS_TEST_POSTGRES_MIGRATION_DSN:-}"
test -n "${AIOPS_TEST_POSTGRES_APPLICATION_DSN:-}"
test -n "${AIOPS_TEST_POSTGRES_SOURCE_GATE_SEAL_DSN:-}"
test -n "${AIOPS_TEST_POSTGRES_SOURCE_GATE_ADMIT_DSN:-}"
go test -race ./internal/assetcatalog ./internal/assetcatalog/postgres \
  ./internal/store/postgres \
  -run 'QualificationSchema|QualificationLifecycle|QualificationReceipt|GateEvidenceContract|GateEvidencePointer|HAFactContract|SchemaAdmission|DatabaseRole' -count=1
go vet ./internal/assetcatalog/... ./internal/store/postgres
git diff --check
~~~

G2 必须使用 PostgreSQL 18.4 TLS、五身份、up/down/up、schema/role/capability admission、3+23、owned exact38/global exact110 ACL、runtime exact72 edge count/hash与SQL/Go known-vector parity、15-frame/lifecycle/HA/direct-SQL negatives。Predecessor关键DML、68 trigger与4 helper必须在up/down/re-up验证；`000015` Asset/Audit/Outbox ordinary behavior只在up/re-up验证。exact-12新integration test还覆盖unexpected111、wrong predecessor ACL、五身份与上述ACL维度；merged pre-A2a global helper不得修改或收窄。由于ACL/恢复语义变化，双实例dump/restore recovery在本A2a为required G2，必须证明restore后的global110/runtime exact72 direct manifest与down恢复72且撤销新增edges；缺DSN、共享credential、Skip、identity mismatch或未执行recovery不得PASS。future`000016..000022`新增/替换public routine必须更新content-addressed global manifest、显式PUBLIC revoke与rollback contract，否则admission fail closed。Task19A2a仍只产生`BUILT_CLOSED`，不产生真实qualification或availability。

**Deferred G3/G4:** Task 19A2b persistence、Task 19A2c lane/assembly、Task 29A two-worker HA、Task 19B External CMDB canary/gate、Task 29B final matrix 与所有真实资格执行继续 deferred。此任务不勾任何 Provider/Worker checkbox，全部保持 `NOT_STARTED/UNAVAILABLE/CLOSED`。

### Post-A2a exact-2 domain-validation corrective

**Batch:** sequential C0；Task 19A2a merge 后必须从最新 `main` 创建 fresh worktree，先完成本 corrective 的 fail-first pure behavior tests、受影响 unit/race、fresh G1、独立 P0/P1 review 与单独 PR/merge，之后 Task 19A2b 才可开始。它只消费已合并 A2a domain types/ABI，不读取 fixture、旧 dirty worktree或未合并 A2b 实现。

**Exact two files:**

- Modify: `internal/assetcatalog/validation.go`
- Create: `internal/assetcatalog/validation_test.go`

上述两文件是完整且唯一所有权。禁止修改 migration、schema/role admission、PostgreSQL Repository、Queue、HTTP/OpenAPI/Web、Worker、signer、production config 或任何 Provider package；发现需改这些 surface 时整批停止并返回契约复核。

**Pure validation contract:**

- `Source.Validate` 只消费现有 Source-local facts：三列 gate tuple all-null-or-all-present、UUID/lowercase-64-hex/finite-UTC expiry shape；exact `source.Kind=MANUAL + ProviderKind=MANUAL_V1` direct-`AVAILABLE` 始终 all-null，exact non-MANUAL + non-`MANUAL_V1` 的 `AVAILABLE|DEGRADED` 必须 all-present，mixed Source/Provider pair fail closed，其余 gate 状态必须 all-null。`Source` 不含 published `ProfileCode`，所以 exact published Profile/missing-row/drift 三元判别仍只属于 deferred PostgreSQL closure与 A2b composite loader；纯 receiver不得伪造该输入，也不读取 wall clock。
- `SourceRun.Validate` 强制非 `QUALIFICATION` Run 的 23 列全 `NULL`；`QUALIFICATION` 必须 zero Catalog/checkpoint/success projection、只使用 `QUALIFICATION_PROOF`，并逐 lifecycle 验证 queue immutable binding、WorkResult、cleanup `REVOKED` 后 receipt seal、terminal closure 的 nullability。cleanup 前 receipt time/key/signature/digest 与 HA tuple 必须全空；terminal `TWO_WORKER_HA` 要求 exact HA all-present/distinct，terminal `PROVIDER_CANARY` 要求 HA all-null；失败/cleanup uncertainty 不得伪造成功 receipt。
- Domain validation 只拒绝不可能 shape，不签名、不持久、不解释 current evaluator/receipt-chain，也不调用 `AdmitGate`。数据库 deferred closure 与 A2b current-time/CAS/runtime rechecks 仍是独立必需门。

**RED → GREEN:**

- [ ] RED：table-driven `Source.Validate` 覆盖 partial tuple、错误 UUID/digest/expiry、各 gate status、exact Source-local manual/non-MANUAL pair 与 mixed pair；并证明 receiver不声称已验证 published Profile。任一 fail-open 先失败。
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

上述 11 个 future files 是 Task 19A2b 的完整且唯一清单。它只给已合并 Task 19A/M1E/Task 27 Repository types 增加 sequential persistence/recheck，并定义只暴露 `Seal` 或 `Admit` 的两个 narrow mutation-executor interfaces；它不创建/读取 DSN或 pool，不创建第二 Repository、claim state machine、HTTP 或 production assembly。Task 19A2c 才以隔离 sealer/admitter DSN装配对应 executor。

**Consumes（全部已合并）:**

- Task 19A2a exact schema/domain/admission contracts、HA digest tuple、column ACL、两条 fixed SQL primitives与 sealer/admitter exact capability identities；ordinary application pool无两条 EXECUTE。
- Task 19A publication-closed Source mutation、M1E PageCommitter 与 Task 27 Queue/terminal receipt persistence；不得修改 Task 28A loop 或 Provider package。

**Produces:**

- Generic serializable `RequestQualification/AdmitGate` persistence、qualification-only Queue predicate、safe Source reads、expiry/CAS/drift/direct-SQL guards and Audit/Outbox closure。`RequestQualification` queues only the immutable evidence kind + scope/binding/profile/runtime/lab/prior tuple through the exact column-INSERT boundary；result、issued/expiry/key/signature/receipt and HA columns remain NULL until their required lifecycle points。WorkResult uses legacy lifecycle columns，database trigger derives protected `qualification_result_digest`。Before seal preparation，the application loader locks the Run、uses database time and calls existing raw `LeaseFence.Matches`，then returns only an opaque `SealAdmission` with unexported shared state、no external constructor、invalid zero value and rejected JSON/Text/Binary/log surfaces；forged/expired/destroyed fence cannot create it。The narrow sealer executor accepts only this opaque admission plus a typed signer callback；it owns the isolated transaction，queries its one `pg_catalog.transaction_timestamp()`、passes that exact fixed-six value to the callback，then calls the primitive。callback cannot receive raw transaction/pool/DSN/connector，and the function's exact issued-time + version/epoch CAS closes future-time and cross-transaction TOCTOU；raw fence/token never enters SQL、payload、log or capability connector。terminal persistence and open must call the two A2a primitives，不得以 direct protected-column DML替代。
- Ordinary `RequestSync` and data `Claim/Reclaim/Heartbeat/PageCommitter` continue to require `AVAILABLE` and, for qualification-required profiles, reload the same current unexpired gate-evidence tuple using database time；expiry/drift yields zero Run/Catalog mutation and effective closed admission before stored projection reconciliation。
- Exact server-generated HA Queue/run receipt closure：existing Claim/Reclaim/recovery/cleanup/terminal paths—not caller input—derive and persist domain-separated `HA_OWNER_CLAIM`、`HA_TAKEOVER_COMMITTED`、`HA_RESTART_RECOVERED`、`HA_SESSION_RECOVERED`、`HA_CLEANUP_CONFIRMED` and pre-terminal `HA_RESPONSE_LOSS_REPLAYED` digests。Worker/process digests may come only from Task 28C authenticated workload/startup context，never Queue command JSON、HTTP、script flags or arbitrary worker-name config。The response-loss fact must replay an exact persisted recovery/cleanup command receipt before finalization，avoiding any self-reference to the final HA receipt。The terminal qualification loader then reloads distinct worker/process digests、exact fence increment、Task 28B recovery receipt、cleanup proof and that pre-terminal replay receipt，recomputes `ha_fact_chain_digest` and seals all facts with the existing `TERMINAL_COMMITTED` closure；no API accepts a prebuilt HA fact set。

qualification finalization 与 `AdmitGate` 是两个不可合并的 serializable transactions。`RecordCleanup` 已先持久 `REVOKED`；前者由 sealer executor消费上述 opaque `SealAdmission` 与 signer callback，在自己 transaction内取得唯一 DB issued time并完成签名后调用 receipt-seal primitive，一次性写 receipt/HA、terminal Run、capacity/fence closure与 fixed `TERMINAL_COMMITTED` Audit，并以 Source pointer全 NULL、gate closed提交；seal不写 cleanup/Source/Outbox，也不替代 current public-key验签。若提交响应不确定，未封存重试必须新取 DB time重签，已封存只允许 exact旧 tuple零写 replay。`AdmitGate` 不信任 caller decision：ordinary read loader先取得由 immutable terminal Run/Revision与 expected Source version/gate revision标识的 safe snapshot；然后 admitter executor开启另一个 `SERIALIZABLE READ WRITE` transaction，在函数调用前立即通过 Task 19A2c 注入的 immutable registry/evaluator复验 installed Profile/runtime manifest、current signing key、signature、expiry、registry generation与 Provider-neutral decision。gate-admit primitive再按 target canary Run→receipt-ordered prior HA Runs→Source→published Revision锁序重载全部 durable structural facts，比较 Source version/gate revision CAS，从 canary派生 all-present pointer、`AVAILABLE`、`source.gate_revision=canary_run.gate_revision+1`与 fixed Audit/Outbox；它不接 decision/digest/expiry或 caller payload。terminal Run/Revision不可变性与 Source CAS把 preloaded snapshot绑定到此次 commit；任一 registry generation、snapshot、CAS、expiry或并发 drift整笔回滚。关闭/reference drift/expiry只以 ordinary Repository 的 Source version/gate revision CAS按 Source→Revision合法子序列更新允许的关闭态字段，由 trigger清 pointer且不等待 Run。

**RED → GREEN:**

- [ ] RED：`RequestQualification` 只写 immutable queue binding；任何 result/receipt/HA 预填、queue binding 后 mutation 或非 qualification path 携带 23-column tuple 均拒绝。
- [ ] RED：ordinary RequestSync、Claim/Reclaim/Heartbeat/PageCommitter 在 receipt expiry/drift crossing 后全部零写；exact current evidence 才继续，stored pointer reconciliation 同事务关闭 gate并清空 pointer。
- [ ] RED：HA owner/takeover/restart/recovery/cleanup/response-loss 任一 durable receipt 缺失、identity 不 distinct、fence 非 exact increment、changed replay 或 caller fact injection 时，qualification fact reload 与 terminal seal preparation 均拒绝。
- [ ] RED：forged、expired、destroyed 或 wrong-coordinate `LeaseFence` 不能产生 `SealAdmission`；opaque admission 不可由外部 package构造/复制到 JSON/Text/Binary/log，raw token/fence 不进入 sealer connector或 SQL。sealer executor必须在自己的 transaction取得唯一 DB issued time并只把该值交给 signer callback；callback看不到 transaction/connector，future/backdated output或 Run version/fence 漂移时 primitive零写拒绝，exact response-loss replay例外仍只读。
- [ ] RED：qualification finalization commit 后 pointer 仍 NULL/gate closed；seal-only、terminal-only或把 terminal seal 与 gate open 合并的 transaction均拒绝。普通 application/runtime调用两条 primitive、sealer调用 admit、admitter调用 seal均 `42501`。`AdmitGate` 缺 Provider evaluator、current validation、`TWO_WORKER_HA`、terminal `PROVIDER_CANARY`、`REVOKED` cleanup、signature、current registry generation或未过期窗口任一事实时零 mutation；成功时 pointer + `AVAILABLE` + exact run epoch + Audit + Outbox 同事务，并发 drift 只允许一方提交。
- [ ] RED：partial/cross-Scope/wrong-kind/nonterminal/expired/payload mismatch/错误 revision or binding/缺 HA pointer commit 全失败；protected direct DML按 A2a exact column ACL 返回 `42501`。测试不得用 migration-owner synthetic pointer + `AVAILABLE`、synthetic signature或直接调用 primitive绕过 Repository current verifier/evaluator。
- [ ] GREEN：只实现 existing Repository methods/predicates、exact receipt reload和两条 fixed primitive consumer；不新增 Worker loop、signer、HTTP handler 或 production config。

**G2 — required, no Skip:**

~~~bash
test -n "${AIOPS_TEST_POSTGRES_DSN:-}"
test -n "${AIOPS_TEST_POSTGRES_MIGRATION_DSN:-}"
test -n "${AIOPS_TEST_POSTGRES_APPLICATION_DSN:-}"
test -n "${AIOPS_TEST_POSTGRES_SOURCE_GATE_SEAL_DSN:-}"
test -n "${AIOPS_TEST_POSTGRES_SOURCE_GATE_ADMIT_DSN:-}"
go test -race ./internal/assetcatalog/postgres ./internal/discoveryqueue/postgres \
  -run 'SourceGatePersistence|QualificationFacts|AdmitGate|Expiry|Drift|ResponseLoss' -count=1
go vet ./internal/assetcatalog/postgres ./internal/discoveryqueue/postgres
git diff --check
~~~

G2 必须使用 PostgreSQL 18.4 TLS、真实 migration/application/sealer/admitter identities、serializable concurrency、response-loss replay、两条 primitive、session-user/cross-call与 direct-SQL negatives；positive seal/gate tests必须分别经 Repository + narrow sealer/admitter executor，以 test-only unreachable-from-production 的 immutable verifier/evaluator和真实测试公钥完成 current trust复验，不得由 migration-owner、synthetic signature、普通 application pool或直接 primitive调用合成 receipt/pointer。缺任一 DSN、共享 identity、Skip、memory repository 或绕过 Repository 不得 PASS。Task 19A2b 独立合并后只产生 persistence `BUILT_CLOSED`，不装配 Worker/API/signer，不产生真实 HA/canary receipt或运行时 `AVAILABLE`。

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
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Create: `cmd/discovery-worker/qualification.go`
- Create: `cmd/discovery-worker/qualification_test.go`
- Modify: `cmd/discovery-worker/config.go`
- Modify: `cmd/discovery-worker/config_test.go`
- Modify: `cmd/discovery-worker/production.go`
- Modify: `cmd/discovery-worker/production_test.go`

上述 23 个 files 是 Task 19A2c 的完整且唯一清单。它不修改 migration、schema/domain/PostgreSQL gate/qualification predicate files，不拥有 Task 29A metrics/HA verifier、Task 19B Provider evaluator/canary 或 Task 29B matrix/CI。

**Mandatory Task 28A seam preflight — fail closed:**

实现第一步必须在 Task 19A2c 的新窗口只读核对已合并 Task 28A exact files `internal/discoveryworker/worker.go`、`worker_test.go`、`claim_runtime.go`、`claim_runtime_test.go`。`internal/discoveryworker/qualification.go` 只能是该 stable Worker 的 thin execution-mode/outcome adapter：claim、Reserve/Open/Resolve、heartbeat、fence revalidation、panic/cancel、cleanup、Delay/Complete/Fail 与 response-loss replay 仍逐字走唯一 Task 28A Worker loop；qualification adapter 只选择 Task 19A2b predicate、zero-projection outcome sink 和 `QUALIFICATION_PROOF` terminal command。

若 merged seam 不能在不调用 PageCommitter 的前提下表达 qualification outcome，Task 19A2c 必须停止且不得编辑上述 23 文件。主管理另开一个最小 sequential C0 seam corrective，只允许修改 Task 28A 的这四个 exact files，独立新窗口、定向 RED/G2、单一 PR/merge，用一个 closed `VALIDATION|DATA|QUALIFICATION` mode + typed outcome sink 扩展同一 loop；它不得创建第二 Worker/runner、第二 claim/cleanup/terminal 实现或 Provider-specific branch。该 corrective 合并后重新启动 Task 19A2c；不能为赶进度在 `internal/discoveryqualification/runner.go` 或任何新 package 复制状态机，该文件明确禁止创建。

**Consumes（全部已合并）:**

- Task 19A2a schema/domain/pure contracts and Task 19A2b qualification predicate、durable fact loader、`SourceGateRepository`/`GateEvaluator` serializable persistence。
- Task 28A unique Worker/claim-runtime execution seam、Task 28B same-attempt authority、Task 28C immutable Provider registry/production binary/runtime manifest，以及 Task 18B neutral Provider descriptor。
- No Task 29A receipt or Provider-specific canary；Task 19A2c only makes their later production entry possible。

**Produces:**

- A thin qualification mode wired into the one Task 28A fenced execution loop。It consumes exact `ACTIVE + PUBLISHED + UNAVAILABLE` claim、server-resolved opaque lab binding and Task 28C registry，executes bounded Provider read/protocol/DLP through the same Reserve/Open/Resolve/heartbeat/cleanup/terminal sequence，then calls the sole Task 19A2c zero-projection outcome sink。It never calls PageCommitter、writes Observation/Asset/Relationship、runs missing/stale、or changes Source checkpoint/`last_success`/`last_complete_snapshot`。
- Single-OpenAPI fixed operations `POST /api/v1/workspaces/{workspace_id}/asset-sources/{source_id}/revisions/{revision}:qualify` and `POST .../{revision}:admit-gate`，served only by a separate mTLS workload qualification listener—not the OIDC browser router and never `effective_actions`。Closed body contains only evidence kind、expected Source/version/gate/revision/prior-receipt digests；Idempotency-Key remains a header，and server assembly resolves the opaque lab binding。Endpoint、CredentialReference/value、credential、raw Provider payload/cursor and arbitrary Header/Body are rejected。
- The sole generic production assembly for the Task 19A2b repository、immutable `EvidenceVerifier`/public-key/runtime-manifest registry、qualification listener/mode and `QualificationOutcomeSink`/signer。Control Plane loads only `AIOPS_SOURCE_GATE_ADMIT_DATABASE_URL` into a fixed-role admitted admitter executor；Discovery Worker follows the existing secret-file pattern and loads only `AIOPS_DISCOVERY_SOURCE_GATE_SEAL_DSN_FILE` into a fixed-role admitted sealer executor；both empty names were reserved by the earlier capability harness but are not consumed before A2c。Constructors reject missing/equal-to-application/shared DSN、wrong `session_user`、role/ACL drift or connector crossing，never print DSN，and never expose raw pool outside typed executor。The sink accepts only terminal Run coordinates/fence/evidence kind，uses the complete Task 19A2b durable fact loader to obtain opaque `SealAdmission`，selects one immutable registered verifier，recomputes result/fact-chain digests，then passes the sole signer callback to the sealer executor；no caller may submit issued time、HA facts、signature、receipt digest or decision。The executor begins the final transaction、obtains its exact DB issued time and invokes the callback to build the 15-frame receipt/signature；the callback sets expiry to `min(issued_at + closed-kind 24-hour TTL, current signing-key not_after, opaque lab-binding expiry, exact prior-receipt expiry when present)`。missing/expired bounds、future/backdated issued substitution or longer output rejects，so a canary/Source pointer cannot outlive its HA prerequisite。It commits receipt + terminal/`TERMINAL_COMMITTED` while leaving the Source pointer NULL/gate closed。`cmd/discovery-worker/qualification.go` owns symlink-safe signer loading through existing workload-secret bootstrap and exposes the later registration seam used by Task 29A；Control Plane receives public keys/digests only。The same immutable current registry is injected into A2b `AdmitGate` for cryptographic signature、installed Profile/runtime/key/expiry rechecks immediately before the admitter primitive；`000015` structural closure cannot replace it。Task 19B may later modify only `cmd/control-plane/source_gate.go` sequentially to register neutral CMDB gate evaluator；it cannot alter persistence or execution loop。

**RED → GREEN:**

- [ ] RED：architecture test proves `internal/discoveryworker/qualification.go` contains no independent claim/Reserve/Open/Resolve/heartbeat/cleanup/Delay/Complete/Fail loop and `internal/discoveryqualification/runner.go` does not exist；all such calls originate from the one Task 28A Worker path。
- [ ] RED：CMDB publication 后 ordinary Queue claim/`RequestSync` 因 `UNAVAILABLE` 零写失败；only mTLS qualification operation may create/execute `QUALIFICATION`。OIDC bearer、browser router、unknown evidence kind、caller lab binding/endpoint/header/payload all reject。
- [ ] RED：outcome sink with missing/duplicate verifier、caller-supplied HA fact、fact reload drift、signer failure、changed response-loss replay or Task 28A fence/cleanup bypass produces zero receipt；qualification success leaves Catalog/checkpoint/success pointers unchanged。
- [ ] RED：signer callback必须消费 sealer transaction提供的 exact fixed-six DB issued time，且 expiry 不等于上述 four-way minimum（无 prior 时 three-way）、任一 required bound 缺失/已过期、callback替换 future/backdated issued、canary晚于 prior HA expiry或 receipt TTL 超过 24 hours时零 seal；即使 canary 在 admit 时不足 24 小时，oversize stored TTL 也绝不进入 pointer。
- [ ] RED：production constructors fail closed on missing Task 19A2b repository、Task 28A mode seam、Task 28B authority、Task 28C registry/runtime manifest、mTLS identity、verifier registry、signing-key manifest、sealer/admitter DSN或 exact fixed-role admission；equal/shared/crossed connector与 raw pool exposure均拒绝，no test fake is production reachable。
- [ ] GREEN：only thin adapter/API/immutable verifier-registry/outcome-sink/signer assembly is added on top of merged persistence and unique Worker loop；browser action surface and ordinary data predicate remain unchanged。

**G2 — required, no Skip:**

~~~bash
test -n "${AIOPS_TEST_POSTGRES_DSN:-}"
test -n "${AIOPS_TEST_POSTGRES_MIGRATION_DSN:-}"
test -n "${AIOPS_TEST_POSTGRES_APPLICATION_DSN:-}"
test -n "${AIOPS_TEST_POSTGRES_SOURCE_GATE_SEAL_DSN:-}"
test -n "${AIOPS_TEST_POSTGRES_SOURCE_GATE_ADMIT_DSN:-}"
go test -race ./internal/assetcatalog ./internal/discoveryworker ./internal/config \
  ./internal/httpapi ./cmd/control-plane ./cmd/discovery-worker \
  -run 'Qualification|GateEvidence|AdmitGate|WorkerLoop|ImportBoundary' -count=1
go test ./api/openapi -run 'Qualification|SourceGate' -count=1
corepack pnpm@10.34.0 --dir web generate:api:check
go vet ./internal/discoveryworker ./internal/httpapi ./cmd/control-plane ./cmd/discovery-worker
git diff --check
~~~

G2 必须使用 PostgreSQL 18.4 TLS、真实 Task 19A2b persistence、Task 28A/28B/28C production dependencies、sealer/admitter distinct fixed-role connectors 和 both constructors；缺任一 DSN、identity admission、Skip、memory repository、test-only handler、second runner/loop、mutable/duplicate verifier registry 或 missing signing-key manifest 不得 PASS。Task 19A2c 以自己的单一精确 commit/PR 合并后最多为 `BUILT_CLOSED`，不产生 Provider HA/canary receipt 或 `AVAILABLE`。

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
