# External CMDB Governed Discovery Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 实现首个非通用 HTTP 代理的 `EXTERNAL_CMDB` 生产 Provider，通过固定 CMDB Catalog v1 协议增量发现资产/关系，保留字段来源、软删除/恢复、Scope 和独立可用门。

**Architecture:** Source Revision 只选择 server-installed `CMDB_CATALOG_V1` profile 和 opaque Credential/Trust/Network references。Discovery Worker 在受信任配置中解析基础地址，使用固定 `/v1/capabilities`、`/v1/assets`、`/v1/relations` 读协议；上游页面被规范化、DLP、限额后才进入 fenced Reconciler。不提供 URL template、任意 Header/Body、字段表达式或通用 CMDB 查询。

**Tech Stack:** Go 1.26.5、`net/http`、TLS 1.3/mTLS、OAuth2 client assertion via opaque reference、OpenAPI 3.1 CMDB Catalog v1、PostgreSQL 18.4。

## Global Constraints

- 前置完成 [05-source-ingestion-csv-api.md](./05-source-ingestion-csv-api.md)；只消费其 `discoverysource.Provider`、Source Revision、Run/Fence/Checkpoint 契约。
- 每个 Task 严格执行 `Red → Green → Refactor`：先运行并保留预期失败，再做最小生产实现，随后消除重复、复跑指定验证并按 Task 提交；不得跳过失败或弱化断言。
- `EXTERNAL_CMDB` 不是通用 REST connector；只有 `CMDB_CATALOG_V1` 固定路径、方法、query 参数和响应 Schema。其他厂商必须新增独立 profile/adapter/test/gate。
- 上游凭据必须是最小只读权限；DB/API/UI/Run payload 只保存 `CredentialReferenceID`，原始 Token、client secret、CA、endpoint 只能存在 Worker 进程内并在本次 lease 结束时清理。
- Checkpoint 是 `(snapshot_epoch,updated_at,external_id,asset_cursor,relation_cursor)` 的加密投影；audit 只留 hash/version。
- 每页最多 500 assets、2,000 relations、4 MiB、15 秒；每来源 5 req/s burst 10，全 Workspace 20 req/s，`429/503` 尊重最大 60 秒 `Retry-After` 并持久化 backpressure。
- 只有完整 snapshot 结束或有签名 tombstone 才标记 `STALE`；断页、超时、部分成功不进行 missing detection。
- CMDB 不得覆盖 Owner、Service、Criticality、DataClassification 或人工标签；跨来源候选只创建 Conflict。
- 真实协议 E2E 使用 TLS socket 和严格 wire fixture；上线前还必须通过非生产 CMDB endpoint canary，不能仅凭 mock 开门。
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
	if !errors.Is(err, ErrAuthorityMismatch) || proof.Available {
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
Capability: protocol_version, authority_id, snapshot_epoch, max_page_size,
            supports_delta, supports_tombstone, server_time
Asset: external_id, type_code, display_name, source_revision, updated_at,
       deleted, tombstone_reason, attributes{allow-listed code:string}
Relation: external_id, from_external_id, to_external_id, type_code,
          source_revision, updated_at, deleted
Page: items, next_cursor, snapshot_epoch, complete
~~~

No response may include secrets, arbitrary nested objects, executable text, HTML, endpoint, credential or opaque vendor payload. `Validate` performs TLS/SNI/CA and optional client-certificate verification, authority ID equality, clock skew ≤60s, protocol equality, read-only permission exactness, one max-limit asset probe, schema/DLP test and credential cleanup. Proof exposes booleans/stable codes/counts/digests only.

- [ ] **Step 3: Implement strict client and normalization**

Use a dedicated `http.Client` with TLS 1.3 minimum, no environment proxy, redirect rejection, 5s connect/15s request deadlines, max 64 KiB headers and exact content type. Decode with `DisallowUnknownFields`, limit body before decode and reject duplicate JSON keys. OAuth/mTLS material comes from `BoundRuntime`; logs receive only operation/result/latency/Trace ID.

Map CMDB type codes through a closed table to Asset Kind; unknown types become rejected items, never guessed. Each field gets provenance `(field_code,CMDB_V1_*_FIELD,SOURCE,source_revision,observed_at,confidence=100)`. Map relation types through the approved relationship enum. A deleted record yields only tombstone ID/revision/reason; it never physically deletes history.

- [ ] **Step 4: Verify and commit**

Run:

~~~bash
gofmt -w internal/assetsource/externalcmdb
go test -race ./internal/assetsource/externalcmdb -count=1
go test ./api/openapi -run ExternalCMDB -count=1
~~~

Expected: PASS for TLS identity, read-only capability, closed Schema, size/time limits, DLP, unknown-type rejection, tombstone and forbidden request surface.

~~~bash
git add api/openapi/external-cmdb-catalog-v1.yaml internal/assetsource/externalcmdb
git commit -m "feat(assetdiscovery): add fixed external cmdb provider"
~~~

### Task 18: Incremental asset/relation checkpoint, provenance, deletion, and recovery

**Files:**
- Create: `internal/assetsource/externalcmdb/discover.go`
- Create: `internal/assetsource/externalcmdb/discover_test.go`
- Create: `internal/assetsource/externalcmdb/protocol_integration_test.go`
- Modify: `internal/assetcatalog/postgres/discovery_integration_test.go`
- Create: `testdata/asset-source/external-cmdb/capabilities.json`
- Create: `testdata/asset-source/external-cmdb/assets-page-1.json`
- Create: `testdata/asset-source/external-cmdb/assets-page-2.json`
- Create: `testdata/asset-source/external-cmdb/relations.json`

**Interfaces:**
- Consumes: sealed checkpoint and exact run fence; returns one bounded `discoverysource.Page` at a time.
- Produces cursor order `(updated_at,external_id)` separately for assets/relations plus immutable `snapshot_epoch`.
- Produces only `assetdiscovery.NormalizedItem/ObservedRelation`; repository remains the sole projection writer.

- [ ] **Step 1: Write failing pagination, stale-fence, and lifecycle tests**

~~~go
func TestDiscoverResumesAssetsThenRelationsAtExactCheckpoint(t *testing.T) {
	server := newPagedCatalogServer(t, twoAssetPagesAndRelations())
	provider := newProviderForServer(t, server, expectedAuthority(server.AuthorityID()))
	first, err := provider.Discover(context.Background(), server.Runtime(), requestAt(emptyCheckpoint()))
	if err != nil || first.Complete || len(first.Items) != 500 {
		t.Fatalf("first = (%#v, %v)", first, err)
	}
	second, err := provider.Discover(context.Background(), server.Runtime(), requestAt(first.NextCheckpoint))
	if err != nil || second.NextCheckpoint.AssetCursor == first.NextCheckpoint.AssetCursor {
		t.Fatalf("second = (%#v, %v)", second, err)
	}
}

func TestPartialCMDBRunNeverMarksMissingAssetStale(t *testing.T) {
	result := runCMDBUntilInjectedTimeout(t)
	if result.Missing != 0 || result.Stale != 0 || result.Status != "FAILED" {
		t.Fatalf("partial result = %#v", result)
	}
}
~~~

Run: `go test ./internal/assetsource/externalcmdb ./internal/assetcatalog/postgres -run CMDB -count=1`

Expected: FAIL because delta paging/checkpoint integration is missing.

- [ ] **Step 2: Implement page state machine and atomic checkpoint rules**

The phase order is `CAPABILITIES→ASSETS→RELATIONS→COMPLETE`. Every request carries the server-returned cursor only from process-local decrypted checkpoint; no caller can change it. Each response must keep the same authority/snapshot epoch and nondecreasing `(updated_at,external_id)`. The Worker calls Reconciler with current fence, before/after cursor hashes, page sequence and page digest; Observation/projection/checkpoint advance commit atomically.

On `429/503`, parse only integer/date `Retry-After`, cap at 60s and return `Page.RetryAfter`; queue persists `not_before` and releases the lease without advancing checkpoint. On transport ambiguity, schema drift, snapshot epoch change, clock regression or stale fence, stop without missing detection. Full completion may mark absent source-owned assets stale. Tombstone has the same effect for one asset. Reappearance appends Observation and recovery event but remains stale pending later connection validation.

- [ ] **Step 3: Run real TLS protocol integration and concurrency tests**

Use `httptest.NewUnstartedServer`, install a real CA/server/client certificate chain, require HTTP/2 or HTTP/1.1 TLS transport, serve raw fixture bytes and assert actual request path/query/header allow-list. Run two Workers against one PostgreSQL source: only the current fence can apply page 2; the stale Worker must receive `ErrStaleSourceFence` and create no Observation/checkpoint/audit.

Run:

~~~bash
go test -race ./internal/assetsource/externalcmdb -run 'ProtocolIntegration|Discover' -count=1
TEST_DATABASE_URL="$TEST_DATABASE_URL" \
  go test -race ./internal/assetcatalog/postgres -run CMDBDiscoveryIntegration -count=1
~~~

Expected: PASS for resume, dedupe, provenance, relation ordering, explicit/implicit deletion, recovery, 429 backpressure, crash/reclaim and stale-fence rejection.

- [ ] **Step 4: Commit**

~~~bash
git add internal/assetsource/externalcmdb testdata/asset-source/external-cmdb \
  internal/assetcatalog/postgres/discovery_integration_test.go
git commit -m "feat(assetdiscovery): reconcile incremental cmdb facts"
~~~

### Task 19: Per-source availability gate, real staging canary, and operating proof

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

`AVAILABLE` requires current source/revision/binding digests, successful identity/trust/credential-cleanup/fixed-probe validation, contract+negative+DLP tests, real TLS protocol receipt, two-replica fence failover receipt, rate/backpressure receipt and a non-production external CMDB canary less than 24 hours old. Any credential/trust/network/profile/revision change, repeated auth/schema failures, checkpoint ambiguity, cleanup uncertainty or protocol drift closes the gate before another claim. A plain upstream outage sets `DEGRADED` and applies backoff; it never silently switches endpoint.

- [ ] **Step 3: Execute staging canary and UI/E2E verification**

The script validates profile and source IDs, invokes Control Plane validate/publish/sync APIs with recent OIDC obtained by the approved operator flow, waits for terminal run, verifies counts/digests/provenance/tombstone/recovery and downloads only the signed safe receipt. It must not print environment values or enable shell tracing.

Run:

~~~bash
go test -race ./internal/assetsource/externalcmdb -count=1
scripts/verify-external-cmdb-source.sh
corepack pnpm@10.34.0 --dir web test:e2e -- --grep "external cmdb source"
~~~

Expected: positive staging canary and negative wrong-authority/bad-CA/bad-signature/rate-limit/schema/DLP/fence cases PASS; UI displays independent Source/Revision/Gate/checkpoint states and no endpoint/credential/raw payload.

- [ ] **Step 4: Commit**

~~~bash
git add internal/assetsource/externalcmdb/gate.go internal/assetsource/externalcmdb/gate_test.go \
  scripts/verify-external-cmdb-source.sh docs/operations/asset-sources/external-cmdb.md \
  web/e2e/source-external-cmdb.spec.ts web/src/features/asset-sources/AssetSourcesPage.tsx \
  web/src/features/asset-sources/SourceRunTimeline.tsx
git commit -m "feat(assetdiscovery): gate external cmdb sources"
~~~
