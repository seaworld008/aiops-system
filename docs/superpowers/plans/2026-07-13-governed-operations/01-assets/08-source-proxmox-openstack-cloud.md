# Proxmox, OpenStack, and Cloud Compute Discovery Providers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 Proxmox VE、OpenStack Nova、AWS EC2、Azure Compute 和 Google Compute Engine 建立五个彼此隔离的真实计算资产 Provider，覆盖身份验证、增量分页/checkpoint、HA fence、限流/背压、provenance、软删除/恢复、DLP 和逐 Provider 可用门。

**Architecture:** `PROXMOX`、`OPENSTACK` 和 `CLOUD_PROVIDER` SourceKind 不共享通用 endpoint/payload 适配器。每个 Provider 拥有独立 Source Profile、SDK wrapper、身份 probe、最小只读权限、字段/relationship 映射、checkpoint codec 和 gate key；公共的 Source Revision、Worker Lease/Fence、Reconciler 和安全证据接口来自前序包。一个 Provider `AVAILABLE` 不会打开其他 Provider。

**Tech Stack:** Go 1.26.5、`github.com/luthermonson/go-proxmox v0.8.0`、`github.com/gophercloud/gophercloud/v2 v2.13.0`、AWS SDK Go v2 core `v1.42.1`/config `v1.32.29`/EC2 `v1.316.0`/STS `v1.44.0`、Azure `azidentity v1.14.0`/`armcompute/v7 v7.3.0`、`cloud.google.com/go/compute v1.64.0`、PostgreSQL 18.4。

## Global Constraints

- 前置完成 [05-source-ingestion-csv-api.md](./05-source-ingestion-csv-api.md)；不改写 Source Revision/Run/Fence/Checkpoint 契约。
- 每个 Task 严格执行 `Red → Green → Refactor`：先运行并保留预期失败，再做最小生产实现，随后消除重复、复跑指定验证并按 Task 提交；不得跳过失败或弱化断言。
- 只能从 server-installed profile 解析 provider endpoint/region/cloud；API、UI、model、Task 和 Run payload 不能提交 URL、region override、proxy、Header、Body 或 SDK option。
- 凭据只以 opaque reference 存储：Proxmox API Token、OpenStack Application Credential、AWS AssumeRole/WebIdentity、Azure Workload Identity、GCP Workload Identity Federation。不支持长期云 Access Key 、密码表单或个人用户凭据作为新生产来源。
- 每个 Runtime 只暴露 adapter 所需的闭合 GET/List/Describe 方法；终端/VNC/Console、Guest Exec、power、resize、migration、tag mutation、security-group/network/storage mutation 不得进入接口或调用图。
- 资产 OS 类型仅由受信任闭合 Provider 字段映射；无确定信号的 VM 使用 `CLOUD_RESOURCE` + 明确 provider subtype，不按名称/image text 猜测。
- 标签/metadata 只投影 server-allow-listed key 并通过 DLP；user-data、cloud-init、password、SSH key、custom-data、console output、IP/MAC、endpoint、raw fault/message 全部排除。
- 每个 Provider 的分页 token/marker 加密且绑定 account/project/subscription/cluster、region 和 exact Source definition revision/digests；audit/UI 只保存 digest/version/age。持久 checkpoint AAD 不绑定 fence，但每次解封、Provider 调用和页提交都必须重新验证 exact live fence，使 reclaim 可恢复而 stale worker 不能提交。
- 删除仅由显式 Provider tombstone 或完整 inventory snapshot 缺失产生 `STALE`；部分页、限流、权限缺失、某 region 失败不做 missing detection。
- 这五个 Profile 均为 `SINGLE_ENVIRONMENT`: Proxmox cluster、OpenStack project、AWS account、Azure subscription 或 GCP project 的 immutable authority binding each resolves exactly one same-Workspace Environment; regions/zones are source fields, never caller-selected Catalog Environments.
- 五个 Adapter 都固定使用 `CHECKPOINT_SEQUENCE`，`OrderSequence` 等于本页 accepted next checkpoint version；各自的 `ProviderVersionSHA256` 必须逐字采用下述 domain-separated `SHA256(FramedTupleV1(...))` 公式与 Pack 01 字节编码，字段不得重排、拼接或省略，命名 digest 字段以解码后的 32 raw bytes 入帧。Provider 永不注入 Source revision 或 Catalog time。
- 对五个 Adapter，一次更晚 Run 的同内容观察仍必须追加新的 Observation/chain 并推进它实际接受的 checkpoint；`provider_fact_sha256` 不变只抑制 business projection/Type Detail 写入，不能抑制 Observation、审计或 checkpoint 证据。
- CI 协议 fixture 必须经过真实 TLS/HTTP/SDK serialization；每个 Provider 生产开门还必须有它自己的非生产账户/集群 canary、负向证据和 HA receipt。
- 完成后进入 [09-discovery-worker-ha-e2e.md](./09-discovery-worker-ha-e2e.md)。

---

### Task 23: Proxmox VE read-only cluster and VM inventory provider

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`
- Create: `internal/assetsource/proxmox/profile.go`
- Create: `internal/assetsource/proxmox/client.go`
- Create: `internal/assetsource/proxmox/validate.go`
- Create: `internal/assetsource/proxmox/discover.go`
- Create: `internal/assetsource/proxmox/normalize.go`
- Create: `internal/assetsource/proxmox/provider_test.go`
- Create: `internal/assetsource/proxmox/protocol_integration_test.go`

**Interfaces:**
- Produces `PROXMOX/PROXMOX_VE_V1`; wrapper methods are only `Version`, `ClusterStatus`, `ListNodes`, `ListClusterResources`.
- Checkpoint is `{cluster_identity_digest,cluster_generation,resource_digest,completed_at}`; every run is a bounded full snapshot. `ProviderVersionSHA256=SHA256(FramedTupleV1("proxmox-object-version.v1",cluster_identity_digest,cluster_generation,resource_digest,external_id))` exactly, using the common byte encoding above.
- Maps node to `BARE_METAL_HOST`, QEMU/LXC to `CLOUD_RESOURCE` with subtype, and emits `RUNS_ON/CONTAINS` only as top-level `Page.Relations`. Each relation uses the accepted checkpoint sequence and `ProviderVersionSHA256=SHA256(FramedTupleV1("proxmox-relation-version.v1",cluster_identity_digest,cluster_generation,resource_digest,source_external_id,target_external_id,relationship_type))`.

- [ ] **Step 1: Write failing identity, read-only surface, provenance, and tombstone tests**

~~~go
func TestProxmoxAdapterExposesOnlyInventoryReads(t *testing.T) {
	typeOfClient := reflect.TypeOf((*InventoryClient)(nil)).Elem()
	want := map[string]bool{"Version": true, "ClusterStatus": true, "ListNodes": true, "ListClusterResources": true}
	for index := 0; index < typeOfClient.NumMethod(); index++ {
		delete(want, typeOfClient.Method(index).Name)
	}
	if len(want) != 0 || typeOfClient.NumMethod() != 4 {
		t.Fatalf("inventory client surface mismatch: %#v", want)
	}
}

func TestProxmoxIncompleteClusterResponseCannotMarkVMStale(t *testing.T) {
	result := runWithNodeFailure(t)
	if result.CompleteSnapshot || result.Stale != 0 || result.GateReason != "PROXMOX_PARTIAL_CLUSTER" {
		t.Fatalf("result = %#v", result)
	}
}
~~~

Run: `go test ./internal/assetsource/proxmox -count=1`

Expected: FAIL because Proxmox provider is absent.

- [ ] **Step 2: Implement exact validation and bounded inventory**

Pin `go-proxmox v0.8.0`, but wrap it behind the four-method interface and disable its generic retry/mutation/terminal surfaces. Runtime uses pinned CA/SNI, API Token reference, no environment proxy and hard timeouts. Validation checks `/version`, stable cluster identity/quorum, token read privilege and a one-item resource probe; proof binds cluster identity, TLS peer, role digest, definition and credential cleanup.

Normalize only node ID/status/capacity and QEMU/LXC ID/name/status/template/capacity/node relation. Exclude config, cloud-init, description, tags outside allow-list, network/disk secrets, VNC/term data and errors. Field provenance uses closed `PROXMOX_V1_*` codes. Sort full inventory and compute digest. An unchanged later Run still emits every membership item and appends an Observation/chain while advancing checkpoint; it suppresses only business projection/Type Detail changes. A rejection-free complete snapshot performs soft-missing; reappearance stays stale pending revalidation.

Rate limits: 2 concurrent calls/source, 4 req/s burst 8, 5,000 resources/run, 8 MiB and 30s/call. `429/502/503` returns persisted retry-after without automatic SDK mutation retry.

- [ ] **Step 3: Test real HTTPS wire, fence, and commit**

Use a TLS server that enforces exact `/api2/json/version`, `/cluster/status`, `/nodes`, `/cluster/resources?type=vm` requests and authenticates a synthetic API token. Verify wrong cluster/CA/token scope, extra fields, DLP, oversized inventory, partial cluster, unchanged digest, missing/recovery, crash/reclaim and stale fence.

Run: `go test -race ./internal/assetsource/proxmox -run 'ProtocolIntegration|Provider' -count=1`

Expected: actual HTTPS serialization passes and no unsafe field/method appears.

~~~bash
git add go.mod go.sum internal/assetsource/proxmox
git commit -m "feat(assetdiscovery): add proxmox inventory provider"
~~~

### Task 24: OpenStack Keystone/Nova scoped compute inventory provider

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`
- Create: `internal/assetsource/openstack/profile.go`
- Create: `internal/assetsource/openstack/client.go`
- Create: `internal/assetsource/openstack/validate.go`
- Create: `internal/assetsource/openstack/discover.go`
- Create: `internal/assetsource/openstack/normalize.go`
- Create: `internal/assetsource/openstack/provider_test.go`
- Create: `internal/assetsource/openstack/protocol_integration_test.go`

**Interfaces:**
- Produces `OPENSTACK/OPENSTACK_NOVA_V2_1` with pinned Nova microversion `2.79` and exact project/region identity.
- Wrapper methods are `AuthenticateApplicationCredential`, `GetProject`, `ListServersDetail`; no all-project, hypervisor-admin or mutation method.
- Checkpoint is `{cloud_identity_digest,project_id,region,microversion,changes_since,marker,full_snapshot_epoch}`.
- `ProviderVersionSHA256=SHA256(FramedTupleV1("openstack-object-version.v1",project_id,region,microversion,updated,server_id,deleted))` exactly, using the common byte encoding above; Catalog order remains the accepted checkpoint sequence.

- [ ] **Step 1: Write failing project identity, pagination, deletion, and admin-surface tests**

~~~go
func TestOpenStackValidationRejectsCatalogProjectMismatch(t *testing.T) {
	cloud := newOpenStackProtocolServer(t, project("project-b"))
	provider := newOpenStackProvider(t, expectedProject("project-a"))
	proof, err := provider.Validate(context.Background(), cloud.Runtime(), validationRequest())
	if !errors.Is(err, ErrProjectIdentityMismatch) || proof.Available {
		t.Fatalf("Validate = (%#v, %v)", proof, err)
	}
}

func TestNovaPaginationNeverUsesAllTenants(t *testing.T) {
	requests := discoverNovaRequests(t)
	for _, request := range requests {
		if request.Query().Get("all_tenants") != "" {
			t.Fatal("all_tenants escaped project scope")
		}
	}
}
~~~

Run: `go test ./internal/assetsource/openstack -count=1`

Expected: FAIL because OpenStack provider is absent.

- [ ] **Step 2: Implement fixed Keystone and Nova read flow**

Pin `gophercloud/v2 v2.13.0`. Authenticate only with an opaque Application Credential reference; derive Keystone cloud identity, project and Nova endpoint from the trusted service catalog, then compare exact expected IDs/region. Validation lists one server with microversion 2.79, verifies read-only role and token cleanup/expiry. Never return token/catalog endpoint to Run or logs.

Use `changes-since`, `deleted=true`, `marker`, `limit=500` for delta pages where supported, plus scheduled complete snapshots for authoritative absence. Require stable project/region/microversion and monotonic `(updated,server_id)`. Map server ID/name/status/flavor-code/image-ID-safe-code/availability-zone to source fields; exclude addresses, security groups, fault body, user data, metadata except allow-listed safe keys and attached credential hints. Unknown OS remains `CLOUD_RESOURCE`. Deleted server emits tombstone; partial region does not mark missing.

Rate limits: 2 calls/source, 5 req/s burst 10, 10,000 servers/snapshot, 8 MiB/page, max 30s. Respect `Retry-After` only through the common closed `Delay{Reason: PROVIDER_RETRY_AFTER}` outcome capped at 60 seconds；by type it carries no items/relations/checkpoint/final flags. Persist backpressure only after attempt cleanup and stop on catalog/schema/token ambiguity.

- [ ] **Step 3: Verify real Keystone/Nova HTTP and commit**

Run a TLS protocol server with real Keystone auth JSON and Nova pagination/microversion headers. Prove valid pages, marker resume, delta delete/recovery, bad CA/project/region/microversion, admin scope, DLP, 429, token expiry, checkpoint tamper and stale fence.

Run: `go test -race ./internal/assetsource/openstack -run 'ProtocolIntegration|Provider' -count=1`

Expected: all positive/negative protocol tests PASS with no cross-project asset.

~~~bash
git add go.mod go.sum internal/assetsource/openstack
git commit -m "feat(assetdiscovery): add openstack compute provider"
~~~

### Task 25: Separate AWS, Azure, and GCP compute inventory adapters

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`
- Create: `internal/assetsource/cloud/provider.go`
- Create: `internal/assetsource/cloud/common.go`
- Create: `internal/assetsource/cloud/aws/profile.go`
- Create: `internal/assetsource/cloud/aws/provider.go`
- Create: `internal/assetsource/cloud/aws/provider_test.go`
- Create: `internal/assetsource/cloud/azure/profile.go`
- Create: `internal/assetsource/cloud/azure/provider.go`
- Create: `internal/assetsource/cloud/azure/provider_test.go`
- Create: `internal/assetsource/cloud/gcp/profile.go`
- Create: `internal/assetsource/cloud/gcp/provider.go`
- Create: `internal/assetsource/cloud/gcp/provider_test.go`
- Create: `internal/assetsource/cloud/protocol_integration_test.go`

**Interfaces:**
- Produces three distinct adapters/gates: `CLOUD_PROVIDER/AWS_EC2_V1`, `CLOUD_PROVIDER/AZURE_COMPUTE_V1`, `CLOUD_PROVIDER/GCP_COMPUTE_V1`.
- AWS identity is STS account+role ARN digest; Azure identity is tenant+subscription+managed-identity object digest; GCP identity is organization/project+workload-pool subject digest.
- Each wrapper exposes only identity probe and paged instance list; common code handles normalized budgets/provenance only, never credentials/endpoints/SDK options.

- [ ] **Step 1: Write failing cross-cloud identity and independent-gate tests**

~~~go
func TestCloudProvidersRejectAuthorityMismatchIndependently(t *testing.T) {
	tests := []struct {
		name string
		provider discoverysource.Provider
		runtime discoverysource.BoundRuntime
	}{
		{"aws", awsProviderExpecting("111122223333"), awsRuntimeFor("999900001111")},
		{"azure", azureProviderExpecting("sub-a"), azureRuntimeFor("sub-b")},
		{"gcp", gcpProviderExpecting("project-a"), gcpRuntimeFor("project-b")},
	}
	for _, test := range tests {
		proof, err := test.provider.Validate(context.Background(), test.runtime, validationRequest())
		if err == nil || proof.Available {
			t.Errorf("%s validation escaped authority: %#v", test.name, proof)
		}
	}
}
~~~

Run: `go test ./internal/assetsource/cloud/... -count=1`

Expected: FAIL because cloud adapters are absent.

- [ ] **Step 2: Pin SDKs and implement identity/least-privilege validation**

Pin exact modules from Tech Stack. AWS uses workload identity/AssumeRole and `GetCallerIdentity` plus `DescribeInstances` with server-owned regions; no static access-key profile. Azure uses workload identity, exact tenant/subscription and `VirtualMachinesClient` pagers; GCP uses Workload Identity Federation, exact project and `InstancesClient.AggregatedList`. Dedicated transports reject environment proxy/redirect/custom endpoint unless the installed Source Profile explicitly represents an approved sovereign-cloud profile.

Validation binds authority identity, region-set digest, workload subject, SDK/API version, read permission probe, credential TTL/cleanup and DLP result. Over-privileged identities do not gain new methods; missing read permission closes only that Provider/source.

- [ ] **Step 3: Implement paged checkpoints, provenance, and soft lifecycle**

AWS checkpoint `{account,region_index,next_token,snapshot_epoch}`; Azure `{tenant,subscription,location_index,next_link_token,snapshot_epoch}`; GCP `{project,aggregated_page_token,snapshot_epoch}`. Tokens are sealed under the common typed `CheckpointAAD`; fence is enforced at decrypt/use/commit boundaries rather than embedded in persistent AAD. Provider-version digests are exactly `SHA256(FramedTupleV1("aws-ec2-object-version.v1",account,region,instance_id,normalized_document_sha256-or-NULL,tombstone))`, `SHA256(FramedTupleV1("azure-compute-object-version.v1",tenant,subscription,location,resource_id,normalized_document_sha256-or-NULL,tombstone))`, and `SHA256(FramedTupleV1("gcp-compute-object-version.v1",project,zone,instance_id,normalized_document_sha256-or-NULL,tombstone))`, using the common byte encoding above; no missing upstream version is guessed. Only completion across every server-owned region/location marks a snapshot complete. Delta APIs are not invented where the provider offers only list pagination; periodic complete snapshots plus per-page checkpoint/digest provide resumability. Unchanged later Runs still append Observation/chain and suppress only business projection/Type Detail changes.

Normalize provider instance ID, safe name, lifecycle/power state, machine/flavor code, zone/region code, CPU/memory capacity and allow-listed governance-neutral tags. Network addresses/MAC, IAM profile internals, user/custom data, disks' encryption key refs, startup script, console output and provider error body are excluded. Every field gets `AWS_EC2_V1_*`, `AZURE_COMPUTE_V1_*` or `GCP_COMPUTE_V1_*` provenance. Missing instance after complete snapshot becomes stale; reappearance stays stale pending revalidation.

Default rate/backpressure is AWS 5 req/s/source burst 10, Azure 4/8, GCP 5/10; max 2 concurrent calls/source, 20,000 instances/snapshot, 8 MiB/page and 30s. Provider quota errors persist retry time and never trigger cross-region or cross-account fallback.

- [ ] **Step 4: Run SDK wire/security tests and commit**

Use real SDK serializers against TLS protocol fixtures and assert exact host/path/query/action/version headers, real pagination tokens and identity responses. Add static call-graph tests forbidding create/start/stop/terminate/update/tag/security/network/storage methods.

Run:

~~~bash
gofmt -w $(rg --files internal/assetsource/cloud -g '*.go')
go mod tidy
go test -race ./internal/assetsource/cloud/... -count=1
govulncheck ./internal/assetsource/cloud/...
~~~

Expected: all three adapters independently pass identity, paging, DLP, missing/recovery, quota, checkpoint tamper and stale-fence tests.

~~~bash
git add go.mod go.sum internal/assetsource/cloud
git commit -m "feat(assetdiscovery): add governed cloud compute providers"
~~~

### Task 26: Five independent provider gates, real lab canaries, UI, and negative E2E

**Files:**
- Create: `internal/assetsource/proxmox/gate.go`
- Create: `internal/assetsource/proxmox/gate_test.go`
- Create: `internal/assetsource/openstack/gate.go`
- Create: `internal/assetsource/openstack/gate_test.go`
- Create: `internal/assetsource/cloud/gate.go`
- Create: `internal/assetsource/cloud/gate_test.go`
- Create: `scripts/verify-infrastructure-source-labs.sh`
- Create: `docs/operations/asset-sources/proxmox.md`
- Create: `docs/operations/asset-sources/openstack.md`
- Create: `docs/operations/asset-sources/cloud-compute.md`
- Create: `web/e2e/source-infrastructure-providers.spec.ts`
- Modify: `web/src/features/asset-sources/AssetSourcesPage.tsx`
- Modify: `web/src/features/asset-sources/SourceRunTimeline.tsx`

**Interfaces:**
- Produces independent gate keys for `PROXMOX_VE_V1`, `OPENSTACK_NOVA_V2_1`, `AWS_EC2_V1`, `AZURE_COMPUTE_V1`, `GCP_COMPUTE_V1`.
- `scripts/verify-infrastructure-source-labs.sh <provider-kind>` accepts only one closed provider kind plus opaque source/revision/lab-binding environment IDs; no endpoint/credential CLI flag exists.
- Safe receipt includes provider/source/revision/binding, identity/protocol/DLP/checkpoint/HA/backpressure/canary digests and expiration, never raw facts.

- [ ] **Step 1: Write failing independent-gate tests**

~~~go
func TestOneCloudGateCannotOpenAnother(t *testing.T) {
	store := newGateStore()
	store.Accept(validProof("AWS_EC2_V1"))
	if store.Status("AWS_EC2_V1") != assetcatalog.SourceGateAvailable {
		t.Fatal("AWS gate did not open")
	}
	for _, provider := range []string{"AZURE_COMPUTE_V1", "GCP_COMPUTE_V1", "OPENSTACK_NOVA_V2_1", "PROXMOX_VE_V1"} {
		if store.Status(provider) != assetcatalog.SourceGateUnavailable {
			t.Fatalf("%s inherited another provider gate", provider)
		}
	}
}
~~~

Run: `go test ./internal/assetsource/proxmox ./internal/assetsource/openstack ./internal/assetsource/cloud/... -run Gate -count=1`

Expected: FAIL because independent gate stores/evaluators do not exist.

- [ ] **Step 2: Implement proof-complete gate rules**

Each gate requires exact current revision/binding/authority identity, credential/trust/network validation, least-privilege probe, real SDK/protocol positive+negative suite, DLP/provenance, encrypted checkpoint resume, soft delete/recovery, provider-specific quota/backpressure, two-replica fence failover and a real non-production lab canary younger than 24h. Drift or cleanup/checkpoint ambiguity suspends only that source/provider and fences its runs. Temporary provider outage degrades with backoff; it cannot cause another region/account/provider to substitute.

- [ ] **Step 3: Execute five real lab canaries and negative E2E**

The script iterates only when explicitly invoked once per provider. Each lab has pre-seeded low-sensitivity compute assets; it performs read-only validate/publish/sync, one provider-approved read-only inventory change observation, pagination/crash resume and two-worker fence takeover. Negative cases are wrong authority/region/project, revoked opaque reference, bad CA, permission loss, 429/quota, malformed/oversized fields, DLP hit, token tamper, partial region and stale fence. It writes signed receipts to the evidence store and prints only IDs/digests/counts.

Run:

~~~bash
go test -race ./internal/assetsource/proxmox ./internal/assetsource/openstack ./internal/assetsource/cloud/... -count=1
for provider in PROXMOX_VE_V1 OPENSTACK_NOVA_V2_1 AWS_EC2_V1 AZURE_COMPUTE_V1 GCP_COMPUTE_V1; do
  scripts/verify-infrastructure-source-labs.sh "$provider"
done
corepack pnpm@10.34.0 --dir web test:e2e -- --grep "infrastructure source"
~~~

Expected: all five canaries and negative matrices PASS independently; UI displays the exact provider gate and does not imply the entire `CLOUD_PROVIDER` family is available when one adapter passes.

- [ ] **Step 4: Commit**

~~~bash
git add internal/assetsource/proxmox/gate.go internal/assetsource/proxmox/gate_test.go \
  internal/assetsource/openstack/gate.go internal/assetsource/openstack/gate_test.go \
  internal/assetsource/cloud/gate.go internal/assetsource/cloud/gate_test.go \
  scripts/verify-infrastructure-source-labs.sh docs/operations/asset-sources \
  web/e2e/source-infrastructure-providers.spec.ts \
  web/src/features/asset-sources/AssetSourcesPage.tsx \
  web/src/features/asset-sources/SourceRunTimeline.tsx
git commit -m "feat(assetdiscovery): gate infrastructure providers"
~~~
