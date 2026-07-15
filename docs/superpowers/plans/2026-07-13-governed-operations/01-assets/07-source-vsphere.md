# VMware vSphere Governed Discovery Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 使用真实 vSphere SOAP/PropertyCollector 协议发现 Datacenter、Cluster、ESXi Host、VirtualMachine 及关系，通过内容寻址 Source Revision、增量 checkpoint、HA fence、DLP 和独立 gate 形成可生产运行的 `VSPHERE` 来源。

**Architecture:** `govmomi` 只被 Discovery Worker 的 vSphere adapter 导入。已发布修订绑定 server-installed vCenter profile、opaque Credential/Trust/Network references 和 authority inventory roots；validation 先固定 vCenter Instance UUID、TLS 身份、只读权限和最小 PropertyCollector probe。首次使用 paged `RetrievePropertiesEx`，后续使用 `WaitForUpdatesEx` version checkpoint；每页先规范化/DLP，再在当前 fence 下与 checkpoint 原子投影。

**Tech Stack:** Go 1.26.5、`github.com/vmware/govmomi v0.55.1`、vSphere SOAP API/PropertyCollector、TLS 1.3 where supported（最低 TLS 1.2 需显式安全例外证据）、PostgreSQL 18.4。

## Global Constraints

- 前置完成 [05-source-ingestion-csv-api.md](./05-source-ingestion-csv-api.md)；不得绕过其 Source Revision、validation/publish、Run/Fence/Checkpoint 契约。
- 每个 Task 严格执行 `Red → Green → Refactor`：先运行并保留预期失败，再做最小生产实现，随后消除重复、复跑指定验证并按 Task 提交；不得跳过失败或弱化断言。
- 不接受 vCenter URL、用户名、密码、session cookie、TLS thumbprint 或 PEM 作为 API/Run 参数；只使用已安装 profile 与 opaque references。
- 只允许 Session/ServiceContent/About、PropertyCollector inventory read 和受限 tag read；不得调用 PowerOn/Off、Reconfigure、Clone、Migrate、Guest Operations、Console/Ticket、Datastore file 或任何 mutation。
- 持久化字段限定为实例 UUID/MoRef 安全标识、名称、对象类型、电源/连接状态、CPU/内存容量、guest family code 和关系；不持久化 Guest IP/MAC、custom attributes、annotation、alarm body、event message、endpoint 或主机凭据。
- OS 类型仅由闭合 guest ID 映射为 `LINUX_VM|WINDOWS_VM`；未知/冲突为 `CLOUD_RESOURCE` 并创建治理冲突，不根据名称猜测。
- 每源最多 2 个并发 SOAP 读、500 objects/page、8 MiB/page、30s/call、1 full snapshot at a time；上游忙/会话失效进入持久 backpressure，不忙循环。
- PropertyCollector token/version 加密保存；audit/UI 仅显示 hash/version/age。token 过期必须让当前 exact Run 走 Phase 1 `CHECKPOINT_LINEAGE_ROLLOVER` 并切换到新的完整 snapshot lineage；不得创建旁路 Run、清零或任意重置 checkpoint，也不得把不完整结果视为删除。
- 真实协议 CI 使用 govmomi simulator 的 SOAP wire；生产 gate 还需受控非生产 vCenter canary 与 HA 故障演练。
- 完成后进入 [08-source-proxmox-openstack-cloud.md](./08-source-proxmox-openstack-cloud.md)。

---

### Task 20: vSphere profile, client construction, identity/privilege validation, and normalization

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`
- Create: `internal/assetsource/vsphere/profile.go`
- Create: `internal/assetsource/vsphere/client.go`
- Create: `internal/assetsource/vsphere/validate.go`
- Create: `internal/assetsource/vsphere/normalize.go`
- Create: `internal/assetsource/vsphere/validate_test.go`
- Create: `internal/assetsource/vsphere/normalize_test.go`
- Create: `internal/assetsource/vsphere/security_test.go`

**Interfaces:**
- Consumes: `discoverysource.Provider`, exact `VSPHERE_VCENTER_V1` Source Profile and non-serializable `BoundRuntime`.
- Produces: `vsphere.New(ClientFactory) (discoverysource.Provider, error)` with `Kind()=VSPHERE`, `ProviderKind()=VSPHERE_VCENTER_V1`.
- The pre-cleanup Provider validation proof binds vCenter `about.instanceUuid`, API version, inventory-root digest, TLS peer digest, privilege-set digest, `CREDENTIAL_OPEN` and fixed-probe digests. Broker cleanup is a separate later `ATTEMPT_CLEANED`/terminal receipt and never part of this proof.

- [ ] **Step 1: Write failing identity, privilege, and forbidden-method tests**

~~~go
func TestValidateRejectsDifferentVCenterInstanceUUID(t *testing.T) {
	server := startVCenterSimulatorTLS(t)
	provider := newProvider(t, expectedInstanceUUID("42000000-0000-0000-0000-000000000099"))
	proof, err := provider.Validate(context.Background(), server.Runtime(), validationRequest())
	if err != nil || proof.Outcome != assetcatalog.ValidationOutcomeFailed || proof.Code != "VCENTER_IDENTITY_MISMATCH" {
		t.Fatalf("Validate = (%#v, %v)", proof, err)
	}
}

func TestVCenterAdapterDoesNotImportMutationOrGuestOperations(t *testing.T) {
	source := readPackageSource(t, "internal/assetsource/vsphere")
	for _, forbidden := range []string{"PowerOnVM_Task", "PowerOffVM_Task", "ReconfigVM_Task", "GuestOperationsManager", "AcquireTicket"} {
		if strings.Contains(source, forbidden) {
			t.Errorf("forbidden vSphere operation %s", forbidden)
		}
	}
}
~~~

Run: `go test ./internal/assetsource/vsphere -count=1`

Expected: FAIL because the adapter is absent.

- [ ] **Step 2: Pin dependency and implement fail-closed runtime binding**

Add exact `github.com/vmware/govmomi v0.55.1`. `ClientFactory` builds a dedicated SOAP client only from profile-resolved endpoint plus Credential/Trust handles. It disables environment proxy, rejects redirects, requires pinned CA/SNI or reviewed TLS 1.2 exception, sets timeouts and registers a cleanup that logs out/clears session material on every success, error, cancellation or panic boundary. Neither runtime nor client implements `json.Marshaler`.

- [ ] **Step 3: Implement validation and allow-listed object normalization**

Validation calls only `RetrieveServiceContent`, session login, `About`, current session, a fixed privilege-check query and one bounded PropertyCollector request under configured roots. Required privileges are an exact server-owned read set; any extra privilege is reported as a stable warning and any missing privilege fails. Do not request properties outside the allow-list.

Object mapping:

~~~text
Datacenter / ClusterComputeResource / ResourcePool / Datastore / Network -> CLOUD_RESOURCE
HostSystem -> BARE_METAL_HOST
VirtualMachine + closed Linux guest ID -> LINUX_VM
VirtualMachine + closed Windows guest ID -> WINDOWS_VM
VirtualMachine + unknown/ambiguous guest ID -> CLOUD_RESOURCE
folder/cluster contains child; VM RUNS_ON Host; VM contained by resource pool/datacenter
~~~

Every source-owned field gets a closed `VSPHERE_V1_*` provenance path code. MoRef is namespaced with vCenter Instance UUID. Reject duplicate instance UUID, object outside authority roots, invalid capacity, oversized names, secret-shaped custom data and cross-root relations.

- [ ] **Step 4: Verify and commit**

Run:

~~~bash
gofmt -w $(rg --files internal/assetsource/vsphere -g '*.go')
go mod tidy
go test -race ./internal/assetsource/vsphere -count=1
govulncheck ./internal/assetsource/vsphere/...
~~~

Expected: PASS; `go.mod/go.sum` pin the exact version, validation fails closed and no mutation/secret-bearing field reaches normalized output.

~~~bash
git add go.mod go.sum internal/assetsource/vsphere
git commit -m "feat(assetdiscovery): add governed vsphere provider"
~~~

### Task 21: Full inventory, incremental PropertyCollector checkpoint, soft deletion, and HA-safe resume

**Files:**
- Create: `internal/assetsource/vsphere/inventory.go`
- Create: `internal/assetsource/vsphere/updates.go`
- Create: `internal/assetsource/vsphere/checkpoint.go`
- Create: `internal/assetsource/vsphere/inventory_test.go`
- Create: `internal/assetsource/vsphere/updates_test.go`
- Create: `internal/assetsource/vsphere/protocol_integration_test.go`
- Modify: `internal/assetcatalog/postgres/discovery_integration_test.go`

**Interfaces:**
- Consumes checkpoint `{instance_uuid,mode,collector_version,full_snapshot_id,page_token_hash}` and current lease fence.
- Produces bounded pages from `RetrievePropertiesEx/ContinueRetrievePropertiesEx` or `WaitForUpdatesEx`; raw page token/version exists only inside sealed checkpoint.
- Produces complete-snapshot marker only after every configured inventory root closes on the same vCenter instance/version.
- `VSPHERE_VCENTER_V1` is `SINGLE_ENVIRONMENT`; the exact Source authority binding resolves one Environment and wire objects cannot select another.
- Every emitted item/tombstone uses `CHECKPOINT_SEQUENCE{OrderSequence=accepted next checkpoint version,ProviderVersionSHA256=SHA256(FramedTupleV1("vsphere-object-version.v1",instance_uuid,collector_version,object_moref))}` with the Pack 01 byte encoding; Adapter never supplies Source revision or Catalog time.

- [ ] **Step 1: Write failing full/delta/delete/resume tests**

~~~go
func TestIncrementalLeaveCreatesTombstoneWithoutHardDelete(t *testing.T) {
	simulator := seededVCenterSimulator(t)
	provider := providerForSimulator(t, simulator)
	checkpoint := completeInitialInventory(t, provider, simulator.Runtime())
	removedID := simulator.RemoveVM(t, "vm-delete-me")

	page, err := requirePageOutcome(provider.Discover(context.Background(), simulator.Runtime(), requestAt(checkpoint)))
	if err != nil || len(page.Items) != 1 || !page.Items[0].Tombstone || page.Items[0].ExternalID != removedID {
		t.Fatalf("page = (%#v, %v)", page, err)
	}
	assertHistoryPreservedAndLifecycleStale(t, removedID)
}

func TestStaleFenceCannotAdvancePropertyCollectorCheckpoint(t *testing.T) {
	result := applyVCenterPageWithExpiredFence(t)
	if !errors.Is(result.Err, discoverysource.ErrStaleFence) || result.ObservationCount != 0 || result.CheckpointVersionChanged {
		t.Fatalf("result = %#v", result)
	}
}

func TestSameRunVCenterPageReplayIsIdempotentAndLaterRunUnchangedAppendsObservation(t *testing.T)
~~~

Run: `go test ./internal/assetsource/vsphere ./internal/assetcatalog/postgres -run VCenter -count=1`

Expected: FAIL because inventory/update/checkpoint flows are missing.

- [ ] **Step 2: Implement deterministic full inventory and relation closure**

Create one ContainerView per configured root with a fixed object-type/property spec. Sort normalized objects by `(provider_kind,external_id)` and emit relations in top-level `Page.Relations`, sorted by the Pack 01 full tuple；never duplicate the source Item on a later relation page. Every relation uses `CHECKPOINT_SEQUENCE{OrderSequence=accepted next checkpoint version,ProviderVersionSHA256=SHA256(FramedTupleV1("vsphere-relation-version.v1",instance_uuid,collector_version,source_moref,target_moref,relationship_type))}`. A full snapshot checkpoint binds instance UUID, root digest, source revision digest and snapshot ID. Intermediate pages use `(FinalPage=false,CompleteSnapshot=false)`；only a rejection-free asset-and-relation final closure uses `(true,true)`. Any root error, page token loss, vCenter restart, object schema rejection or DLP finding fails/downgrades closure and prevents missing detection.

- [ ] **Step 3: Implement incremental updates and governed checkpoint-lineage rollover**

Use `WaitForUpdatesEx` with bounded wait and max object updates. Accept only `enter|modify|leave` for known objects/properties. `leave` emits a tombstone; `enter/modify` emits a complete allow-listed projection. If the Collector version expires while the exact validated vCenter instance UUID is unchanged, return the closed reason `VSPHERE_COLLECTOR_VERSION_EXPIRED` and enter the Phase 1 `CHECKPOINT_LINEAGE_ROLLOVER` path; after bounded backoff that same exact governed Run is the sole gate exception and must establish the successor lineage through a full snapshot. If the vCenter instance UUID changes, fail as `VSPHERE_INSTANCE_IDENTITY_DRIFT`, suspend the gate and require a newly validated/published canonical Source revision; identity drift is never a rollover. Neither case may continue with the old token.

For each page, Reconciler verifies fence/source revision/gate/checkpoint-before and exact `CHECKPOINT_SEQUENCE`, commits Observations/relations/checkpoint-after together, returns an exact same-Run replay receipt, and rejects a changed replay digest. A later Run observing unchanged content still appends its Observation/chain but does not append Type Detail or alter governance fields. Collector expiry consumes the Phase 1 rollover receipt exactly as defined by the core contract: the persisted prior checkpoint remains intact until an accepted successor-lineage page advances it by CAS, `checkpoint_version` stays monotonic, and neither Control Plane nor Adapter may clear, decrement or synthesize a reset. The gate remains degraded and missing detection remains disabled until a rejection-free full snapshot closes the rollover. Only publication of a newly validated canonical revision follows the separate publication checkpoint transition. A recovered VM remains `STALE` until later Connection publication revalidates it. Credential/session cleanup is terminal evidence even when the run is cancelled.

- [ ] **Step 4: Run real SOAP simulator and PostgreSQL failover tests**

Run:

~~~bash
go test -race ./internal/assetsource/vsphere -run 'ProtocolIntegration|Inventory|Incremental' -count=1
TEST_DATABASE_URL="$TEST_DATABASE_URL" \
  go test -race ./internal/assetcatalog/postgres -run VCenterDiscoveryIntegration -count=1
~~~

Expected: actual SOAP requests pass for paged full inventory and delta; crash after page commit resumes once, expired Worker fence cannot commit, deletion/recovery preserves history/provenance and partial runs never mark missing assets stale.

- [ ] **Step 5: Commit**

~~~bash
git add internal/assetsource/vsphere internal/assetcatalog/postgres/discovery_integration_test.go
git commit -m "feat(assetdiscovery): reconcile vsphere inventory deltas"
~~~

### Task 22: vSphere availability gate, non-production vCenter canary, and UI/operations proof

**Files:**
- Create: `internal/assetsource/vsphere/gate.go`
- Create: `internal/assetsource/vsphere/gate_test.go`
- Create: `scripts/verify-vsphere-source.sh`
- Create: `docs/operations/asset-sources/vsphere.md`
- Create: `web/e2e/source-vsphere.spec.ts`
- Modify: `web/src/features/asset-sources/AssetSourcesPage.tsx`
- Modify: `web/src/features/asset-sources/SourceRunTimeline.tsx`

**Interfaces:**
- Produces gate key `VSPHERE/VSPHERE_VCENTER_V1/<source_id>/<revision_digest>/<instance_uuid_digest>`.
- Consumes current validation, SOAP protocol, DLP, checkpoint, credential-cleanup, rate/backpressure, two-replica failover and real non-production canary receipts.
- Script accepts only `AIOPS_SOURCE_ID`, `AIOPS_SOURCE_REVISION`, `AIOPS_DISCOVERY_LAB_BINDING` opaque identifiers.

- [ ] **Step 1: Write failing per-provider gate tests**

~~~go
func TestVCenterGateClosesOnInstanceOrCollectorDrift(t *testing.T) {
	proofs := validVCenterProofs()
	if EvaluateGate(proofs).Status != assetcatalog.SourceGateAvailable {
		t.Fatal("valid source is unavailable")
	}
	proofs.LiveInstanceUUIDDigest = digest("other-vcenter")
	decision := EvaluateGate(proofs)
	if decision.Status != assetcatalog.SourceGateSuspended || decision.ReasonCode != "VSPHERE_IDENTITY_DRIFT" {
		t.Fatalf("decision = %#v", decision)
	}
}
~~~

Run: `go test ./internal/assetsource/vsphere -run Gate -count=1`

Expected: FAIL because vSphere gate evaluation is absent.

- [ ] **Step 2: Implement evidence-complete gate and stop rules**

`AVAILABLE` requires exact current revision/binding, vCenter identity, TLS, least-privilege, credential cleanup, full+delta SOAP protocol, normalized schema/DLP, rate/backpressure, encrypted-checkpoint recovery, stale-fence and HA failover proofs plus a non-production vCenter canary younger than 24h. Instance UUID/TLS/root/revision drift, guest-operation permission, checkpoint ambiguity or cleanup uncertainty immediately suspends the source and fences live runs. Temporary busy/session expiry degrades with persisted backoff and never rotates to an unapproved vCenter.

- [ ] **Step 3: Run canary, UI, and negative E2E**

The canary creates no VM and performs no mutation. It validates, publishes a reviewed revision, discovers a pre-seeded non-sensitive inventory, checks exact object/relation counts, triggers one read-only simulator/lab inventory change, verifies delta and cleanup, then records a signed safe receipt.

Run:

~~~bash
go test -race ./internal/assetsource/vsphere -count=1
scripts/verify-vsphere-source.sh
corepack pnpm@10.34.0 --dir web test:e2e -- --grep "vSphere source"
~~~

Expected: canary and wrong-instance/bad-CA/missing privilege/oversize/custom-secret/token-expiry/rate-limit/stale-fence cases PASS; UI separates validation, revision, gate, checkpoint and run states without exposing endpoint/session/guest network facts.

- [ ] **Step 4: Commit**

~~~bash
git add internal/assetsource/vsphere/gate.go internal/assetsource/vsphere/gate_test.go \
  scripts/verify-vsphere-source.sh docs/operations/asset-sources/vsphere.md \
  web/e2e/source-vsphere.spec.ts web/src/features/asset-sources/AssetSourcesPage.tsx \
  web/src/features/asset-sources/SourceRunTimeline.tsx
git commit -m "feat(assetdiscovery): gate vsphere inventory sources"
~~~
