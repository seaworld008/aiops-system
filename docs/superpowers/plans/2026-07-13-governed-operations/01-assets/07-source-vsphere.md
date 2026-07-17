# VMware vSphere Governed Discovery Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 使用真实 vSphere SOAP/PropertyCollector 协议发现 Datacenter、Cluster、ESXi Host、VirtualMachine 及关系，通过内容寻址 Source Revision、增量 checkpoint、HA fence、DLP 和独立 gate 形成可生产运行的 `VSPHERE` 来源。

**Architecture:** `govmomi` 只能由 Discovery Worker 的 vSphere adapter，以及 Task 21B0 后续显式批准的 resident authority production graph 导入；Control Plane、browser、通用 Worker/Runner 和其他 Provider 都不得导入。已发布修订绑定 server-installed vCenter profile、opaque Credential/Trust/Network references 和 authority inventory roots；validation 先固定 vCenter Instance UUID、TLS 身份、只读权限和最小 PropertyCollector probe。Task 21A 只在 Task 28A 同一个 claim/`AttemptSession`/`BoundRuntime` 生命周期内完成 paged `RetrievePropertiesEx → ContinueRetrievePropertiesEx` 全量快照；跨 Run 的 `WaitForUpdatesEx`、leave/soft-delete 与 HA resume 必须等待独立 PropertyCollector session-continuity authority 和 Task 21B。每页先规范化/DLP，再在当前 fence 下与 checkpoint 原子投影。

**Tech Stack:** Go 1.26.5、`github.com/vmware/govmomi v0.55.1`、vSphere SOAP API/PropertyCollector、TLS 1.3 where supported（最低 TLS 1.2 需显式安全例外证据）、PostgreSQL 18.4。

## Global Constraints

- 前置完成 [05-source-ingestion-csv-api.md](./05-source-ingestion-csv-api.md)；不得绕过其 Source Revision、validation/publish、Run/Fence/Checkpoint 契约。
- 每个 Task 严格执行 `Red → Green → Refactor`：先运行并保留预期失败，再做最小生产实现，随后消除重复、复跑指定验证并按 Task 提交；不得跳过失败或弱化断言。
- 不接受 vCenter URL、用户名、密码、session cookie、TLS thumbprint 或 PEM 作为 API/Run 参数；只使用已安装 profile 与 opaque references。
- 只允许 Session/ServiceContent/About、PropertyCollector inventory read 和受限 tag read；不得调用 PowerOn/Off、Reconfigure、Clone、Migrate、Guest Operations、Console/Ticket、Datastore file 或任何 mutation。
- 持久化字段限定为实例 UUID/MoRef 安全标识、名称、对象类型、电源/连接状态、CPU/内存容量、guest family code 和关系；不持久化 Guest IP/MAC、custom attributes、annotation、alarm body、event message、endpoint 或主机凭据。
- OS 类型仅由闭合 guest ID 映射为 `LINUX_VM|WINDOWS_VM`；未知/冲突为 `CLOUD_RESOURCE` 并创建治理冲突，不根据名称猜测。
- 每源最多 2 个并发 SOAP 读、500 objects/page、8 MiB/page、30s/call、1 full snapshot at a time；上游忙进入持久 backpressure。会话、collector、filter 或 continuation 丢失必须 fail closed，不能用新登录、缓存或重放旧 token 制造续接。
- 官方 PropertyCollector 协议事实是本计划的 C0 前提：[RetrieveResult](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vmodl.query.PropertyCollector.RetrieveResult.html) 的 continuation token 每次只能使用一次，并且只能由产生它的同一登录 session、同一 `PropertyCollector` 消费；[`WaitForUpdatesEx`](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vmodl.query.PropertyCollector.html) 计算的是该 session 中现存 filter 的更新，filter/version 随 session/collector 生命周期存在。关闭或丢失 session 会销毁这些服务端状态，持久 checkpoint tuple、digest 或新登录都不能重建它们。
- Raw session cookie、collector/filter handle 和 continuation token 永不进入 checkpoint、Queue、Run、receipt、audit、日志或序列化 payload。私有 sealed checkpoint 只允许 `{instance_uuid,mode,collector_version,full_snapshot_id,page_token_hash}`；其中 `collector_version` 也只能在 opened checkpoint 与 Task 21B0 authority 内作为完整性坐标，不能出现在公开 payload/log，也不能重建 session/filter。Task 21A 的 raw token 只存在于当前 `BoundRuntime`；Task 21B 的 live filter/version ownership 只能由 Task 21B0 authority 持有。
- 任一 token/session/collector/filter 丢失都必须保持旧 checkpoint、`missing=0` 并停止 Provider；只有已冻结的 Phase 1 `CHECKPOINT_LINEAGE_ROLLOVER` 可让同一 exact governed Run 建立新的完整 snapshot lineage。不得创建旁路 Run、清零/递减 checkpoint、复用旧 token 或把不完整结果视为删除。
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

### Task 21A: Same-attempt bounded full inventory and complete-snapshot closure

**State:** `NOT_STARTED / UNAVAILABLE / CLOSED`。该 Task 可独立开发和合并，但不得被描述为 incremental、HA-safe resume 或可用 Provider。

**Batch:** C0/C1/C2，严格只消费已合并 Task 20、Task 28A 与 PageCommitter/Queue/Checkpoint/rollover ABI。

**Exact files (6):**
- Create: `internal/assetsource/vsphere/inventory.go`
- Create: `internal/assetsource/vsphere/checkpoint.go`
- Create: `internal/assetsource/vsphere/inventory_test.go`
- Create: `internal/assetsource/vsphere/protocol_integration_test.go`
- Create: `internal/assetcatalog/postgres/vsphere_discovery_integration_test.go`
- Modify: `internal/assetsource/vsphere/validate.go`，只用最小变更把 Task 20 的 closed `Discover` stub 接到本 Task 实现；不得改变 validation/client/profile/normalize 行为。

`vsphere_discovery_integration_test.go` 是 vSphere 专属真库测试 owner：只承载 vSphere Provider outcome → 已合并 PageCommitter/PostgreSQL 的关闭态 page/relation/checkpoint/receipt/fence/rollover 证据。它不得拥有通用 Worker loop、其他 Provider、共享 fixture/helper 或生产代码；Task 21A 创建后只允许 Task 21B 顺序修改，其他 Provider/Worker Batch 不得消费或编辑它。

**Consumes:**

- Task 20 `vsphere.New(ClientFactory)`、固定只读 SOAP validation/normalization。
- Task 28A 同一 claim 中唯一的 `AttemptSession → ClaimRuntime → BoundRuntime` 和连续 `Discover` loop；完整 `RetrievePropertiesEx → ContinueRetrievePropertiesEx` 链必须在该同一 live session/同一 `PropertyCollector` 内结束。
- 已合并 PageCommitter/Queue/CheckpointCodec/lease-fence/checkpoint-lineage rollover；Provider 不复制这些 ABI，也不把 Source revision 或 Catalog time 注入事实。

**Produces:**

- 只产生 bounded full-inventory pages。Raw continuation token 保留在同一 `BoundRuntime` 的私有 runtime cell；持久 private checkpoint 仍固定为 `{instance_uuid,mode,collector_version,full_snapshot_id,page_token_hash}`，其中 hash 只验证当前 runtime 中 token 的关联，不授权新 runtime 续接。
- `VSPHERE_VCENTER_V1` 始终是 `SINGLE_ENVIRONMENT`；exact Source authority binding 解析一个 Environment，wire object 不能选择 Environment。
- 只有同一 vCenter instance、全部 configured roots、全部 object/relation pages 均无 transport/schema/DLP/root rejection 时，最后一页才产生 `(FinalPage=true,CompleteSnapshot=true)`。任何 partial/error/token/session/collector loss 都是 `CompleteSnapshot=false`、`missing=0`。
- 每个 item 使用 `CHECKPOINT_SEQUENCE{OrderSequence=accepted next checkpoint version,ProviderVersionSHA256=SHA256(FramedTupleV1("vsphere-object-version.v1",instance_uuid,collector_version,object_moref))}`；每个 relation 使用 `CHECKPOINT_SEQUENCE{OrderSequence=accepted next checkpoint version,ProviderVersionSHA256=SHA256(FramedTupleV1("vsphere-relation-version.v1",instance_uuid,collector_version,source_moref,target_moref,relationship_type))}`，两者都使用 Pack 01 byte encoding。Adapter 永不供应 Source revision 或 Catalog time。
- 旧 token/session 丢失只产生 safe closed evidence并停止；不得新登录后使用旧 token。后继只能由已冻结 `BeginCheckpointLineageRollover` 在 exact current Run/fence/evidence 下保持旧 checkpoint 并建立 successor full snapshot；Task 21A 不扩宽 Worker/Queue 公共 ABI。

**Classification:** C0 = token/session binding、fence/CAS/replay、identity drift、rollover、complete-only missing closure 与 sensitive serialization；C1 = full inventory/relation/complete snapshot；C2 = 固定 `RetrievePropertiesEx/ContinueRetrievePropertiesEx` SOAP wire。

- [ ] **Step 1: Write real failing full-inventory/session-loss tests**

RED 必须覆盖超过 500 objects 的分页 full closure、多个 root 的 deterministic object/relation ordering、continuation 只在同一 session/collector 成功、wrong session/collector 与 close 后 token 失败、partial root/DLP/schema rejection 时 `missing=0`、token/runtime/checkpoint serialization/log/DLP 负例、instance UUID drift、same-Run page replay 幂等、later-Run unchanged 仍追加 Observation、stale fence 零提交，以及 token/session 丢失只能走 governed rollover。测试不得用 fake 替代 production `discoverysource.Provider` 或 Task 28A loop。

Run:

~~~bash
go test ./internal/assetsource/vsphere ./internal/assetcatalog/postgres \
  -run 'VCenter|Inventory|FullSnapshot|SessionLoss|Rollover' -count=1
~~~

Expected: FAIL because same-attempt full inventory and closure are absent。

- [ ] **Step 2: Implement only the same-attempt full snapshot**

每个 configured root 创建 fixed object/property spec；结果按 `(provider_kind,external_id)` 排序，relation 按 Pack 01 full tuple 排序。Intermediate pages 始终 `(false,false)`。Continuation token 每次消费后立即失效；下一 token 只更新当前 runtime cell 与 checkpoint hash。若 runtime 中没有与 checkpoint hash 匹配的 live token，Provider 在发 SOAP 前关闭，旧 checkpoint 不变且不运行 missing detection。

- [ ] **Step 3: Run Task 21A G2**

G2 必须使用本机 TLS govmomi simulator 的真实 SOAP serialization 与项目 PostgreSQL 18.4 TLS wrapper/application identity；`AIOPS_TEST_POSTGRES_DSN` 缺失或 Skip 都不是 PASS。

~~~bash
test -n "${AIOPS_TEST_POSTGRES_DSN:-}"
go test -race ./internal/assetsource/vsphere \
  -run 'ProtocolIntegration|Inventory|FullSnapshot|SessionLoss' -count=1
go test -race ./internal/assetcatalog/postgres \
  -run 'VCenterDiscoveryIntegration|PageCommitter|CheckpointLineageRollover|StaleFence' -count=1
~~~

Expected: 同一 Task 28A attempt 内真实 paged full inventory/closure PASS；session/token loss、partial root、stale fence 和 rollover negatives PASS。该门不声称跨 Run delta、leave、HA takeover、真实 vCenter 或 Provider availability。

### Task 21B0: vSphere PropertyCollector session-continuity authority (C0 prerequisite)

**State:** `NOT_STARTED / UNAVAILABLE / CLOSED`。本 Task 是 Task 21B 的显式设计/实现前置，不是 Task 28B 的别名；本节冻结 vSphere protocol half，[Pack 09 对应入口](./09-discovery-worker-ha-e2e.md#task-21b0-dependency-vsphere-propertycollector-session-continuity-authority)冻结 Worker/HA half，两者交叉引用同一个 prerequisite，不是两套实现。

**Admission boundary:** 当前没有已批准的 production topology 或 exact file manifest 可以让 session/filter/version 跨 Run、跨 Worker 保持 live。实现前必须先在本 Task 与 Pack 09 同一入口冻结不重叠文件所有权、私有 ABI、resident authority deployment/identity、failure model 和 G2 命令；缺任一项立即停工，禁止在公共 `discoverysource`/Queue/Worker ABI 上临时加字段，也禁止用 cookie/token 序列化、process cache、新登录或 Task 28B cleanup recovery 冒充 continuity。

**Required `Produces`:**

- 一个 opaque、不可序列化的 vSphere-specific resident authority，exact 绑定 Source/revision、validated instance UUID、authority-root digest、collector/session/filter identity、credential revision 和当前 lease/fence owner；raw cookie/token/filter handle 永不离开 authority，`collector_version` 只允许作为 sealed checkpoint/authority 内部完整性坐标。
- 跨 Run lease/fence 只能由单调 CAS handoff；stale owner 在 SOAP 前拒绝。Task 28A attempt cleanup 只关闭当前 Worker 到 authority 的 exact attempt handle，不能销毁或证明该 resident vSphere session，也不能让 replacement Worker获得 Provider runtime。
- Authority 必须提供一个 no-gap bootstrap barrier：在同一 resident session/collector 中先创建 filter并取得可继续的 initial version，再运行 Task 21A 的 deterministic full-inventory algorithm，同时保留 filter updates；只有 full pages 与其间全部 updates 已 drain 到一个 non-truncated version 后，才允许产生 authoritative complete-snapshot closure 和首个 incremental checkpoint。Task 21A 在独立 attempt 中形成的 completed checkpoint绝不能直接升级为 21B cursor。
- Credential rotation、Source disable/supersede、instance/root drift、collector/session expiry、authority shutdown 和 terminal failure 都有 idempotent revoke/destroy receipt；cleanup uncertainty 必须暂停 gate。普通 Run 完成与 authority 最终销毁是两种不同 closure，必须证明没有 orphan session/filter。
- Authority 丢失时，checkpoint tuple/digest 不能重建 session/filter/version；只能保持 `missing=0` 并经 governed rollover 建立新 full snapshot lineage。

**Classification:** C0 = authority identity/binding、cross-Run lease/fence、credential rotation、terminal cleanup/revoke、no-orphan、secret-zero wire；C1 = authority lifecycle/handoff；C2 = resident authority fixed protocol 与真实 PropertyCollector ownership。

**Required G2 before Task 21B may start:** 两个独立 authority client 实例必须使用 distinct worker/process identity，通过真实 TLS authority implementation 访问同一 govmomi simulator session/collector/filter；真实 PostgreSQL fence/CAS、owner-client termination/takeover、stale owner、credential rotation、authority/session loss、terminal revoke/no-orphan、response-loss replay 与 sensitive serialization 全部 PASS。测试还必须在 filter creation、initial version、每个 full page、delta drain 和 final closure 之间分别插入 create/modify/delete，证明无遗漏 tombstone/restore且 partial/gap 始终 `missing=0`。Task 28B test-only transport fixture、单进程 map 或 mock SOAP 均不能满足此门。两真实 Discovery Worker binary、真实非生产 vCenter、真实部署 authority HA 与发布资格保留 G3/G4。

### Task 21B: Cross-Run incremental updates, leave/soft-delete, and HA-safe resume

**State:** `NOT_STARTED / UNAVAILABLE / CLOSED`。只有 Task 21A 与 Task 21B0 均已合并且 Task 21B0 G2 真实通过后才可开始。

**Exact files (5):**
- Create: `internal/assetsource/vsphere/updates.go`
- Create: `internal/assetsource/vsphere/updates_test.go`
- Modify: `internal/assetsource/vsphere/checkpoint.go`
- Modify: `internal/assetsource/vsphere/protocol_integration_test.go`
- Modify: `internal/assetcatalog/postgres/vsphere_discovery_integration_test.go`

**Consumes:** Task 21A deterministic full-inventory implementation/evidence（不消费其独立-attempt checkpoint作为 incremental cursor）、Task 21B0 resident authority/no-gap bootstrap barrier、Task 28A exact claim/AttemptSession seam，以及已合并 PageCommitter/Queue/Checkpoint/rollover/stale-fence contracts。Task 21B 不修改这些公共 ABI。

**Produces:**

- Bounded `WaitForUpdatesEx` only through the exact live Task 21B0 authority。首次 incremental lineage 必须在同一 resident session/collector 内执行 `create filter → initial version → Task 21A full algorithm while retaining updates → drain to non-truncated version → authoritative complete closure`；Task 21A 独立 session 的 full checkpoint不能直接续接。`enter|modify` 产生完整 allow-listed projection，`leave` 产生 tombstone 而非 hard delete；later Run unchanged 仍追加 Observation chain。
- Item 的 `CHECKPOINT_SEQUENCE` 使用 `OrderSequence=accepted next checkpoint version` 与 `ProviderVersionSHA256=SHA256(FramedTupleV1("vsphere-object-version.v1",instance_uuid,collector_version,object_moref))`；relation 使用同一 `OrderSequence` 与 `ProviderVersionSHA256=SHA256(FramedTupleV1("vsphere-relation-version.v1",instance_uuid,collector_version,source_moref,target_moref,relationship_type))`。Private checkpoint tuple不能替代 authority binding。
- `InvalidCollectorVersion` 或 authority/session loss 且 instance UUID 未变时，产生 closed `VSPHERE_COLLECTOR_VERSION_EXPIRED` evidence，保持旧 checkpoint、`missing=0` 并走 governed rollover full snapshot。Instance UUID 变化是 `VSPHERE_INSTANCE_IDENTITY_DRIFT`，暂停 gate并要求新 validated/published revision，绝不 rollover。
- Same-Run exact replay只返回既有 PageCommitter receipt；changed replay、stale fence、authority owner drift、cleanup uncertainty 和 partial update 均零提交。恢复的 VM 保持 `STALE`，直到后续 Connection publication 重新验证。

**Classification:** C0 = authority/checkpoint/fence/CAS/replay、identity drift/rollover、tombstone 与 cleanup terminal；C1 = delta/delete/recovery/complete closure；C2 = 固定 `WaitForUpdatesEx` SOAP protocol。

- [ ] **Step 1: Write real failing delta/delete/cross-Run tests**

RED 至少覆盖 cross-Run live filter/version、`enter|modify|leave`、leave tombstone 不 hard delete、same-Run replay、later-Run unchanged Observation、stale fence、owner takeover、collector expiry rollover、instance UUID drift、credential rotation、terminal cleanup/no-orphan，以及 token/filter/version/serialization/DLP negatives。必须在 filter creation、initial version、full-page boundaries、delta drain 与 final closure 间删除/恢复对象，证明没有 bootstrap gap；独立 Task 21A checkpoint、partial initial update或 truncated drain 都不能启用 incremental checkpoint/missing detection。

- [ ] **Step 2: Implement bounded incremental discovery through the authority**

Adapter 不接收 raw filter/session，所有 SOAP command 都带 authority server-derived exact binding 和当前 fence admission。Bootstrap full pages在 filter update barrier drain 完成前不得设置 `CompleteSnapshot=true`；最终 closure必须同时绑定同一 resident session/collector、initial version、drained non-truncated version与 exact full snapshot。任何 partial/error/root/DLP/authority ambiguity或 bootstrap gap 都不做 missing detection；只有 governed successor full snapshot 的 rejection-free final closure才能恢复 missing detection和 degraded gate。

- [ ] **Step 3: Run Task 21B G2**

~~~bash
test -n "${AIOPS_TEST_POSTGRES_DSN:-}"
go test -race ./internal/assetsource/vsphere \
  -run 'ProtocolIntegration|Incremental|Leave|Authority|Takeover|Rollover' -count=1
go test -race ./internal/assetcatalog/postgres \
  -run 'VCenterDiscoveryIntegration|PageCommitter|CheckpointLineageRollover|StaleFence' -count=1
~~~

Expected: real TLS SOAP、real Task 21B0 authority 和 PostgreSQL 18.4 behavior PASS，无 Skip；不把 simulator 或双 client G2 写成真实非生产 vCenter/两生产 Worker G3。

**Shared fresh G1 for Task 21A/21B0/21B PRs:**

~~~bash
go mod verify
test -z "$(gofmt -l $(rg --files -g '*.go'))"
git diff --check
go vet ./...
go build ./cmd/control-plane ./cmd/worker ./cmd/read-runner ./cmd/write-runner ./cmd/executor
~~~

G3/G4 始终 deferred：真实非生产 vCenter、真实 deployed session authority、两真实 Discovery Worker takeover/restart、canary、Task 22 gate 和 final Provider matrix 未完成前，vSphere 最多 `BUILT_CLOSED`，并继续 `UNAVAILABLE/CLOSED`。

### Task 22: vSphere availability gate, non-production vCenter canary, and UI/operations proof

**Hard prerequisite:** Task 21B0 resident authority、Task 21B、Task 28C vSphere registry row 与 Task 29A vSphere-specific two-worker HA evidence必须依次真实完成并具有 current evidence。Task 21A 单独合并不允许 Task 22、Task 28C registry、Task 29A vSphere HA receipt、canary 或 Task 29B matrix 消费 vSphere 为 available；在此之前本 Task 固定 `NOT_STARTED/UNAVAILABLE/CLOSED`。

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

`AVAILABLE` requires exact current revision/binding, vCenter identity, TLS, least-privilege, credential cleanup, full+delta SOAP protocol, normalized schema/DLP, rate/backpressure, encrypted-checkpoint recovery, stale-fence and HA failover proofs plus a non-production vCenter canary younger than 24h. Instance UUID/TLS/root/revision drift, guest-operation permission, checkpoint ambiguity or cleanup uncertainty immediately suspends the source and fences live runs. Temporary busy alone may degrade with persisted backoff。Session/collector/filter expiry必须 fence并幂等 destroy旧 authority、保持旧 checkpoint和 `missing=0`，只允许 governed full-snapshot rollover在 rejection-free no-gap closure后恢复；它绝不是普通 retry，也不能旋转到未批准 vCenter。

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
