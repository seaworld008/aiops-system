# Discovery Worker, HA Fencing, Backpressure, and Provider Acceptance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 创建真实 `cmd/discovery-worker`、PostgreSQL HA queue/lease/fence、加密 checkpoint、持久限流/背压与全 Provider 生产验收门，使 Source 控制面与发现数据面形成可故障转移的闭环。

**Architecture:** Control Plane 只创建不可变 Source Revision 和 durable Run；Discovery Worker 通过 PostgreSQL `FOR UPDATE SKIP LOCKED` 领取 exact source/revision/gate 任务，使用单调 fence epoch/token 在 validation、runtime resolve、credential open、provider call、page reconcile、checkpoint、heartbeat 和 complete 边界复验。Provider runtime/credential 只在 Worker 内存；页结果经 Schema/DLP 后与加密 checkpoint 在一个事务提交。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4、pgx v5、AES-256-GCM、mTLS workload identity、existing `workerbootstrap`/`securemanifest`、Prometheus client_golang 1.23.2。

## Global Constraints

- 前置完成 [05-source-ingestion-csv-api.md](./05-source-ingestion-csv-api.md)、[06-source-external-cmdb.md](./06-source-external-cmdb.md)、[07-source-vsphere.md](./07-source-vsphere.md) 与 [08-source-proxmox-openstack-cloud.md](./08-source-proxmox-openstack-cloud.md)。
- 每个 Task 严格执行 `Red → Green → Refactor`：先运行并保留预期失败，再做最小生产实现，随后消除重复、复跑指定验证并按 Task 提交；不得跳过失败或弱化断言。
- 生产必须有独立 `cmd/discovery-worker`；不得把 Provider SDK、Credential Resolver 或目标网络客户端装入 Control Plane、通用 `cmd/worker` 或浏览器。
- Job/Run 只含 Source/Revision/Gate/Checkpoint digest、Scope、Run ID、预算和 fence；不含 endpoint、Secret、Token、PEM、cursor plaintext、Header/Body 或 Provider 错误。
- Raw lease token 只存 Worker 内存，DB 仅存 SHA-256；每次 reclaim 必须 `fence_epoch+1` 且旧 fence 无法 heartbeat/reconcile/checkpoint/complete。
- Checkpoint 使用 AES-256-GCM，AAD 绑定 Tenant/Workspace/Source/Provider/Revision/Definition/Fence epoch/Checkpoint version；key 只通过 workload secret binding 读取。
- 数据库持久每 source/workspace/provider 并发、token bucket、`not_before`、queue depth 和 failure streak；进程内 semaphore 只是二次保护，不是授权事实。
- Validation Run 可消费 `VALIDATING` revision；Discovery/Import/Ingestion Run 仅可消费 exact `PUBLISHED + ACTIVE + AVAILABLE`。任何漂移停止并关闭影响的 provider/source gate。
- Credential open/session cleanup 是 terminal 成功的必要证据；cleanup 未知不能把 run 写为成功。
- `MANUAL` 不进 Worker；`KUBERNETES_OPERATOR` 由 Phase 3 注册；`AWX_INVENTORY` 由 Phase 5 固定 AWX 契约注册。未注册时都是 `UNAVAILABLE`，不得用通用 Provider 替代。
- 完成后进入 [10-overview-control-room.md](./10-overview-control-room.md)。

---

### Task 27: PostgreSQL source queue, lease/fence, encrypted checkpoint, and global backpressure

**Files:**
- Create: `internal/discoveryqueue/queue.go`
- Create: `internal/discoveryqueue/postgres/repository.go`
- Create: `internal/discoveryqueue/postgres/repository_test.go`
- Create: `internal/discoveryqueue/postgres/repository_integration_test.go`
- Create: `internal/discoverycheckpoint/codec.go`
- Create: `internal/discoverycheckpoint/codec_test.go`
- Create: `internal/discoverylimit/limiter.go`
- Create: `internal/discoverylimit/postgres/limiter.go`
- Create: `internal/discoverylimit/postgres/limiter_integration_test.go`

**Interfaces:**
- Produces `Queue.Claim/Heartbeat/Delay/Complete/Fail` and `PageCommitter.ApplyPage` with exact `LeaseFence`.
- Produces `CheckpointCodec.Seal/Open` and `Limiter.Acquire/Release/Delay` bound to Source/Workspace/Provider.
- Consumes nine-table `000015` schema; creates no new migration.

- [ ] **Step 1: Write failing reclaim, stale-fence, checkpoint-tamper, and global-limit tests**

~~~go
func TestExpiredRunReclaimInvalidatesOldFence(t *testing.T) {
	queue := openQueue(t)
	first := claimRun(t, queue, "worker-a", 30*time.Second)
	advanceClock(t, 31*time.Second)
	second := claimRun(t, queue, "worker-b", 30*time.Second)
	if second.Fence.Epoch != first.Fence.Epoch+1 || second.Fence.Token == first.Fence.Token {
		t.Fatalf("fences = %#v %#v", first.Fence, second.Fence)
	}
	if _, err := queue.Heartbeat(context.Background(), first.Fence, 1, 30*time.Second); !errors.Is(err, discoveryqueue.ErrStaleFence) {
		t.Fatalf("old heartbeat error = %v", err)
	}
}

func TestCheckpointCannotOpenInAnotherScopeOrRevision(t *testing.T) {
	codec := newCheckpointCodec(t)
	sealed := sealCheckpoint(t, codec, scopeA(), sourceRevision(3))
	if _, err := codec.Open(context.Background(), scopeB(), sourceRevision(3), sealed); !errors.Is(err, discoverycheckpoint.ErrAuthentication) {
		t.Fatalf("cross-scope open error = %v", err)
	}
	if _, err := codec.Open(context.Background(), scopeA(), sourceRevision(4), sealed); !errors.Is(err, discoverycheckpoint.ErrAuthentication) {
		t.Fatalf("cross-revision open error = %v", err)
	}
}
~~~

Run: `go test ./internal/discoveryqueue/... ./internal/discoverycheckpoint ./internal/discoverylimit/... -count=1`

Expected: FAIL because durable queue/checkpoint/limiter are absent.

- [ ] **Step 2: Implement exact HA claim and fenced state transitions**

`Claim` uses one serializable transaction and `FOR UPDATE SKIP LOCKED`, filters supported Provider kinds, `not_before<=now`, source/revision eligibility and persisted capacity. It generates 32 random bytes, returns raw token once, stores its SHA-256, sets owner/lease/heartbeat sequence and increments epoch. Reclaim only expired leases. `Heartbeat` requires token hash+epoch+owner+strict sequence+live source/gate/revision; maximum extension is 30s.

`Delay` atomically records bounded stable reason and `not_before`, releases capacity and clears lease fields. `Complete/Fail` require current fence and terminal credential-cleanup proof; they clear lease/capacity and freeze terminal run. A matching terminal replay is idempotent; any other fence/result hash is rejected.

- [ ] **Step 3: Implement atomic page/checkpoint and persisted rate/backpressure**

`ApplyPage` transaction order: lock run/source/revision; verify fence, gate, revision/digest, page sequence and checkpoint-before; call scoped Reconciler; seal checkpoint outside SQL but authenticate exact AAD; persist ciphertext/key ID/hash/version and page digest; insert safe audit/outbox; commit. A crash before commit changes nothing; after commit replay returns the same result. Checkpoint key rotation reads previous key IDs but every new page writes current key.

Limiter defaults come from immutable Source Profile and are clamped by server maxima. Persist active slots and next token time using source row/CAS so two replicas cannot exceed source/Workspace/provider limits. Queue depth beyond 10,000 runs/Workspace rejects new sync with `SOURCE_BACKPRESSURE`; no run is silently dropped. Provider `Retry-After` max 60s and exponential transport backoff max 15m are persisted.

- [ ] **Step 4: Verify PostgreSQL failover behavior and commit**

Run:

~~~bash
gofmt -w internal/discoveryqueue internal/discoverycheckpoint internal/discoverylimit
go test -race ./internal/discoveryqueue/... ./internal/discoverycheckpoint ./internal/discoverylimit/... -count=1
TEST_DATABASE_URL="$TEST_DATABASE_URL" \
  go test -race ./internal/discoveryqueue/postgres ./internal/discoverylimit/postgres -run Integration -count=1
~~~

Expected: PASS for concurrent claims, lease expiry/reclaim, stale fence at every boundary, crash-before/after-commit, checkpoint tamper/rotation, global limit across replicas, 429 delay, queue overflow and PostgreSQL reconnect.

~~~bash
git add internal/discoveryqueue internal/discoverycheckpoint internal/discoverylimit
git commit -m "feat(assetdiscovery): add fenced discovery queue"
~~~

### Task 28: Real discovery-worker production constructor and fail-closed provider runtime

**Files:**
- Create: `internal/discoveryworker/worker.go`
- Create: `internal/discoveryworker/worker_test.go`
- Create: `internal/discoveryworker/registry.go`
- Create: `internal/discoveryworker/registry_test.go`
- Create: `internal/discoveryworker/production.go`
- Create: `internal/discoveryworker/production_test.go`
- Create: `cmd/discovery-worker/main.go`
- Create: `cmd/discovery-worker/main_test.go`
- Create: `cmd/discovery-worker/config.go`
- Create: `cmd/discovery-worker/production.go`
- Create: `cmd/discovery-worker/production_test.go`
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`

**Interfaces:**
- Produces `discoveryworker.New(Dependencies) (*Worker,error)` and `cmd/discovery-worker.newProduction(Config) (*Worker,error)`.
- Registry contains exact adapters `CSV_IMPORT`, `CONTROL_PLANE_API`, `EXTERNAL_CMDB/CMDB_CATALOG_V1`, `VSPHERE_VCENTER_V1`, `PROXMOX_VE_V1`, `OPENSTACK_NOVA_V2_1`, `AWS_EC2_V1`, `AZURE_COMPUTE_V1`, `GCP_COMPUTE_V1`.
- Production constructor uses PostgreSQL Queue/Reconciler, secure Source Profile resolver, workload Credential/Trust resolver, checkpoint keyring, metrics and mTLS workload identity; no fake fallback exists.

- [ ] **Step 1: Write failing production dependency and secret-boundary tests**

~~~go
func TestProductionConstructorFailsClosedForEveryMissingDependency(t *testing.T) {
	valid := validProductionDependencies(t)
	for _, mutate := range []func(*Dependencies){
		func(d *Dependencies) { d.Queue = nil },
		func(d *Dependencies) { d.Reconciler = nil },
		func(d *Dependencies) { d.RuntimeResolver = nil },
		func(d *Dependencies) { d.CredentialResolver = nil },
		func(d *Dependencies) { d.Checkpoints = nil },
		func(d *Dependencies) { d.Registry = nil },
	} {
		candidate := valid.Clone()
		mutate(&candidate)
		if _, err := New(candidate); err == nil {
			t.Fatal("constructor accepted missing production dependency")
		}
	}
}

func TestDiscoveryWorkerRunPayloadHasNoSensitiveTransportFields(t *testing.T) {
	assertNoExportedFields(t, discoveryqueue.Claim{}, "Endpoint", "URL", "Credential", "Secret", "Token", "PEM", "Header", "Body", "Cursor")
}
~~~

Run: `go test ./internal/discoveryworker ./cmd/discovery-worker -count=1`

Expected: FAIL because Worker and production constructor do not exist.

- [ ] **Step 2: Implement one fenced run loop with terminal cleanup**

For every claim:

1. revalidate workload identity, Scope, source, exact revision/profile/gate and fence;
2. decrypt checkpoint through keyring and resolve non-serializable RuntimeBinding;
3. open the opaque CredentialReference for this source/revision/lease only;
4. for validation, call fixed `Validate`; for discovery, call `Discover` page-by-page;
5. before and after every network call heartbeat and revalidate fence/gate;
6. DLP/schema/budget check, then `ApplyPage` with current fence;
7. on Retry-After call fenced Delay; on ambiguity stop, degrade/suspend gate and never guess/retry side effects;
8. close/zero runtime, credential/session and provider response buffers;
9. persist cleanup proof, then Complete/Fail.

Panic recovery only performs cleanup/failure recording and process health degradation; it cannot mark success. Context cancellation stops new claims and gives current runs at most one lease interval to clean up. Unsupported provider closes only its source gate with `SOURCE_PROVIDER_UNAVAILABLE`.

- [ ] **Step 3: Assemble the real binary without production fake branches**

`cmd/discovery-worker` requires PostgreSQL DSN file, workload identity certificate/key file, CA file, secure source-profile manifest file, credential resolver socket, checkpoint keyring file, metrics private bind and worker ID. Files must be absolute, owner-only where secret-bearing, symlink-safe and loaded through existing secure bootstrap patterns. Startup verifies migrations through 000015, manifest digest/signature, registry completeness, mTLS identity, DB time and dependency health before readiness.

The binary does not import `internal/*/memory`, testdata, MSW, Control Plane handler or model/LLM packages. Add AST/import tests proving Provider SDK packages are reachable only from `cmd/discovery-worker` production graph and never from `cmd/control-plane`.

- [ ] **Step 4: Verify binary, race, shutdown, and commit**

Run:

~~~bash
gofmt -w internal/discoveryworker cmd/discovery-worker internal/config
go test -race ./internal/discoveryworker ./cmd/discovery-worker ./internal/config -count=1
go build ./cmd/discovery-worker
go test ./cmd/control-plane ./cmd/discovery-worker -run 'Production|Boundary|Secret' -count=1
~~~

Expected: PASS; missing/stale configuration fails before ready, shutdown cleans credentials/leases, Control Plane has no Provider network/secret dependency and no test fake is production-reachable.

~~~bash
git add internal/discoveryworker cmd/discovery-worker internal/config/config.go internal/config/config_test.go
git commit -m "feat(assetdiscovery): assemble production discovery worker"
~~~

### Task 29: Multi-provider HA drills, final gate matrix, telemetry, and E2E evidence

**Files:**
- Create: `internal/discoveryworker/metrics.go`
- Create: `internal/discoveryworker/metrics_test.go`
- Create: `scripts/verify-discovery-worker-ha.sh`
- Create: `scripts/verify-asset-source-provider-matrix.sh`
- Create: `docs/operations/asset-sources/discovery-worker.md`
- Create: `docs/operations/asset-sources/provider-gates.md`
- Create: `web/e2e/source-provider-gates.spec.ts`
- Modify: `Makefile`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Produces low-cardinality metrics `asset_source_claims_total{provider,result}`, `asset_source_pages_total{provider,result}`, `asset_source_backpressure_total{provider,reason}`, `asset_source_fence_rejections_total{boundary}`, `asset_source_gate_status{provider,status}`, `asset_source_checkpoint_age_seconds{provider}`.
- Produces signed provider acceptance matrix keyed by exact Provider profile/revision; missing providers remain explicitly `UNAVAILABLE`.
- HA scripts consume only test/lab binding IDs from environment and never print their values.

- [ ] **Step 1: Write failing provider-matrix and metric-cardinality tests**

~~~go
func TestProviderMatrixNeverTreatsFamilyAsSingleGate(t *testing.T) {
	matrix := NewProviderMatrix()
	matrix.Accept(validReceipt("AWS_EC2_V1"))
	if matrix.Status("AWS_EC2_V1") != "AVAILABLE" || matrix.Status("AZURE_COMPUTE_V1") != "UNAVAILABLE" {
		t.Fatalf("matrix = %#v", matrix)
	}
	for _, forbidden := range []string{"tenant_id", "workspace_id", "source_id", "external_id", "subject", "endpoint"} {
		if strings.Contains(gatherMetrics(t), forbidden) {
			t.Fatalf("metrics contain %s", forbidden)
		}
	}
}
~~~

Run: `go test ./internal/discoveryworker -run 'ProviderMatrix|Metrics' -count=1`

Expected: FAIL because acceptance matrix/metrics are missing.

- [ ] **Step 2: Implement exact coverage and fail-closed matrix**

Matrix rows are:

~~~text
MANUAL                         -> governed Asset API, no Worker gate
CSV_IMPORT/CSV_RFC4180_V1      -> Phase 1 gate
CONTROL_PLANE_API/API_BATCH_V1 -> Phase 1 gate
EXTERNAL_CMDB/CMDB_CATALOG_V1  -> Phase 1 gate
VSPHERE/VSPHERE_VCENTER_V1     -> Phase 1 gate
PROXMOX/PROXMOX_VE_V1          -> Phase 1 gate
OPENSTACK/OPENSTACK_NOVA_V2_1  -> Phase 1 gate
CLOUD_PROVIDER/AWS_EC2_V1      -> Phase 1 gate
CLOUD_PROVIDER/AZURE_COMPUTE_V1-> Phase 1 gate
CLOUD_PROVIDER/GCP_COMPUTE_V1  -> Phase 1 gate
KUBERNETES_OPERATOR            -> Phase 3, UNAVAILABLE here
AWX_INVENTORY                  -> Phase 5, UNAVAILABLE here
~~~

Each Phase 1 row requires current validation, real protocol, negative, DLP, provenance, incremental checkpoint, delete/recovery, rate/backpressure, credential cleanup, two-replica HA/fence and real non-production canary receipts. Receipt expiry/drift changes only that row to unavailable/suspended. UI and API return the same orthogonal status/reason/evidence timestamps.

- [ ] **Step 3: Execute kill/failover/backpressure and full provider E2E**

`verify-discovery-worker-ha.sh` starts two real Worker processes and PostgreSQL, queues validation and discovery for every CI protocol provider, kills the lease owner during provider read and after page commit, expires the lease, verifies one reclaim/epoch increment, no duplicate Observation, no stale checkpoint commit, terminal credential cleanup and correct gate. It restarts PostgreSQL, saturates source/workspace/provider limits and proves durable Retry-After/queue rejection/recovery.

Run:

~~~bash
go test -race ./internal/discoveryworker ./internal/discoveryqueue/... ./internal/assetsource/... -count=1
scripts/verify-discovery-worker-ha.sh
scripts/verify-asset-source-provider-matrix.sh
corepack pnpm@10.34.0 --dir web test:e2e -- --grep "source provider gate|source failover"
go build ./cmd/discovery-worker
git diff --check
~~~

Expected: all CI protocol providers pass positive/negative/HA; lab-only canaries are verified by signed receipts; `KUBERNETES_OPERATOR` and `AWX_INVENTORY` remain visibly unavailable; no duplicate mutation, leaked secret or false-green family gate exists.

- [ ] **Step 4: Commit**

~~~bash
git add internal/discoveryworker/metrics.go internal/discoveryworker/metrics_test.go \
  scripts/verify-discovery-worker-ha.sh scripts/verify-asset-source-provider-matrix.sh \
  docs/operations/asset-sources/discovery-worker.md \
  docs/operations/asset-sources/provider-gates.md web/e2e/source-provider-gates.spec.ts \
  Makefile .github/workflows/ci.yml
git commit -m "test(assetdiscovery): prove provider ha and gates"
~~~
