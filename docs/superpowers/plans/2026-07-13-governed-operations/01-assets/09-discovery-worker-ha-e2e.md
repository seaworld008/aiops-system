# Discovery Worker, HA Fencing, Backpressure, and Provider Acceptance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 创建真实 `cmd/discovery-worker`、PostgreSQL HA queue/lease/fence、加密 checkpoint、持久限流/背压与全 Provider 生产验收门，使 Source 控制面与发现数据面形成可故障转移的闭环。

**Architecture:** Control Plane 只创建不可变 Source Revision 和 durable Run；Discovery Worker 通过 PostgreSQL `FOR UPDATE SKIP LOCKED` 领取 exact source/revision/gate 任务，使用单调 fence epoch/token 在 validation、runtime resolve、credential open、provider call、page reconcile、checkpoint、heartbeat 和 complete 边界复验。Task 28A attempt runtime/credential 只在 Worker 内存；vSphere 若要跨 Run 保持 PropertyCollector session/filter，只能由 Task 21B0 单独批准的 resident authority 持有，绝不能降级为 Worker checkpoint/cache。页结果经 Schema/DLP 后与加密 checkpoint 在一个事务提交。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4、pgx v5、AES-256-GCM、mTLS workload identity、existing `workerbootstrap`/`securemanifest`、Prometheus client_golang 1.23.2。

## Global Constraints

- Task 28A provider-neutral Worker core 只消费已合并 PageCommitter/Queue/Checkpoint/CleanupBroker/Limiter，不等待任一 Provider 包；它必须先独立合并。每个 Provider 的 durable integration（External CMDB 为 [Task 18B](./06-source-external-cmdb.md#task-18b-external-cmdb-durable-reconciliation-and-lifecycle-integration)）随后只消费该稳定 seam。vSphere [Task 21A](./07-source-vsphere.md#task-21a-same-attempt-bounded-full-inventory-and-complete-snapshot-closure) 只能在同一个 Task 28A claim/`AttemptSession`/`BoundRuntime` 内完成全量分页，单独合并仍不是 durable incremental/HA integration。源文件核验又确认现有 Broker attempt map 仅在进程内，因此 Task 28B 单独交付 recoverable cleanup-session transport/same-attempt authority；Task 28C production constructor/registry 只能注册已经满足各自 durable contract 的 exact Provider row。
- 每个 Task 严格执行 `Red → Green → Refactor`：先运行并保留预期失败，再做最小生产实现，随后消除重复、复跑指定验证并按 Task 提交；不得跳过失败或弱化断言。
- 生产必须有独立 `cmd/discovery-worker`；不得把 Provider SDK、Credential Resolver 或目标网络客户端装入 Control Plane、通用 `cmd/worker` 或浏览器。
- 持久 Job/Run 只含 Source/Revision/Gate/Checkpoint digest、Scope、Run ID、预算、fence epoch/owner/token hash；不含 endpoint、Secret、raw Token、PEM、cursor plaintext、Header/Body 或 Provider 错误。完整 sealed `LeaseFence` 只由 Claim 返回到当前 Worker 内存，绝不进入 Job/Task/Batch/audit/log payload。
- Raw lease token 只存 Worker 内存，DB 仅存 SHA-256；每次 reclaim 必须 `fence_epoch+1` 且旧 fence 无法 heartbeat/reconcile/checkpoint/complete。
- Checkpoint 使用 AES-256-GCM；唯一 AAD 构造器与 typed `CheckpointAAD` 由 `internal/discoverycheckpoint` 拥有，并用 `FramedTupleV1("asset-source-checkpoint.v1",Tenant,Workspace,Source,Provider,Source definition revision,canonical revision digest,source definition digest,checkpoint key ID,Checkpoint version)` 的精确九字段顺序。key 只通过 workload secret binding 读取。持久 AAD 不含 gate revision/fence epoch/token，因为 checkpoint 必须跨 reclaim 和后续 Run 恢复且 Claim 不得制造 checkpoint 版本变更；每次 Open、Provider call、Reconcile、checkpoint 提交和 Complete 仍分别要求 exact live owner/token/epoch。Codec 必须有 golden bytes/hash、九字段逐项篡改、NULL/empty 和 key-rotation 测试。
- “Checkpoint 可跨 reclaim/Run 打开”只表示 sealed provider metadata 可验证，不表示第三方服务端 cursor/session 可重建。vSphere `ContinueRetrievePropertiesEx` token 只能由产生它的同一登录 session/同一 `PropertyCollector` 使用；`WaitForUpdatesEx` filter/version 也是该 session/collector 的服务端状态。vSphere checkpoint tuple/digest、Task 28B cleanup receipt 或新登录都不能成为 continuation authority。
- 数据库通过 `asset_source_limit_buckets` 与 append-only `asset_source_limit_permits` 分别持久每 Source/Workspace/Provider 的 token bucket 和 active permit/terminal receipt；`not_before`、queue depth 与 failure streak 仍属于 Queue/Source backpressure。进程内 semaphore 只是二次保护，不是授权事实。
- Validation Run 可消费 `VALIDATING` revision；Discovery/Import/Ingestion Run 与普通 `RequestSync` 仅可消费 exact `PUBLISHED + ACTIVE + AVAILABLE`，需要真实资格的 Profile 还必须在每个普通 admission/data-write boundary 重载 current unexpired gate evidence。Task 19A2a/19A2b/19A2c 后继依次建立 schema/domain、persistence/rechecks 与唯一 production lane 的 `QUALIFICATION` Run 是唯一 `PUBLISHED + ACTIVE + UNAVAILABLE` 例外，只经 fixed mTLS workload qualification lane 和同一个 Task 28A Worker loop 执行零 Catalog projection 的 Provider read/protocol/DLP/cleanup/HA proof；它不能被普通 claim predicate、browser 或 sync API创建。任何漂移停止并关闭影响的 provider/source gate。
- Validation Run 的 checkpoint 输入固定为空；它不得比较、解密或推进当前 published revision 的 Source checkpoint。Discovery/Import/Ingestion 才消费 exact current checkpoint；checkpoint-lineage-rollover 仅走 Pack 01 的受治理同一 Run 例外。
- Credential open/session cleanup 是 terminal 成功的必要证据。每个 attempt 先持久化 Broker-owned opaque UUID，再允许 open；Broker 持有真实 revoke/session handle，Run/API/日志永不携带。cleanup 未知不能把 run 写为成功并必须暂停 Source gate。Task 28B 的 handle/proof 只证明 exact Worker attempt cleanup；它不拥有 vSphere resident PropertyCollector session/filter，也不证明跨 Run continuity 或 no-orphan closure。
- `MANUAL` 不进 Worker；`KUBERNETES_OPERATOR` 由 Phase 3 注册；`AWX_INVENTORY` 由 Phase 5 固定 AWX 契约注册。未注册时都是 `UNAVAILABLE`，不得用通用 Provider 替代。
- 完成后进入 [10-overview-control-room.md](./10-overview-control-room.md)。

## Fast-build checkpoint/transaction ownership correction (2026-07-15)

The previous proposal to combine all Pack 02 Task 4 and Task 27 files into one `M1B-discovery-page-commit` is superseded because it creates a 21+ file XL Batch and a dependency cycle. M1B Source read and M1C `assetdiscovery`/`discoverysource` contracts are now merged. The safe remaining order is: M1D implements only the Checkpoint Codec；one later exact mutation Batch owns both the package-private PostgreSQL projection helper and `PageCommitter`；Queue ABI/PostgreSQL lifecycle、cleanup and limiter are frozen only with their first real consumer and then close in ownership-safe slices.

M1D has exactly two files: `internal/discoverycheckpoint/codec.go` and `codec_test.go`. It does not create `internal/discoveryqueue` or consume `LeaseFence`；existing `assetcatalog.LeaseFence` remains the exact alias of sealed `internal/leasefence.Fence` and is consumed unchanged by the later PageCommitter/Queue batches. This avoids freezing speculative Queue commands before their PostgreSQL state machine and cleanup consumers exist.

The complete M1D public ABI is fixed below and was merged by PR #44；fields and method signatures may not be widened in later implementation:

~~~go
var (
	ErrInvalidInput           = errors.New("checkpoint codec input invalid")
	ErrUnavailable            = errors.New("checkpoint codec unavailable")
	ErrAuthentication         = errors.New("checkpoint authentication failed")
	ErrSensitiveSerialization = errors.New("checkpoint codec sensitive value is not serializable")
)

const CheckpointEnvelopeVersion byte = 1

type CheckpointAAD struct {
	TenantID, WorkspaceID, SourceID, ProviderKind string
	CheckpointRevision                            int64
	CanonicalRevisionDigest, SourceDefinitionDigest string
	CheckpointKeyID                               string
	CheckpointVersion                             int64
}

type SealedCheckpoint struct {
	Envelope          []byte
	CheckpointKeyID   string
	CheckpointSHA256  string
	CheckpointVersion int64
}

func (value SealedCheckpoint) Clone() SealedCheckpoint

type ReplayIdentity struct {
	CheckpointKeyID string
	DigestSHA256    string
}

type InMemoryKeyring struct { /* opaque, sensitive, process-local */ }

func NewInMemoryKeyring(activeKeyID string, retained map[string][32]byte) (*InMemoryKeyring, error)
func (keys *InMemoryKeyring) ActiveKeyID() (string, error)
func (keys *InMemoryKeyring) Destroy()

type CheckpointCodec struct { /* opaque, process-local */ }

func NewCheckpointCodec(keys *InMemoryKeyring) (*CheckpointCodec, error)
func (codec *CheckpointCodec) Seal(ctx context.Context, aad CheckpointAAD, checkpoint discoverysource.Checkpoint) (SealedCheckpoint, error)
func (codec *CheckpointCodec) Open(ctx context.Context, aad CheckpointAAD, expectedProfile assetcatalog.ProfileCode, sealed SealedCheckpoint) (discoverysource.Checkpoint, error)
func (codec *CheckpointCodec) ReplayIdentity(ctx context.Context, aad CheckpointAAD, checkpoint discoverysource.Checkpoint) (ReplayIdentity, error)
~~~

`CheckpointAAD` is process-local and is the only owner of its byte representation. Its exact encoding remains Pack 01 `FramedTupleV1("asset-source-checkpoint.v1",TenantID,WorkspaceID,SourceID,ProviderKind,CheckpointRevision,raw CanonicalRevisionDigest,raw SourceDefinitionDigest,CheckpointKeyID,CheckpointVersion)`；UUID、Provider/code、positive integers and lowercase SHA-256 shapes are validated before crypto, and named digests are decoded to 32 raw bytes. `CheckpointAAD`、`InMemoryKeyring` and `CheckpointCodec` reject JSON/text/binary marshal/unmarshal and redact `String/GoString/LogValue/Format`；no public method returns raw AAD or key bytes.

`NewInMemoryKeyring` accepts only unique valid opaque key IDs and exact 32-byte AES-256 master keys, copies the retained set, requires the active ID to exist, and is the sole M1D test/bootstrap key source；production workload-secret loading remains outside M1D. `Destroy` zeroes all retained masters and makes every copy/Codec return `ErrUnavailable`. `ActiveKeyID` is safe metadata. The constructor input remains caller-owned and must be cleared by its caller after construction.

`Seal` requires `aad.CheckpointKeyID == ActiveKeyID` and obtains the profile/raw bytes only through M1C's bounded Checkpoint access. To preserve the already-frozen `discoverysource.MaxCheckpointCanonicalBytes == 65_507` against the database envelope maximum 65,536, raw canonical checkpoint bytes are the AES-GCM plaintext with no prefix. The 32-byte AEAD key is HKDF-SHA256(master, empty salt, `FramedTupleV1("asset-source-checkpoint-aead-key.v1",profile_code)`), GCM additional data is the exact nine-field `CheckpointAAD` encoding, and the persisted envelope is exactly `0x01 || fresh non-zero 12-byte nonce || ciphertext || 16-byte tag`；therefore its length is exactly `29 + len(raw checkpoint)`. The derived key and temporary raw bytes are always cleared. `SealedCheckpoint` contains only the four columns PageCommitter may persist；its hash is lowercase SHA-256 of the entire envelope, and it never enters Queue/API/audit/log payload.

`Open` requires the sealed key ID/version/hash to equal the exact AAD, selects that retained key, derives the AEAD key from `expectedProfile`, authenticates before returning any bytes, and rebuilds a new profile-bound opaque Checkpoint. Missing retained key、malformed envelope/hash、AAD/profile/version drift and GCM failure all return only `ErrAuthentication`, with zero plaintext and no wrapped detail. `ReplayIdentity` selects `aad.CheckpointKeyID`, derives a separate 32-byte HMAC key with HKDF-SHA256、empty salt and fixed info `asset-source-checkpoint-replay-key.v1`, and computes HMAC-SHA256 over the already-frozen `FramedTupleV1("asset-source-checkpoint-replay.v1",the same nine AAD fields,canonical checkpoint bytes)`；`SourceDefinitionDigest` already binds the exact Profile definition, so Replay does not append a second profile frame. It returns only safe key ID/digest and clears raw/subkey bytes. Master、AEAD and replay keys are never reused as one another.

Only `SealedCheckpoint` may cross the SQL persistence boundary and only `ReplayIdentity` may become a receipt comparison input. `CheckpointAAD`、keyring、Codec、raw checkpoint/AAD/key/subkey bytes are process-local. Context cancellation returns `ctx.Err()` before emitting output；invalid Seal/constructor input returns `ErrInvalidInput`, a destroyed/misconfigured active key path returns `ErrUnavailable`, and all Open/retained-key authentication failures collapse to `ErrAuthentication`. Errors never include IDs、digests、profile、envelope or crypto details.

The later Queue Batch must freeze its full method ABI together with the PostgreSQL state machine rather than in M1D. Persisted/serializable Queue commands and rows never contain a fence；the in-process `ClaimResult` is the sole Queue result allowed to carry the sealed `assetcatalog.LeaseFence`, and that result must itself reject serialization/logging. This distinction preserves Task 27's Claim handoff without creating a durable raw-token carrier.

The page mutation Batch first consumes [M1E0 corrective](./12-m1e0-relation-page-corrective.md)，then fast plan §12 指向的 [M1E 原子页提交任务包](./13-m1e-page-commit-transaction.md) with exactly five new files and one owner. `PageCommitter` is the sole owner of the serializable page transaction. It consumes the concrete next `discoverysource.Checkpoint` only through the existing process-local `discoverysource.Page`, seals it outside SQL with exact `CheckpointAAD`, then begins one transaction that locks and revalidates Run/Source/revision/fence/checkpoint-before, calls the package-private PostgreSQL projection helper, derives cursor-after from the sealed ciphertext, computes page/relation digests from server-owned facts, persists projection/ciphertext/key ID/hash/receipts/checkpoint CAS, revalidates the fence and commits once. Its public ABI、canonical semantic identity、empty relation page rule、error vocabulary、exact files and G2 evidence are defined only in that task pack and are not duplicated here.

The old Pack 02 sketch in which `Batch` supplies `CursorAfterHash/PageDigest` and `Repository.ReconcileBatch` commits independently remains superseded. The later mutation manifest must list the exact projection/PageCommitter files under one owner with no concurrent edits；it must not pull unrelated queue/cleanup/limiter files into that review unit. No raw checkpoint、fence、`pgx.Tx` or SQL handle crosses a public interface；projection cannot commit without checkpoint, checkpoint cannot commit without projection, and neither path may open a nested transaction.

Because AES-GCM sealing is randomized, receipt replay cannot depend only on a newly sealed ciphertext hash. `ApplyPage` first looks up `(Scope,Run,page sequence)` and verifies normalized item/relation/final semantics plus `HMAC-SHA256(replay_mac_key, FramedTupleV1("asset-source-checkpoint-replay.v1",the same nine typed CheckpointAAD fields,canonical checkpoint bytes))` using the receipt's persisted opaque key ID. `replay_mac_key` is a distinct 32-byte subkey derived from that retained checkpoint master key by HKDF-SHA256 with empty salt and fixed info `asset-source-checkpoint-replay-key.v1`；the AEAD key is never reused directly for HMAC and the derived subkey is cleared after use. This keyed identity excludes ciphertext randomness without persisting a guessable plaintext cursor digest；a different next checkpoint is an idempotency mismatch, and a missing retained key fails closed. An exact receipt returns the persisted result/checkpoint hash before fence admission or sealing. A fresh page seals once and reuses that exact envelope across bounded serialization retries；after an ambiguous commit it performs receipt lookup before any reseal. The final committed page digest still binds the actual persisted ciphertext hash.

This ordering is normative: receipt lookup and semantic/checkpoint replay verification happen before any seal or reseal. Only a confirmed new page may call `Seal`, exactly once；the resulting envelope is reused through bounded serialization retries. An ambiguous commit always returns to receipt lookup before any possible reseal.

---

## Frozen ownership and dependency order

当前主线已经分别合并 Checkpoint Codec、PageCommitter、Queue、CleanupBroker 和 Limiter。它们是后继 Worker 的稳定 `Consumes`，不是 Task 28 可重写的内部草稿。唯一依赖顺序为：

```text
M1D Checkpoint Codec + M1E PageCommitter + Task 27 Queue/Cleanup/Limiter
  -> Task 28A provider-neutral Worker core/claim-runtime seam（先合并）
  -> provider durable integrations that do not require a cross-Run resident cursor
  -> Task 28B recoverable cleanup-session transport/same-attempt authority
  -> Task 28C production constructor/registry/binary（只注册已闭合 rows）
  -> External CMDB Task 19A → Task 19A2a → Task 19A2b → Task 19A2c
  -> Task 29A provider-neutral two-worker HA receipt/metrics
  -> External CMDB Task 19B per-source canary/evaluator/atomic gate
  -> Task 29B signed final provider matrix/E2E/CI

vSphere-specific closed lane:
Task 28A
  -> Task 21A same-attempt full snapshot（可独立合并，能力仍关闭）
Task 21A + Task 28B
  -> Task 21B0 PropertyCollector session-continuity authority
  -> Task 21B cross-Run delta/leave/HA resume
  -> Task 28C vSphere registry row
  -> Task 29A vSphere-specific HA evidence
  -> Task 22 vSphere gate/canary
  -> Task 29B vSphere matrix row
```

后继 Batch 只能从最新 `origin/main` 读取已合并 `Produces`。Task 18B 不得读取 Task 28A 未提交文件；Task 28B 不得读取 Task 18B 未合并 descriptor；Task 28C 不得读取 Task 28B 或其他 Provider 未合并实现。Source Gate 后半段对 External CMDB 严格为 `Task 28C → Task 19A → Task 19A2a → Task 19A2b → Task 19A2c → Task 29A → Task 19B → Task 29B`。vSphere 是显式 closed 分支：Task 21A 不是 Task 28C 可消费的 durable descriptor；Task 21B0/21B 未真实完成前，Task 28C 必须不注册 vSphere，Task 22/29A/29B 也不得合成 vSphere availability evidence。Task 28C 可为其他已闭合 Provider 先合并；若其先合并，后续 vSphere registry extension 必须另行冻结不重叠 exact files，不能借 Task 21A 自动出现。

每个 Batch 都由新窗口独立真实 G2/PR/merge，Task 29A 不消费 canary、不写 gate，Task 19B 不拥有 HA runner/metrics，Task 29B 不重建 gate/canary/HA。源文件核验发现 process-local Broker 不能满足 replacement Worker cleanup 后，原来的“Task 28A core + Task 28B production”最小拆分增加一个独立 transport Batch，并把 production 顺延为 Task 28C；这仍未解决 vSphere PropertyCollector continuity。后续因 canary↔AVAILABLE、Task 19B↔旧 Task 29 证据循环、46-file context risk 与 23-file persistence L Batch，最终拆成 12-file Task 19A2a、11-file Task 19A2b、19-file Task 19A2c、Task 29A 与 Task 29B，三段 Source Gate files 零重叠。

### Task 27: Merged durable queue, cleanup, checkpoint, and limiter primitives

**Stable files and owners:**

| Stable `Produces` | Exact files | Merge owner |
|---|---|---|
| Checkpoint Codec | `internal/discoverycheckpoint/codec.go`、`codec_test.go` | M1D / PR #44 |
| Atomic PageCommitter/projection | `internal/discoverysource/page_commit.go`、`page_commit_test.go`、`internal/assetcatalog/postgres/page_committer.go`、`page_projection.go`、`page_committer_integration_test.go` | [M1E](./13-m1e-page-commit-transaction.md) / PR #53；不是 Task 27 owner |
| Queue ABI/PostgreSQL lifecycle | `internal/discoveryqueue/queue.go`、`internal/discoveryqueue/postgres/repository.go`、`repository_test.go`、`repository_integration_test.go` | Task 27 Queue slice / PR #55 |
| Process-local CleanupBroker boundary | `internal/discoverycleanup/broker.go`、`broker_test.go` | Task 27 cleanup slice / PR #57；attempt map 不跨进程，不是 HA recovery transport |
| Limiter ABI/PostgreSQL lifecycle | `internal/discoverylimit/limiter.go`、`internal/discoverylimit/postgres/limiter.go`、`limiter_integration_test.go` | Task 27 limiter slice / PR #64 |

**Interfaces（冻结，不得扩宽）:**

- Produces `Queue.Claim/Reclaim/ReclaimFinalizing/ReapDrifted/CancelIneligible/Heartbeat/AdvanceStage/ReserveCleanupAttempt/RecordCleanup/Delay/ProposeValidationResult/PrepareFailureIntent/BeginCheckpointLineageRollover/Complete/Fail`；process-local non-serializable `ClaimResult` 是唯一可携带 sealed `LeaseFence` 的 Queue value，raw token 永不进入 durable command/row。
- Produces process-local `CleanupBroker.OpenAttempt/RevokeAttempt/VerifyCleanupProof`；only the Broker owns the revocation/session handle，Queue 只保存 random opaque attempt UUID/epoch 并验证 signed cleanup proof。新的 Broker 实例对旧 attempt 直接 `RevokeAttempt` 会 `ErrAttemptNotFound`；跨 Worker recovery 由 Task 28B 唯一拥有。
- Produces `CheckpointCodec.Seal/Open/ReplayIdentity` 和 `Limiter.Acquire/Release/Delay` bound to exact Source/Workspace/Provider。
- Consumes twelve-table `000015` schema，including immutable `asset_source_revision_authorities`、`asset_source_limit_buckets` and `asset_source_limit_permits`；Limiter Go runtime 不创建 migration。
- `PageCommitter.ApplyPage` 由 M1E 唯一拥有。Task 27/28 只能调用，不得创建第二 PageCommitter、projection SQL、receipt owner 或 nested transaction。

**Classification:** C0 = fence/receipt/checkpoint/cleanup/permit truth；C1 = Queue/Cleanup/Limiter durable slices；C2 = none。上述代码已分别以 `BUILT_CLOSED` 合并，但这不等于旧 Task 27 的两 Worker/HA/restart/recovery 最终 checkbox 已完成。

**Retained RED evidence:** reclaim increments the persisted epoch and invalidates the old sealed fence；cross-Scope/revision checkpoint open authenticates fail closed；Validation never reads or changes the published checkpoint；cleanup/failure intent survives crashes；attempt/open/revoke/terminal response loss returns the exact persisted attempt/proof/receipt；cleanup uncertainty preserves the sealed work result and closes the Source. These REDs were closed by the independent merge slices above. The superseded pre-merge code sketch is removed because it exposed fields that are not part of the frozen `ClaimResult` ABI；future tests must consume the actual merged types rather than recreate that sketch.

**Frozen Queue/Cleanup behavior:**

`Claim` uses one serializable transaction and `FOR UPDATE SKIP LOCKED`, filters `QUEUED|DELAYED` supported Provider Runs, `not_before<=now`, run-kind-specific source/gate/revision/checkpoint eligibility and persisted capacity. It generates 32 random bytes, returns a sealed process-local fence once, stores only token SHA-256, sets owner/lease/heartbeat sequence, increments epoch and moves stage to `VALIDATING` or `READING`. Validation binds its `VALIDATING` revision but neither compares nor returns the published Source checkpoint. Normal reclaim accepts only an expired `RUNNING` lease whose Source remains exact eligible. If the old attempt is `NOT_OPENED|NO_CREDENTIAL`, it may continue under the new fence；if an opaque attempt is `PENDING`, reclaim sets `CLEANING_UP`, persists/uses a bounded `TRANSPORT_BACKOFF` delay intent and returns cleanup-only work that must revoke then delay before a fresh claim—no Provider/checkpoint/page admission is available. If cleanup is already `REVOKED|NO_CREDENTIAL`, reclaim verifies `ATTEMPT_CLEANED` and executes the previously persisted delay intent；it never resumes Provider work. `ReclaimFinalizing` accepts only an expired `FINALIZING` row, increments the fence and returns cleanup-only work；an already-clean receipt goes directly to the persisted work-result `Complete|Fail`. `CancelIneligible` serializably cancels no-lease `QUEUED|DELAYED` rows after disable/drift and, for an exact Validation Run, atomically rejects the still-bound Revision with stable proof. For an expired drifted `RUNNING` row, `ReapDrifted` advances the fence without Provider/checkpoint access and fails directly only if no credential was opened；otherwise it enters cleanup-only work and requires Broker revocation before terminal failure. `Heartbeat` repeats run-kind-specific exact facts plus token/epoch/owner/strict-sequence：Validation verifies only its empty checkpoint shape，data Runs verify the current Source checkpoint. Maximum extension is 30s. The current holder may fail/clean up before expiry after drift but cannot extend.

`ReserveCleanupAttempt` must commit a random opaque attempt UUID plus the current fence epoch before `CleanupBroker.OpenAttempt` may resolve/open credentials or sessions. It is idempotent for exact `(run,fence epoch)`；a lost response is retried to retrieve the same UUID, never to allocate another. The current process-local Broker creates at most one logical session for its local attempt state and `RevokeAttempt(attempt_id)` returns one idempotent signed proof. If Open succeeds but its response is lost/ambiguous, Worker must not Open again for work, create a new attempt or make a Provider call；it persists `TRANSPORT_BACKOFF`, revokes the known attempt, records proof and delays. `RecordCleanup` accepts only a signed Broker proof bound to the same Run/attempt/epoch and writes an append-only `ATTEMPT_CLEANED` receipt；the current Run summary is not the history owner. Replacement Worker 不能对新的 process-local Broker 只传 opaque UUID 就声称可 revoke；它必须从 Queue cleanup-only claim 取得 exact `RunCoordinates + CleanupAttempt`，经 Task 28B fixed mTLS transport recovery-open 同一外部 session，再由本地 Broker handle revoke。该路径不得解析 Provider runtime/checkpoint，也不得携带 endpoint、credential 或其他 secret payload。`REVOKED|NO_CREDENTIAL` are clean；missing/invalid/`UNCERTAIN` proof fails the Run and sets gate `SUSPENDED`.

`Delay` requires the current attempt's clean proof, then atomically transitions cleanup-only `RUNNING→DELAYED`, consumes the persisted closed reason `PROVIDER_RETRY_AFTER|TRANSPORT_BACKOFF` and bounded `not_before`, releases capacity and clears the lease while preserving committed page/checkpoint/count progress plus the immutable attempt receipt. The next claim creates a new fence and may clear the current cleanup summary to `NOT_OPENED` only after verifying that receipt. `ProposeValidationResult` persists exact revision/canonical/binding/outcome/proof digest as `VALIDATION_PROOF` and transitions `RUNNING→FINALIZING`；the invalid outcome proposes `FAILED`, never `PARTIAL`. Any other fatal path must call fenced `PrepareFailureIntent` **before cleanup** to persist stable code/digest and transition `RUNNING→FINALIZING/CLEANING_UP`；it cannot overwrite an existing data/validation result. `Complete/Fail` accept a safe terminal command containing Run ID、work-result/intent digest and cleanup digest. They first look up the immutable `TERMINAL_COMMITTED` receipt；an exact replay returns read-only even after the first call destroyed every fence copy, while any changed tuple is rejected. Only the first terminal mutation requires current fence, writes the receipt and atomically updates the bound Revision validation state. If cleanup is `UNCERTAIN` after a success result, `Fail` preserves that result and writes the sole `CLEANUP_UNCERTAIN` override/digest, producing `FAILED + SUSPENDED` and no success pointer. Both terminal methods release capacity, destroy the raw token and freeze terminal Run while preserving owner/token-hash/epoch/heartbeat evidence.

**Frozen cross-component behavior:**

Provider discovery returns the Pack 05 closed `DiscoverOutcome` with concrete `Page|Delay`, never a struct in which retry and data coexist. `Delay{Reason=PROVIDER_RETRY_AFTER,RetryAfter}` requires `0 < RetryAfter <= 60s` and by construction has no Items、Relations、next checkpoint or final flags. `Page` has no delay and contains the page/checkpoint/final fields. Transport ambiguity is created only by the Worker as Queue `TRANSPORT_BACKOFF` intent（exponential, max 15m）after stopping Provider calls and before cleanup. Neither delay path calls `ApplyPage` or changes checkpoint/counts.

Pack 05 `Checkpoint`/`BoundRuntime` raw access remains process-local and call-site allow-listed：Provider code may decode only temporary callback bytes into a private typed cursor；Worker and `PageCommitter` treat the cursor as opaque and only the checkpoint codec seals/opens canonical bytes. No raw checkpoint/runtime value enters Queue、job、Temporal、audit、receipt、error or log. Validation likewise remains three separate closures：the Worker first validates and recomputes the immutable Provider `ValidationProof` digest，then independently records Broker cleanup/`ATTEMPT_CLEANED`，and only terminal `Complete|Fail` combines the already-sealed validation work-result digest with the cleanup digest. No later cleanup fact may rewrite the Provider proof.

`ApplyPage(ctx, fence, PageCommitCoordinates, Page)` outer order is fixed：perform exact persisted receipt lookup and semantic/keyed-checkpoint replay verification before any live-fence admission or seal；an exact receipt returns its persisted result. Only after confirming a genuinely new page may it verify the process-local sealed fence and call checkpoint `Seal` exactly once. It then starts the bounded serializable SQL attempt：lock Run/Source/Revision；repeat the receipt guard；verify gate/revision/digest、stage、page sequence and checkpoint-before；call M1E package-private projection helper, which derives Source revision and Catalog acceptance time rather than accepting them from Provider items；revalidate the same live fence with database `clock_timestamp()`；persist that already-sealed ciphertext/key ID/hash/version、page digest and safe receipt；a final page persists `DATA_PROJECTION` and transitions only to `FINALIZING/CLEANING_UP`；commit. A serialization retry reuses the exact same sealed envelope；an ambiguous commit returns to receipt lookup before any possible reseal. Claim/reclaim never decrypt-and-reseal or bump checkpoint version. A crash before commit changes nothing；after commit an exact replay returns the persisted result even when final cleanup has already made the Run terminal. Checkpoint key rotation reads previous key IDs but every confirmed new page writes the current key.

`BeginCheckpointLineageRollover` is available only to Profiles with a closed expiry reason and a verified Adapter evidence digest. It binds that proof to the exact current fence/Run/revision/checkpoint, degrades the gate and leaves the old checkpoint untouched；the same Run must then emit an authoritative full-snapshot `Page` whose first commit CASes from the old hash into a new lineage. No API/Worker can clear、rewind or create a side Run. Recoverable Provider/transport failure cleans and delays this same Run. Only terminal `SUCCEEDED + effective complete snapshot` seals rollover and restores the gate；any terminal failure or cleanup/checkpoint uncertainty suspends it and requires a newly validated/published revision.

Limiter defaults come from the exact immutable Source Profile and are clamped by fixed server maxima. `Acquire/Release/Delay` runs in one `SERIALIZABLE READ WRITE` transaction, locks the three exact bucket rows in fixed `SOURCE→WORKSPACE→PROVIDER` order, counts only unexpired ACQUIRE rows without a terminal receipt, and advances each bucket by CAS over `next_token_at/last_receipt_id/version`. The bucket table contains no Queue lease/fence、Source backpressure or aggregate active counter；active slots are the normalized permit ledger itself.

`asset_source_limit_permits` is append-only. ACQUIRE is the permit identity and binds exact Scope、Source/Run/Provider、the three canonical bucket identities、request ID、command SHA、receipt SHA、acquired time and a positive database-bounded TTL；RELEASE/DELAY/EXPIRE repeats that immutable tuple and appends the sole terminal receipt for the permit. Exact request+command replay after response loss returns the stored receipt without another token/slot；changed command digest, second terminal receipt, cross-bucket/source/run/provider drift or stale acquire fails closed. Crash recovery appends EXPIRE rather than deleting or rewriting the acquire. No advisory lock、process memory、`asset_sources.next_allowed_at/consecutive_failures` or Queue row may substitute for either Limiter table.

Queue depth beyond 10,000 runs/Workspace rejects new sync with `SOURCE_BACKPRESSURE`; no run is silently dropped. Provider `Retry-After` max 60s and exponential transport backoff max 15m are persisted by Queue/Source backpressure and are not Limiter bucket truth.

**Retained G2 regression gate:**

Run:

~~~bash
gofmt -w $(rg --files internal/discoveryqueue internal/discoverycheckpoint internal/discoverylimit internal/discoverycleanup -g '*.go')
go test -race ./internal/discoveryqueue ./internal/discoverycheckpoint \
  ./internal/discoverylimit ./internal/discoverycleanup -count=1
test -n "${AIOPS_TEST_POSTGRES_DSN:-}"
go test -race ./internal/discoveryqueue/postgres \
  ./internal/discoverylimit/postgres -run Integration -count=1
~~~

`AIOPS_TEST_POSTGRES_DSN` 缺失或任何 integration test Skip 都不能记为 PostgreSQL PASS。Expected: concurrent claims、lease expiry/reclaim、stale fence、exact attempt/terminal receipt recovery、checkpoint tamper/rotation、三 bucket concurrency 和 response-loss replay 继续通过。两 Worker、进程/数据库 restart、HA takeover 和完整 recovery 保留到 Task 29A/G3；不得把单进程 G2 写成这些证据已完成。

### Task 28A: Provider-neutral Worker core and claim-runtime seam

**Batch:** C0/C1，1–2 日，必须先于任一 provider durable integration 合并。

**Exact files:**

- Create: `internal/discoveryworker/worker.go`
- Create: `internal/discoveryworker/worker_test.go`
- Create: `internal/discoveryworker/claim_runtime.go`
- Create: `internal/discoveryworker/claim_runtime_test.go`

源文件核验时 `internal/discoveryworker/` 与 `cmd/discovery-worker/` 均不存在。该最小 Batch 只建立通用 core 与 process-local seam；不创建 registry、production constructor、binary、config、metrics 或 Provider integration test。

**Consumes（只读已合并）:**

- Task 27 frozen `discoveryqueue.Queue`、`ClaimResult`、`CleanupBroker`、`Limiter`。
- M1E `discoverysource.PageCommitter`、M1D `CheckpointCodec`。
- M1C `discoverysource.Provider`、`BoundRuntime`、`Checkpoint`、closed concrete `Page|Delay` 和 validation proof。

**Produces:**

- `discoveryworker.New(Dependencies) (*Worker, error)` 和一个 provider-neutral `Worker` run/stop boundary。
- `ClaimRuntimeResolver` 与 opaque process-local `ClaimRuntime` seam：Provider path 固定为 `Queue.ReserveCleanupAttempt(exact Run/epoch) → CleanupBroker.OpenAttempt(exact request) → resolver.ResolveOpenedAttempt(same AttemptSession + expected RuntimeBinding) → Provider`。resolver 只能取得由该次 `SessionOpener.OpenSession` 创建并与同一 Broker-owned `SessionHandle` 共享 attempt cell 的 `BoundRuntime`；runtime view 的 close/clear 与 handle 的 revoke/destroy 清理同一 cell，但只有 Broker revoke/proof 可证明 cleanup。resolver 不得独立解析/打开第二份 credential、endpoint 或 session。`ClaimRuntime` 在内部不可变绑定 Run/attempt/epoch/runtime binding，并只向 core 提供 same-attempt Provider、opened checkpoint/empty validation checkpoint、immutable limits 与 non-serializable `BoundRuntime`。
- 唯一通用状态机：claim-mode dispatch、heartbeat/fence revalidation、Limiter acquire/terminal、上述 exact ordered open/resolve、Provider Validate/Discover、PageCommitter call、persisted next intent、same-attempt Broker cleanup/proof、Queue Delay/Complete/Fail 和 bounded shutdown。`CLEANUP_ONLY|TERMINAL` 只执行 exact recovery-open/revoke/proof path，绝不调用 resolver 或 Provider。

Core 必须直接调用已合并 interfaces；不得复制 Queue stage/gate enums、lease/fence matching、Limiter bucket math、cleanup proof、PageCommitter replay/SQL 或 Provider-specific pagination。`ClaimRuntimeResolver` 只是 Broker attempt-bound 的受信 process view seam，不是新的 registry、credential store 或 transport；runtime view 的 close/clear 不能替代 Broker `RevokeAttempt`，terminal/delay 只能接受同一 attempt 的 verified cleanup proof。

**Classification:**

- **C0:** process-local sensitive boundary、stale fence、cleanup-before-terminal/delay、receipt replay、panic/cancel fail closed。
- **C1:** provider-neutral claim → work → cleanup → terminal loop。
- **C2:** 无；所有 Provider import/registration 留给 provider Batch/Task 28C。

**RED → GREEN:**

- [ ] RED：任一 Queue/PageCommitter/Limiter/CleanupBroker/Checkpoint/ClaimRuntime dependency 缺失时 `New` fail closed；production core 无 fake fallback。
- [ ] RED：`ClaimRuntime`、`ClaimResult`、fence/checkpoint/runtime 的 JSON/text/binary/log/format 与 forbidden exported-field tests 全部关闭。
- [ ] RED：`PROVIDER|CLEANUP_ONLY|TERMINAL` 三种 claim mode 各走唯一合法路径；cleanup-only/terminal 不解析 Provider runtime 或 checkpoint。
- [ ] RED：未先成功 `ReserveCleanupAttempt → OpenAttempt` 时 resolver 拒绝且 Provider 零调用；resolver 不得自行触发 credential/session open，cleanup-only/terminal 永不调用 resolver。
- [ ] RED：resolver request、`AttemptSession.Attempt()`、Queue persisted `CleanupAttempt`、expected `RuntimeBinding` 或 returned `ClaimRuntime` 的 Run ID/attempt ID/attempt epoch/Source revision/binding digest 任一漂移均 fail closed；同一 opener/session/runtime cell 与 Broker handle/proof 不一致也拒绝，不能用另一 attempt/session 的 proof 关闭实际 Provider runtime。
- [ ] RED：Validation 使用 exact empty checkpoint 且不读取 published checkpoint；data Run 只用 resolver 返回的 exact opened checkpoint。
- [ ] RED：每次 Provider call 前后 heartbeat/fence drift 停止；stale fence 不调用 `ApplyPage` 或 terminal success。
- [ ] RED：concrete `Page` 才调用 `ApplyPage`；concrete `Delay` 不调用 `ApplyPage`、不推进 checkpoint/count，先 persist intent/cleanup 再 Queue `Delay`。
- [ ] RED：open/revoke/terminal response loss 只按已合并 attempt/cleanup/terminal receipts replay；changed tuple fail closed。
- [ ] RED：panic/context cancellation 只停止新 claim、清理当前 attempt 并降级健康，不标记 success。
- [ ] GREEN：实现最小 provider-neutral loop 和 claim-runtime seam；测试 fake 只存在 `_test.go`。

**G2:**

~~~bash
go test -race ./internal/discoveryworker ./internal/discoverysource \
  ./internal/discoveryqueue ./internal/discoverycleanup \
  ./internal/discoverylimit ./internal/discoverycheckpoint -count=1
go vet ./internal/discoveryworker
git diff --check
~~~

G2 必须覆盖 dependency nil matrix、三 claim modes、exact ordered Reserve/Open/Resolve、same-opener/session/runtime-cell/handle/proof binding、Run/attempt/epoch/runtime-binding drift、validation/data split、Page/Delay XOR、fence drift、cleanup ordering、response-loss replay、panic/cancel 和 sensitive serialization。该 Batch 不声称真实 PostgreSQL/provider integration 或跨进程 attempt recovery；每个 Provider 在后继 integration Batch 以 `AIOPS_TEST_POSTGRES_DSN` 取得自己的真库 G2，跨进程 recovery 由 Task 28B/Task 29A 证明。Task 19A2c 必须先核对并复用本 Task `worker.go/worker_test.go/claim_runtime.go/claim_runtime_test.go` seam；禁止创建 separate qualification runner。若 seam 不足，先停工并用只修改这四文件的 sequential C0 corrective 扩展同一 Worker mode/outcome sink，合并后再继续。

**Deferred G3/G4:** 两 Worker、多进程 takeover、Worker/数据库 restart、HA/recovery、真实 Provider、production identity/config/binary 和 provider gate 全部 deferred。Task 28A 合并后只能记 `BUILT_CLOSED`，所有 Source/Worker 能力继续 `UNAVAILABLE/CLOSED`。

### Task 28B: Recoverable cleanup-session transport and attempt authority

**Batch:** C0/C1，1–2 日；只能消费已合并 Task 28A 与至少一个已合并 Provider descriptor/integration，必须先于 production constructor 与 Task 29A 合并。

**Exact files:**

- Create: `internal/discoverycleanup/session_transport.go`
- Create: `internal/discoverycleanup/session_transport_test.go`
- Create: `internal/discoveryworker/attempt_session.go`
- Create: `internal/discoveryworker/attempt_session_test.go`

不得修改 Task 27 `broker.go`/`broker_test.go`、Task 28A 四文件或任一 Provider 文件。该额外 Batch 是源文件核验发现 process-local `attempts` map 与新进程 `ErrAttemptNotFound` 后的最小必要拆分，不把跨进程 recovery 伪装成 Task 29A 脚本行为。

**Consumes（只读已合并）:**

- Task 27 exact `OpenAttemptRequest`、`SessionOpener`、`SessionHandle`、`AttemptSession`、proof verifier 与 Queue-owned `RunCoordinates/CleanupAttempt`。
- Task 28A `ClaimRuntimeResolver`/opaque `ClaimRuntime` seam，以及各 Provider 已合并的 neutral descriptor/runtime factory。
- 固定协议、mTLS workload identity 与共享 session authority endpoint；wire 只携带 exact Run/attempt/epoch/runtime-binding digest 和 opaque receipt，不携带 endpoint、credential、token、TLS key、`BoundRuntime` 或 raw `SessionHandle`。

**Produces:**

- `discoverycleanup.SessionTransport` fixed mTLS client contract：已预置的外部 shared session authority 必须以 exact `(Run,attempt_id,attempt_epoch,runtime_binding_digest)` 幂等 `OpenOrRecover/Revoke`，changed tuple fail closed。Task 28B 不实现或宣称拥有该外部 authority server/binary。
- `discoveryworker.AttemptSessionAuthority`：同一对象同时实现 Broker `SessionOpener` 与 Task 28A resolver；首次 open 只从同一 session cell 产生一个 process-local `BoundRuntime` 与一个 Broker-owned handle，replacement recovery-open 只返回同一外部 session 的 revoke handle，永不重新产生 Provider runtime。
- 可审计 recovery contract：新进程直接对空的 process-local Broker `RevokeAttempt` 仍是 `ErrAttemptNotFound`；正确路径必须以 Queue cleanup-only claim 的 exact coordinates/attempt 重新 `OpenAttempt`，经 shared authority 找回同一 session 后 revoke/proof。
- 明确 negative contract：Task 28B authority 的 identity/lifetime 是 exact Run attempt；它既不持有也不恢复跨 Run 的 vSphere `PropertyCollector`、filter、continuation token 或 update version。`OpenOrRecover` 不能返回 Provider runtime，因此不得解释成 [Task 21B0](#task-21b0-dependency-vsphere-propertycollector-session-continuity-authority) 的 resident authority。

**Classification:**

- **C0:** mTLS peer identity、exact attempt/runtime binding、same-session runtime/handle/proof、secret-zero-payload 和 recovery fail closed。
- **C1:** shared session transport client、same-attempt authority composition 与 response-loss replay。
- **C2:** 无；不拥有 Provider protocol、Queue/Worker state machine、production registry/binary、shared authority server/binary 或 migration。

**RED → GREEN:**

- [ ] RED：Worker A 首次 open 后销毁本地 Broker，Worker B 对新 Broker 直接 `RevokeAttempt` 得 `ErrAttemptNotFound`；只有 exact recovery-open 后才能 revoke 原 session，且 open/revoke 各一次。
- [ ] RED：Run/attempt/epoch/runtime-binding digest、mTLS peer 或 opaque receipt 任一漂移均在 resolver/Provider 前拒绝；recovery-open 不返回 `BoundRuntime`，cleanup-only Provider 零调用。
- [ ] RED：首次 Provider runtime、Broker handle 与 cleanup proof 必须来自同一 session cell；独立 credential/session open、另一 session proof 或任何 secret-bearing/loggable/serializable wire field均拒绝。
- [ ] GREEN：实现 fixed mTLS transport 与同一对象的 `SessionOpener + ClaimRuntimeResolver` composition；测试 fixture 只在 `_test.go`，缺 transport/identity/descriptor 一律 fail closed。

**G2:**

~~~bash
go test -race ./internal/discoverycleanup ./internal/discoveryworker \
  -run 'SessionTransport|AttemptSession|Recovery|SameAttempt|Secret' -count=1
go vet ./internal/discoverycleanup ./internal/discoveryworker
git diff --check
~~~

G2 必须用 test-only fixed-protocol authority fixture 证明两个独立 client/Broker 实例之间的 exact recovery-open/revoke、same-session runtime/handle/proof、changed tuple、mTLS negative、response-loss replay、zero secret payload 与 sensitive serialization；fixture 不进入 production graph，也不声称真实外部 authority 已验收。单进程 Broker test 不能代替该门。

**Deferred G3/G4:** 两个真实 Worker binary、kill owner、通过 opaque lab binding 连接的已预置真实外部 shared authority及其 reconnect/recovery、Worker/数据库 restart、HA takeover 与 credential resolver/key rotation 留给 Task 29A；Provider canary 留给各 Provider gate（External CMDB 为 Task 19B），最终 matrix 留给 Task 29B。vSphere 还必须单独完成 Task 21B0/21B；Task 28B 的真实 cleanup recovery 也不能替代它们。Task 28B 最多为 `BUILT_CLOSED`，不使任一 Provider 可用。

### Task 21B0 dependency: vSphere PropertyCollector session-continuity authority

**State:** `NOT_STARTED / UNAVAILABLE / CLOSED`。这是 [Pack 07 Task 21B0](./07-source-vsphere.md#task-21b0-vsphere-propertycollector-session-continuity-authority-c0-prerequisite) 的 Worker/HA half，与 Task 28B exact-attempt cleanup authority 正交；两份计划交叉引用同一个 prerequisite，不是两套实现。

**Batch admission:** Task 21A 可先合并，但本 Task 开始前必须用顺序 C0 contract review 冻结 resident authority topology、production deployment/identity、私有 non-serializable ABI、exact file manifest、failure model 与 executable G2 commands。当前没有这些已合并 `Produces`，所以任何代码会话都必须停工；禁止修改公共 `discoverysource`、Queue、Task 28A Worker、migration 或 Task 28B ABI 来临时承载 cookie/token/filter/version。

**Consumes:**

- Task 20 fixed vSphere client/profile/identity，Task 21A same-attempt full closure，Task 28A claim/`AttemptSession`/`BoundRuntime`，Task 28B exact-attempt cleanup transport，以及已合并 Queue/fence/PageCommitter/checkpoint-lineage contracts。
- 官方 PropertyCollector lifetime：`ContinueRetrievePropertiesEx` token 仅同一 login session/同一 collector 可用且一次性；`WaitForUpdatesEx` 依赖该 session 中 live filter/version。Checkpoint digest、Task 28B receipt 或新登录不能重建任何一项。
- 只读 production credential resolver/workload identity 与 PostgreSQL 18.4 application identity；authority wire 不得携带 credential、endpoint、cookie、continuation token、filter handle、`BoundRuntime` 或任意 SOAP body。`collector_version` 的 fixed opaque encoding只能在 sealed checkpoint/authority protocol内作为完整性坐标，不能成为 session reconstruction authority。

**Required `Produces`:**

- 一个 vSphere-specific resident authority，在 authority 内持有 live login session、`PropertyCollector`、filter、continuation/update state；Worker 只持有 opaque process-local capability。Authority exact 绑定 Scope/Source/revision、validated instance UUID、root digest、collector/session/filter identity、credential revision，以及当前 Run/lease/fence owner。
- Cross-Run ownership handoff 使用 monotonic CAS/fence。新 owner 只能接管同一 authority state；stale owner 在任何 SOAP call 前拒绝。Authority/session 丢失时不得创建新登录并复用旧 token/version，只能返回 closed evidence、`missing=0` 并进入 governed full-snapshot rollover。
- Authority 必须拥有 no-gap bootstrap barrier：同一 resident session/collector 先创建 filter并建立 initial version，再运行 Task 21A deterministic full algorithm并保留其间 updates；只有 drain 到 non-truncated version且 full/delta均无 rejection后，才产生 authoritative complete closure与首个 incremental checkpoint。Task 21A 独立 attempt 的 completed checkpoint不能直接成为该 cursor。
- Task 28B `RevokeAttempt` 只关闭 Worker 到 authority 的 exact attempt transport/runtime cell。普通 Run terminal cleanup 与 resident PropertyCollector final destroy 是两个不同 receipt chain：普通 Run 结束不能误销毁后继所需 filter；Source disable/supersede、instance/root drift、credential rotation、collector/session expiry、authority shutdown 或 terminal failure必须幂等 destroy session/filter并产生 no-orphan proof。任一 cleanup uncertainty 暂停 gate。
- Credential rotation 必须先 fence/revoke old authority；new credential/new session 只能建立 successor full snapshot lineage，不能继承旧 filter/version。Authority 的 durable metadata只含 opaque authority ID、exact binding digests、monotonic owner generation 和 safe receipts；raw session/filter/token 永不持久化、序列化或记录，`collector_version` 只存在于 sealed private checkpoint/authority state且永不公开。

**Classification:** C0 = resident authority identity、exact source/revision/instance/root/collector/session binding、cross-Run lease/fence、credential rotation、terminal revoke/no-orphan、secret-zero wire；C1 = ownership handoff/lifecycle；C2 = fixed authority RPC 与真实 PropertyCollector session ownership。

**Mandatory RED → GREEN evidence:**

- [ ] 两个独立 authority client 实例使用 distinct worker/process identity，对同一 TLS authority 的 consecutive Runs只使用一个 live vSphere session/collector/filter；owner-client termination 后 exact fence+1 takeover继续，旧 owner SOAP 零调用。
- [ ] 在 filter creation、initial version、每个 full page、delta drain和 final closure之间分别 create/modify/delete对象；只有无间隙 drain完成的同-session closure可启用 missing detection，独立 Task 21A checkpoint、partial/truncated bootstrap均拒绝。
- [ ] Authority crash/session expiry、credential rotation、instance/root/revision drift 都拒绝 checkpoint reconstruction/new-login reuse，旧 lineage不变、`missing=0`，仅 governed full rollover可恢复。
- [ ] Ordinary Run cleanup只回收 Task 28B attempt cell；source disable/supersede与 terminal authority cleanup销毁 filter/session一次，response-loss exact replay复用 receipt，changed replay拒绝，最终无 orphan。
- [ ] JSON/text/binary/log/format、wire capture 和 DLP tests 证明 authority capability/cookie/token/filter/endpoint/credential零泄露，并证明 `collector_version` 不出 sealed checkpoint/authority boundary。

**Required G2:** 使用真实 TLS resident authority implementation 驱动本机 govmomi simulator 的真实 SOAP serialization，并用项目 PostgreSQL 18.4 TLS wrapper/application identity证明 lease/fence/CAS、takeover、rotation、rollover和 cleanup receipts；`AIOPS_TEST_POSTGRES_DSN` 缺失、Skip、Task 28B test fixture、process-local map 或 mock SOAP 均不能 PASS。exact packages/commands必须与 implementation file manifest 在开工前一起冻结。

**Deferred G3/G4:** 真实部署 authority HA、真实非生产 vCenter、两真实 Discovery Worker/数据库 restart、long-running session expiry、canary/gate 和 provider matrix deferred。G2 代码合并仍最多 `BUILT_CLOSED`；Task 21B、Task 22 与 vSphere registry row未完成前继续 `UNAVAILABLE/CLOSED`。

### Task 28C prerequisite C0: same-attempt process-local External CMDB runtime-material authority

**Batch:** C0 corrective，Task 28C 开工前独立合并；只关闭 External CMDB runtime material 的生产解析 seam，不创建 registry、production constructor、binary、migration、公共 API 或运行资格。

**Exact files:**

- Modify: `internal/discoveryworker/attempt_session.go`
- Modify: `internal/discoveryworker/attempt_session_test.go`
- Create: `internal/discoveryruntime/external_cmdb.go`
- Create: `internal/discoveryruntime/external_cmdb_test.go`
- Create: `internal/discoveryruntime/postgres.go`
- Create: `internal/discoveryruntime/postgres_integration_test.go`
- Modify: `docs/superpowers/plans/2026-07-13-governed-operations/01-assets/09-discovery-worker-ha-e2e.md`

不得修改 Task 28A Worker、Task 28B `SessionTransport`、CleanupBroker、Task 18B Provider/reconciliation、migration、OpenAPI/generated types、Web、Control Plane 或 Task 28C 十文件。若 exact PostgreSQL facts 或服务端 material resolver 需要新的数据库/secret-store ABI，必须停止并另行冻结 owner，不能扩宽本 Batch。

**Consumes（只读已合并 `Produces`）:**

- Task 28B `InitialRuntimeRequest`、`SessionBoundRuntime` 与同一 `AttemptSessionAuthority` cell；`SessionTransport` 继续只携带 exact Run/attempt/epoch/runtime-binding digest 和 opaque receipt，绝不携带 Provider 或 credential material。
- Task 18B `internal/sourceprofile.ExternalCMDBDescriptor`、`externalcmdb.ReconciliationDescriptor`、`externalcmdb.RuntimeMaterial` 与既有 Provider/checkpoint/limits/fact-policy constructors；不得重建 descriptor 语义或创建第二 Provider/session。
- `000015` 的 exact Source/Revision/Run/authority 与 opaque Integration/Credential/Trust/Network reference IDs；PostgreSQL resolver 只通过 TLS application identity 读取这些安全事实，绝不读取 `integrations.secret_ref/config`、endpoint、credential、CA、Vault path 或任意 payload。
- 一个 mandatory、server-only、process-local External CMDB material resolver；它只接受从 PostgreSQL exact snapshot 派生的一次性 capability并返回单一 owner 的 runtime material/revoke/destroy capability。缺 resolver、返回可复制/可序列化 material、或任一 reference/binding drift 均 fail closed。

**Produces:**

- Task 28B `InitialRuntimeRequest` 增加同一内部 cell 签发的一次性、不可重建、不可复制、不可序列化 initial-runtime tuple/callback；tuple 只包含 server-derived exact `{scope,run_id,attempt_id,attempt_epoch}` 与 immutable `RuntimeBinding`，callback 返回的 runtime/lifecycle 必须绑定同一 request/cell。
- `ResolveRuntimeBinding` 的 safe binding lookup 必须允许 exact cleanup-only recovery 在 Source 已 disabled/paused/suspended 或 gate 漂移后继续认证同一 Task 28B SessionTransport session；该 snapshot 必须标记 `initialAllowed=false`、不得携带 opened checkpoint/runtime，且只能产生 recovery revoke handle。任何 `Initial=true` 结果仍须在 material resolver/Provider/network 前拒绝。
- `internal/discoveryruntime` 的 External CMDB authority：按 exact Source/Revision/binding 与 attempt tuple 从真实 PostgreSQL 重载四类 opaque refs，在任何 credential/network access 前比较 immutable descriptor/profile/admission；material resolver 必须在持有 exact Run/Source/Revision row locks 的同一个 serializable admission callback 内执行，把数据库 lease remaining 转换为数据库查询发起时的本地 monotonic absolute deadline（不得在 `Scan` 后重新起算），并在 cell 返回前按数据库时间 post-resolve 重验；随后每 attempt 只调用 material resolver 一次并立即把 `externalcmdb.RuntimeMaterial` 绑定到该 initial cell。
- 同一 runtime cell 唯一拥有 material 的 clear/revoke/destroy/zeroization。Broker revoke、authority destroy、cancel、open failure 或 foreign/reconstructed result 都只能终结该 cell 一次；所有内部 revoke/close 必须使用有限 deadline，callback 超时后仍继续 destroy/zeroize/tombstone；caller 不能取得可重建、可复制或可序列化的 runtime-material carrier。
- 后续 `ResolveClaimRuntime` 只从已打开的 exact cell 生成 Task 18B Provider、checkpoint、limits 与 fact policy；不得再次调用 PostgreSQL/material resolver、SessionOpener、credential resolver 或网络。
- Task 28C 只能消费该已合并 authority 作为单一 `SessionOpener + ClaimRuntimeResolver` composition 的 runtime-material owner；safe runtime-admission manifest 继续只含 opaque IDs/digests，不含 endpoint、token、CA、credential、path 或 material。

**RED → GREEN:**

- [ ] RED：Scope/Run/attempt/epoch、immutable Source/Revision tuple、canonical binding、Integration/Credential/Trust/Network ref 任一漂移在 SessionTransport 前拒绝；Source disabled/stale/gate-drift 的 exact cleanup recovery只能取得 `initialAllowed=false` safe binding，任何 initial material admission 均在 material resolver/Provider/network 前拒绝。
- [ ] RED：material resolver 阻塞期间的 Source disable、Gate 漂移、fence/reclaim 或 lease expiry 不能与 admission 交错；post-resolve 重验失败必须 revoke/destroy/zeroize，且不得返回 opened cell 或 Provider。
- [ ] RED：数据库 query/transport/scan/校验耗时不得延长 material deadline；deadline 已过时 material resolver 必须零调用。revoke callback 等待 `ctx.Done()` 时必须在有限 cleanup deadline 后继续 destroy/zeroize/tombstone，不能卡死 authority shutdown。
- [ ] RED：foreign、reconstructed、value-copied initial tuple/request/session-bound runtime 或 runtime-material capability拒绝；initial callback 与 material resolver 每 attempt 最多各一次。
- [ ] RED：`InitialRuntimeRequest`、initial tuple、session-bound runtime、External CMDB authority/material capability 的 JSON/text/binary、`String/GoString/LogValue/Format` 与 DLP capture 均不出现 endpoint、token、CA、credential、path、raw material 或内部 cell。
- [ ] RED：cancel/revoke/destroy 并发只执行一次 material revoke/destroy/zeroization；任一不确定结果保持 cleanup fail closed，不能产生 Provider success。
- [ ] RED：initial open response loss按 exact attempt/cell安全重放，不重新解析 material；changed replay拒绝。
- [ ] RED：真实 PostgreSQL 18.4 TLS application identity读取 exact immutable refs/authority/checkpoint facts；wrong Scope、stale attempt/fence epoch、Revision/ref/binding drift全部拒绝。disabled Source 必须仍返回 exact cleanup-recovery binding，但 initial material resolver保持零调用。
- [ ] GREEN：只实现上述窄 seam/authority/PostgreSQL resolver；不复用 cleanup mTLS certificate，不读取 direct config secret，不引入 fake/test server、第二 opener/resolver/session或删除 registry row伪绿。

**G2 — required, no Skip:**

~~~bash
go test -race ./internal/discoveryworker ./internal/discoveryruntime \
  -run 'InitialRuntime|ExternalCMDB|RuntimeMaterial|Authority|Postgres' -count=1
test -n "${AIOPS_TEST_POSTGRES_DSN:-}"
test -n "${AIOPS_TEST_POSTGRES_MIGRATION_DSN:-}"
test -n "${AIOPS_TEST_POSTGRES_APPLICATION_DSN:-}"
go test -race ./internal/discoveryruntime -run 'Postgres.*Integration' -count=1
go test -race ./internal/assetsource/externalcmdb ./internal/sourceprofile \
  ./internal/discoverycleanup ./internal/discoverysource ./internal/discoveryqueue \
  ./internal/discoverycheckpoint -count=1
git diff --check
~~~

PostgreSQL test 必须证明 Server `18.4+ 18.x`、TLS 1.3、独立 migration/application identity 和零 Skip；unit fake 只可证明接口负例，不能替代真实 PostgreSQL resolver。G3/G4、真实 secret store/credential issuer、两 Worker/authority restart、Provider canary/gate 和 Task 28C production assembly继续 deferred；本 corrective 最多 `BUILT_CLOSED`，所有能力保持 `UNAVAILABLE/CLOSED`。

### Task 28C: Production constructor and Provider registry

**Batch:** C0/C1/C2，1–2 日；只能在 Task 28A、Task 28B 与需要注册的 provider-specific durable integrations 已合并后开始。vSphere Task 21A 不满足该条件；只有 Task 21B0/21B 完成后 vSphere row 才可进入 registry。

**Exact files:**
- Create: `internal/discoveryworker/registry.go`
- Create: `internal/discoveryworker/registry_test.go`
- Create: `internal/discoveryworker/production.go`
- Create: `internal/discoveryworker/production_test.go`
- Create: `cmd/discovery-worker/main.go`
- Create: `cmd/discovery-worker/main_test.go`
- Create: `cmd/discovery-worker/config.go`
- Create: `cmd/discovery-worker/config_test.go`
- Create: `cmd/discovery-worker/production.go`
- Create: `cmd/discovery-worker/production_test.go`

**Consumes:**

- 已合并 Task 28A `Worker`/claim-runtime seam、Task 28B `SessionTransport`/`AttemptSessionAuthority` 与 Task 27/M1D/M1E public constructors。
- 每个已合并 Provider 的 exact adapter/profile/fact-policy/runtime resolver descriptor；External CMDB 必须消费 Task 18B `Produces`。vSphere descriptor必须消费 Task 21B0 resident-authority binding和 Task 21B cross-Run delta/leave/HA `Produces`；full-only Task 21A descriptor必须拒绝。
- existing secure bootstrap/manifest/workload identity patterns；不把 Control Plane config 变成第二 owner。

**Produces:**

- Immutable exact Provider registry；只注册具有已合并 adapter + neutral profile descriptor/fact-policy + durable-integration evidence 的 Phase 1 row。External CMDB registry 必须比较 Task 18B `internal/sourceprofile` canonical descriptor digest，不能重建 metadata；vSphere 必须比较 Task 21B0 authority capability digest与 Task 21B durable descriptor，任一缺失时该 row完全不注册。`KUBERNETES_OPERATOR`、`AWX_INVENTORY` 和任何缺依赖 Provider 保持未注册/`UNAVAILABLE`，不得使用 family/default HTTP adapter。
- `internal/discoveryworker.NewProduction(...)`、`cmd/discovery-worker.newProduction(Config)` 和独立 binary startup/readiness/shutdown。
- Production constructor uses PostgreSQL Queue/PageCommitter/Limiter、Task 28B single `AttemptSessionAuthority`、由它构造的 process-local Broker、checkpoint keyring、low-cardinality metrics boundary and mTLS workload identity；constructor 不接受彼此独立的 `SessionOpener` 与 runtime resolver 注入，credential/session transport 只能由该 authority open/recover path 调用。若 registry 包含 vSphere，Task 28B authority 只能打开到 Task 21B0 resident authority 的 exact attempt capability；resident session/filter仍由 Task 21B0 拥有，并要求独立 capability digest，不能由 Task 28B reconstruction。constructor 还产生仅含 Provider/Profile/canonical descriptor/runtime-recovery capability digest 的 safe content-addressed runtime-admission manifest，供 Task 19A Control Plane admission 只读消费；manifest 不含 endpoint、credential、socket、key 或 runtime material。
- A production-only `WorkerObserver`/dependency-decorator extension seam in `internal/discoveryworker/production.go` and `cmd/discovery-worker/production.go`。It decorates the exact Queue/PageCommitter/Limiter dependencies injected into Task 28A and exposes one closed later slot for the Task 19A2c qualification outcome dependency，never edits or copies the Task 28A loop，and emits only closed safe enums such as Provider/result/boundary。The constructor derives an opaque worker-identity digest from the authenticated mTLS workload identity and a fresh process-instance digest from its symlink-safe startup bootstrap；CLI/config/caller values cannot supply either digest。Task 28C wires an explicit closed observer so the binary remains `BUILT_CLOSED`; Task 29A is the sole sequential owner that replaces it with real low-cardinality metrics and，after Task 19A2c，registers the HA verifier。

源文件核验显示现有 `internal/config.Config` 是 Control Plane-wide 配置，生产代码当前只由 `cmd/control-plane` 消费。把 discovery credential/keyring/socket 文件加入该共享类型会制造无关 owner 和敏感配置耦合，因此 Discovery Worker 配置只由 `cmd/discovery-worker/config.go` 拥有。Task 28C 不得修改 Task 28A/28B 文件，也不得把 Provider-specific profile/fact policy 重写进 registry。

**Classification:** C0 = secret-bearing config/identity/manifest/graph isolation；C1 = production assembly/readiness/shutdown；C2 = exact registry composition only。

**RED → GREEN:**

- [ ] **Step 1: Write failing production dependency and secret-boundary tests**

~~~go
func TestProductionConstructorFailsClosedForEveryMissingDependency(t *testing.T) {
	valid := validProductionDependencies(t)
	for _, mutate := range []func(*ProductionDependencies){
		func(d *ProductionDependencies) { d.Queue = nil },
		func(d *ProductionDependencies) { d.PageCommitter = nil },
		func(d *ProductionDependencies) { d.Limiter = nil },
		func(d *ProductionDependencies) { d.AttemptAuthority = nil },
		func(d *ProductionDependencies) { d.SessionTransport = nil },
		func(d *ProductionDependencies) { d.Checkpoints = nil },
		func(d *ProductionDependencies) { d.Registry = nil },
		func(d *ProductionDependencies) { d.WorkloadIdentity = nil },
		func(d *ProductionDependencies) { d.Observer = nil },
	} {
		candidate := valid.Clone()
		mutate(&candidate)
		if _, err := NewProduction(candidate); err == nil {
			t.Fatal("constructor accepted missing production dependency")
		}
	}
}

func TestProductionRegistryRejectsUnavailableOrDriftedProvider(t *testing.T) {
	registry := newRegistryFromMergedDescriptors(t)
	assertUnavailable(t, registry, "KUBERNETES_OPERATOR")
	assertUnavailable(t, registry, "AWX_INVENTORY")
	assertSemanticDriftRejected(t, registry, "CMDB_CATALOG_V1")
}
~~~

The same RED enumerates `Config`、supported flags and environment-variable bindings and rejects any worker/process identity field or alias。The same authenticated workload identity across a restart must derive the same opaque worker digest but a distinct fresh process-instance digest；a different authenticated workload identity must derive a different worker digest。Tests never accept a precomputed digest。

Run: `go test ./internal/discoveryworker ./cmd/discovery-worker -count=1`

Expected: FAIL because production constructor/registry/binary do not exist；Task 28A core itself is an already-merged `Consumes` and is not changed by this RED。

- [ ] **Step 2: Compose the merged Worker core and exact Provider descriptors**

Task 28C 不实现第二个 fenced run loop。它只把 Task 28A `New(Dependencies)` 与真实 PostgreSQL Queue/PageCommitter/Limiter、CheckpointCodec、Task 28B 唯一 `AttemptSessionAuthority`、immutable registry 和 mandatory production observer/decorators 组合；process-local Broker 与 resolver 必须由该同一 authority 构造，禁止分别注入、再次调用 credential resolver 或新建 session。vSphere-specific descriptor还必须验证 Task 21B0 resident-authority capability digest，并让 Task 28B attempt authority只打开受 fence 的短期 client capability；它不能把 resident authority state导入 Worker。Observer 只能包装已注入依赖并接收 server-derived safe enum，不得接收 Source/Run/external ID、endpoint、digest 或任意 labels。每个 Provider descriptor 必须来自对应已合并 Provider Batch，并与 neutral metadata digest exact 相等。缺 descriptor、Task 28B transport、observer、duplicate Provider/Profile、semantic drift、attempt binding 漂移或 unsupported kind 在创建 Worker 前 fail closed。Core 的 claim、Page/Delay、cleanup、terminal、panic 和 cancellation 行为继续由 Task 28A 四文件唯一拥有。

- [ ] **Step 3: Assemble the real binary without production fake branches**

`cmd/discovery-worker` requires PostgreSQL DSN file, workload identity certificate/key file, CA file, secure source-profile manifest file, Task 28B shared session-authority endpoint/socket, checkpoint keyring file and metrics private bind. Files must be absolute, owner-only where secret-bearing, symlink-safe and loaded through existing secure bootstrap patterns. 若 vSphere row 被注册，还必须消费 Task 21B0 冻结的独立 opaque resident-authority binding；Task 28B endpoint或普通 credential reference不能替代它。The binary consumes the authenticated workload identity certificate/key only through the production mTLS bootstrap and server-derives its opaque worker-identity digest；it creates a fresh opaque process-instance digest during the same symlink-safe startup. Neither identity digest accepts a flag、environment variable、config value or caller input。Startup verifies migrations through 000015, manifest digest/signature, registry completeness, mTLS identity, DB time and dependency health before readiness.

The binary does not import `internal/*/memory`, testdata, MSW, Control Plane handler or model/LLM packages. Add AST/import tests proving Provider SDK、Provider HTTP-client、credential/session transport packages are reachable only from `cmd/discovery-worker` production graph；vSphere 是唯一条件例外，Task 21B0 若冻结独立 resident-authority graph，该 graph 也可导入 govmomi，但必须与 Control Plane/其他 Provider隔离并通过自己的 import/secret-boundary test。任何 Provider SDK/network graph 都不得从 `cmd/control-plane` 可达；Control Plane 后续只能 import `internal/sourceprofile` neutral metadata/admission package，其既有 HTTP server graph 不受影响。

- [ ] **Step 4: Verify binary, race, shutdown, and commit**

**G2:**

Run:

~~~bash
gofmt -w $(rg --files internal/discoveryworker cmd/discovery-worker -g '*.go')
go test -race ./internal/discoveryworker ./cmd/discovery-worker -count=1
go build ./cmd/discovery-worker
go test ./cmd/control-plane ./cmd/discovery-worker -run 'Production|Registry|Observer|Decorator|Boundary|Secret|Identity|Bootstrap' -count=1
git diff --check
~~~

Expected: PASS; missing/stale configuration fails before ready，any worker/process identity flag、environment variable or config field is rejected，the two opaque digests are derived/generated only by production bootstrap，shutdown cleans credentials/leases, Control Plane has no Provider network/secret dependency and no test fake is production-reachable.

~~~bash
git add internal/discoveryworker/registry.go internal/discoveryworker/registry_test.go \
  internal/discoveryworker/production.go internal/discoveryworker/production_test.go \
  cmd/discovery-worker
git commit -m "feat(assetdiscovery): assemble production discovery worker"
~~~

**Deferred G3/G4:** 两个真实 binary、PostgreSQL reconnect/restart、HA takeover、real workload identity/credential resolver/keyring rotation 由 Task 29A 执行；各 Provider canary/gate 由其独立任务执行，最终 lab matrix/发布资格由 Task 29B 聚合。Task 28C 最多为 `BUILT_CLOSED`；binary 存在不代表任一 Provider 或 Worker 可用。

### Task 29A: Provider-neutral two-worker HA receipt and telemetry

**Batch:** C0/C1，1–2 日 implementation plus deferred G3 execution；只能消费已合并 Task 19A2a、Task 19A2b、Task 19A2c 与 Task 28C observer seam，独立真实 G2/PR/merge，必须先于 External CMDB Task 19B 和任何 final matrix。

**Exact files:**
- Create: `internal/discoveryworker/metrics.go`
- Create: `internal/discoveryworker/metrics_test.go`
- Create: `internal/discoveryqualification/ha.go`
- Create: `internal/discoveryqualification/ha_test.go`
- Create: `scripts/verify-discovery-worker-ha.sh`
- Create: `docs/operations/asset-sources/discovery-worker.md`
- Modify: `internal/discoveryworker/production.go`
- Modify: `internal/discoveryworker/production_test.go`
- Modify: `cmd/discovery-worker/production.go`
- Modify: `cmd/discovery-worker/production_test.go`
- Modify: `cmd/discovery-worker/qualification.go`
- Modify: `cmd/discovery-worker/qualification_test.go`

上述 12 个 files 不与 Task 19B 或 Task 29B 重叠。前六个 files 唯一拥有 HA verifier/metrics/drill/runbook；后六个 files 是对已合并 Task 28C production observer seam 与 Task 19A2c qualification registration seam 的 sequential wiring owner。`internal/discoveryqualification/ha.go` 只实现 `EvidenceVerifier`：它只能接收 Task 19A2c outcome sink 从 Task 19A2b Repository 重载的 immutable `QualificationFactSnapshot`，验证 distinct worker/process、takeover/restart/recovery/cleanup/pre-terminal response-loss chain 后返回 verified digest；它不得接收 caller facts、claim Run、调用 Queue/Worker/Provider/CleanupBroker、持久 terminal、自签或实现任何 loop/runner。Task 29A 不修改 migration、Source gate repository/evaluator、Provider adapter/canary、OpenAPI/Web、Makefile 或 CI。

**Mandatory production seam preflight — fail closed:**

实现第一步必须只读核对已合并 `internal/discoveryworker/production.go`、`production_test.go`、`cmd/discovery-worker/production.go`、`production_test.go` 与 Task 19A2c `cmd/discovery-worker/qualification.go`、`qualification_test.go`。前四个必须已有不复制 Worker loop 的 observer/dependency-decorator seam，后两个必须已有 immutable verifier-registry registration + sole sink/signer seam。若任一不足，Task 29A 必须停止且不得编辑上述 12 文件；主管理先开仅修改这六个 exact files 的最小 sequential C0 seam corrective，独立新窗口、定向 RED/G2、单一 PR/merge，只补 closed extension/registration seam，不实现 metrics/HA verifier。该 corrective 合并后重新启动 Task 29A；禁止用 Task28A 修改、脚本日志、test fake 或第二 loop 代替 production seam。

**Interfaces:**
- Consumes Task 19A2a safe receipt/HA schema、Task 19A2b server-generated durable fact loader、Task 19A2c fixed `TWO_WORKER_HA` qualification lane/immutable verifier registry/sole sink+signer、Task 28C real binary/registry/observer decorators、Task 28B fixed mTLS recovery client/same-attempt composition，以及通过 opaque lab binding 预置的真实外部 shared session authority；不拥有 authority server/binary，脚本不得启动或用 fake/shared process map 代替它。vSphere row 还必须消费 Task 21B0 的真实 resident PropertyCollector authority与 Task 21B continuity evidence；Task 28B cleanup recovery单独存在时 vSphere HA receipt必须拒绝。
- `cmd/discovery-worker/qualification.go` registers exactly the Task 29A HA verifier into the Task 19A2c immutable registry；the sole outcome sink reloads facts、invokes it and passes the verified digest to the sole signer。`ha.go` has no persistence or signing key and cannot make a receipt from script/caller input。
- `internal/discoveryworker/production.go` wraps the real Queue/PageCommitter/Limiter/qualification sink through Task 28C decorators，and `cmd/discovery-worker/production.go` injects the real metrics observer into both Worker processes。No metrics value comes from logs、shell parsing、test fake or a parallel Worker callback。
- Produces one current signed `TWO_WORKER_HA` receipt bound to exact Tenant/Workspace/Source、published revision/binding、Provider/Profile descriptor、Task 28C runtime manifest、opaque lab-binding digest、distinct owner/takeover worker and process identity digests、takeover/restart/session-recovery/cleanup/pre-terminal-response-loss receipt digests、fact-chain digest and expiry。它不消费 real Provider canary receipt，不写 `asset_sources.gate_status`，不产生 per-source Provider decision 或 final matrix。
- Produces only low-cardinality metrics `asset_source_claims_total{provider,result}`, `asset_source_pages_total{provider,result}`, `asset_source_backpressure_total{provider,reason}`, `asset_source_fence_rejections_total{boundary}`, `asset_source_checkpoint_age_seconds{provider}` and `asset_source_qualification_runs_total{provider,evidence_kind,result}`。Labels 禁止 Tenant/Workspace/Source/Run/external ID、subject、endpoint 或 digest。
- Script consumes only test/lab binding IDs including `AIOPS_DISCOVERY_SESSION_AUTHORITY_LAB_BINDING`，never prints values；missing binding、mTLS identity failure、authority unavailable 或 Skip 必须 fail closed。

- [ ] **Step 1: Write failing HA receipt and metric-cardinality tests**

~~~go
func TestHAVerifierCannotClaimCanaryGateOrSigning(t *testing.T) {
	snapshot := loadRepositoryClosedHAFacts(t)
	verified, err := NewHAVerifier().Verify(snapshot)
	if err != nil || verified.EvidenceKind != qualification.EvidenceTwoWorkerHA {
		t.Fatalf("verification = %#v, %v", verified, err)
	}
	snapshot.HATakeoverReceiptDigest = ""
	if _, err := NewHAVerifier().Verify(snapshot); err == nil {
		t.Fatal("verifier accepted incomplete durable facts")
	}
	verifierType := reflect.TypeOf(NewHAVerifier())
	for _, forbidden := range []string{"Sign", "Persist", "AdmitGate", "RunCanary"} {
		if _, exists := verifierType.MethodByName(forbidden); exists {
			t.Fatalf("HA verifier exposes forbidden method %s", forbidden)
		}
	}
}
~~~

Run: `go test ./internal/discoveryworker ./internal/discoveryqualification ./cmd/discovery-worker -run 'HAReceipt|HAVerifier|Metrics|ProductionWiring' -count=1`

Expected: FAIL because provider-neutral HA verifier、signed-receipt wiring and production metrics observer are missing.

- [ ] **Step 2: Execute two-worker cleanup/restart/response-loss qualification**

`verify-discovery-worker-ha.sh` starts two real Task 28C Worker processes and PostgreSQL，then calls only Task 19A2c's mTLS qualification operation with `evidence_kind=TWO_WORKER_HA` against an already-published closed qualification Source. It does not call Provider canary、`AdmitGate` or ordinary `RequestSync`。It kills the lease owner during bounded Provider read/session use，requires a distinct replacement workload/process identity to take over at exact `fence_epoch+1`，proves a fresh process-local Broker direct revoke returns `ErrAttemptNotFound`，then recovery-opens the same external session through Task 28B。

The drill restarts Worker and PostgreSQL，loses one pre-terminal recovery/cleanup command response，replays its exact persisted receipt before finalization and rejects a changed command。Task 19A2b derives every HA digest from Queue/run/Task28B receipts；the Task 19A2c sink reloads that snapshot，invokes Task 29A `ha.go` and alone signs/persists the terminal receipt。After sealing, terminal response-loss replay may be tested separately but cannot self-reference inside the signed fact chain。The drill also scrapes the private metrics endpoint from both real binaries and proves bounded labels；cleanup uncertainty produces only `FAILED + SUSPENDED` and no HA receipt。It never runs a real Provider canary or changes the gate.

**G2 — required, no Skip:**

~~~bash
test -n "${AIOPS_TEST_POSTGRES_DSN:-}"
go test -race ./internal/discoveryworker ./internal/discoveryqualification \
  ./internal/discoveryqueue/... ./cmd/discovery-worker \
  -run 'HAVerifier|HAReceipt|ProductionWiring|Metrics|Cardinality' -count=1
go build ./cmd/discovery-worker
git diff --check
~~~

G2 必须使用真实 Task 19A2b PostgreSQL fact loader、Task 19A2c registry/sink/signer 与 Task 28C production constructors；missing verifier/observer、caller facts、fake signer、unbounded label、second loop 或 Skip 均不得 PASS。该 Batch 代码合并后仍为 `BUILT_CLOSED`。

**Deferred G3 — required before any HA receipt is accepted:**

~~~bash
test -n "${AIOPS_DISCOVERY_SESSION_AUTHORITY_LAB_BINDING:-}"
scripts/verify-discovery-worker-ha.sh
git diff --check
~~~

Expected: two-process takeover/restart/same-session cleanup/pre-terminal response-loss、real binary metrics and zero-projection signed receipt PASS；source remains `PUBLISHED + UNAVAILABLE` and no canary/matrix artifact is created。缺 external authority、mTLS、PostgreSQL restart、second Worker、signer、metrics scrape 或任何 Skip 均不得记录 G3 PASS。

- [ ] **Step 3: Commit**

~~~bash
git add internal/discoveryworker/metrics.go internal/discoveryworker/metrics_test.go \
  internal/discoveryqualification/ha.go internal/discoveryqualification/ha_test.go \
  internal/discoveryworker/production.go internal/discoveryworker/production_test.go \
  cmd/discovery-worker/production.go cmd/discovery-worker/production_test.go \
  cmd/discovery-worker/qualification.go cmd/discovery-worker/qualification_test.go \
  scripts/verify-discovery-worker-ha.sh docs/operations/asset-sources/discovery-worker.md
git commit -m "test(assetdiscovery): prove provider-neutral worker ha"
~~~

**Deferred G3/G4 in this corrective:** 本 PR 不执行 Task 29A 或 G3；absence of its current signed receipt keeps every dependent Provider gate closed。

### Task 29B: Signed provider matrix and final E2E CI

**Batch:** C0/C1/Q，1–2 日 assembly plus deferred G4 execution；只能在每个 Phase 1 Provider 的 Task 29A HA receipt 与独立 per-source gate/canary 已合并并真实执行后开始。External CMDB 必须先完成 Task 19B。

**Exact files:**
- Create: `internal/discoveryqualification/provider_matrix.go`
- Create: `internal/discoveryqualification/provider_matrix_test.go`
- Create: `scripts/verify-asset-source-provider-matrix.sh`
- Create: `docs/operations/asset-sources/provider-gates.md`
- Create: `web/e2e/source-provider-gates.spec.ts`
- Modify: `Makefile`
- Modify: `.github/workflows/ci.yml`

Task 29B 不修改 Task 29A metrics/HA/script/runbook、Task 19A2a schema/domain、Task 19A2b evidence/gate persistence、Task 19A2c API/Worker mode/assembly，或任一 Provider gate/evaluator/canary file。

**Interfaces:**
- Consumes only already-completed signed safe facts for each exact Provider row：current validation、protocol/negative/DLP/provenance/checkpoint/delete-recovery/rate/backpressure/cleanup、Task 29A `TWO_WORKER_HA` receipt、Provider-owned non-production canary receipt、current atomic gate-evidence pointer and status。It does not call Provider、queue qualification、kill Worker、re-run HA/canary or write a gate。
- Produces a content-addressed signed final provider acceptance matrix keyed by exact Source/Profile/Revision/binding and receipt digests；missing、expired、drifted or unavailable rows remain explicitly `UNAVAILABLE` and cannot borrow family evidence。The matrix is a release/visibility aggregate, never an admission input.

- [ ] **Step 1: Write failing fail-closed matrix tests**

~~~go
func TestProviderMatrixNeverTreatsFamilyAsSingleGate(t *testing.T) {
	matrix := NewProviderMatrix()
	matrix.Accept(completedReceiptSet("AWS_EC2_V1"))
	if matrix.Status("AWS_EC2_V1") != "AVAILABLE" || matrix.Status("AZURE_COMPUTE_V1") != "UNAVAILABLE" {
		t.Fatalf("matrix = %#v", matrix)
	}
}
~~~

Run: `go test ./internal/discoveryqualification -run ProviderMatrix -count=1`

Expected: FAIL because final matrix aggregation does not exist.

- [ ] **Step 2: Aggregate the exact closed row set without rebuilding evidence**

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

Every Phase 1 row must reference the already-open exact per-source gate plus its distinct current HA/canary receipt digests；Task 29B verifies signatures/expiry/Scope/revision/binding equality and signs the aggregate. It cannot synthesize a receipt, call `AdmitGate`, infer a family status or turn a Provider on. For `VSPHERE/VSPHERE_VCENTER_V1`, Task 21A full-only evidence is insufficient：Task 21B0 authority、Task 21B delta/leave/HA、Task 22 gate/canary任一缺失时该 row必须保持 `UNAVAILABLE`。UI and API show the same orthogonal status/reason/evidence timestamps.

- [ ] **Step 3: Run final provider E2E/CI aggregation**

`verify-asset-source-provider-matrix.sh` reads only safe receipt/query APIs and opaque lab binding IDs；it does not accept endpoint/credential flags or start any authority/Provider/Worker. It proves changed/expired receipt、family substitution、missing row、matrix signature replay and UI projection fail closed.

~~~bash
go test -race ./internal/discoveryqualification -run ProviderMatrix -count=1
scripts/verify-asset-source-provider-matrix.sh
corepack pnpm@10.34.0 --dir web test:e2e -- --grep "source provider gate"
git diff --check
~~~

Expected: only rows with independently completed gate/canary/HA evidence appear accepted；Kubernetes/AWX remain visibly unavailable here，and no duplicate qualification、gate mutation、leaked secret or false-green family gate exists.

- [ ] **Step 4: Commit**

~~~bash
git add internal/discoveryqualification/provider_matrix.go \
  internal/discoveryqualification/provider_matrix_test.go \
  scripts/verify-asset-source-provider-matrix.sh \
  docs/operations/asset-sources/provider-gates.md web/e2e/source-provider-gates.spec.ts \
  Makefile .github/workflows/ci.yml
git commit -m "test(assetdiscovery): sign final provider matrix"
~~~

**Deferred G4 in this corrective:** 本 PR 只冻结无环合同；Task 29B、final E2E/CI 和 matrix signature 未执行，所有 Provider row 与 production Worker availability 继续 `UNAVAILABLE/CLOSED`。具体实现完成度只由 `docs/status/current.md` 记录，本计划不重述。
