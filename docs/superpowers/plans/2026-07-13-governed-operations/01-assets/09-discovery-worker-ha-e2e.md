# Discovery Worker, HA Fencing, Backpressure, and Provider Acceptance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 创建真实 `cmd/discovery-worker`、PostgreSQL HA queue/lease/fence、加密 checkpoint、持久限流/背压与全 Provider 生产验收门，使 Source 控制面与发现数据面形成可故障转移的闭环。

**Architecture:** Control Plane 只创建不可变 Source Revision 和 durable Run；Discovery Worker 通过 PostgreSQL `FOR UPDATE SKIP LOCKED` 领取 exact source/revision/gate 任务，使用单调 fence epoch/token 在 validation、runtime resolve、credential open、provider call、page reconcile、checkpoint、heartbeat 和 complete 边界复验。Provider runtime/credential 只在 Worker 内存；页结果经 Schema/DLP 后与加密 checkpoint 在一个事务提交。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4、pgx v5、AES-256-GCM、mTLS workload identity、existing `workerbootstrap`/`securemanifest`、Prometheus client_golang 1.23.2。

## Global Constraints

- Task 28A provider-neutral Worker core 只消费已合并 PageCommitter/Queue/Checkpoint/CleanupBroker/Limiter，不等待任一 Provider 包；它必须先独立合并。每个 Provider 的 durable integration（External CMDB 为 [Task 18B](./06-source-external-cmdb.md#task-18b-external-cmdb-durable-reconciliation-and-lifecycle-integration)）随后只消费该稳定 seam。源文件核验又确认现有 Broker attempt map 仅在进程内，因此 Task 28B 单独交付 recoverable cleanup-session transport/same-attempt authority；Task 28C production constructor/registry 才等待上述两者与 [05-source-ingestion-csv-api.md](./05-source-ingestion-csv-api.md)、[06-source-external-cmdb.md](./06-source-external-cmdb.md)、[07-source-vsphere.md](./07-source-vsphere.md)、[08-source-proxmox-openstack-cloud.md](./08-source-proxmox-openstack-cloud.md) 各自已合并的 provider-specific `Produces`。
- 每个 Task 严格执行 `Red → Green → Refactor`：先运行并保留预期失败，再做最小生产实现，随后消除重复、复跑指定验证并按 Task 提交；不得跳过失败或弱化断言。
- 生产必须有独立 `cmd/discovery-worker`；不得把 Provider SDK、Credential Resolver 或目标网络客户端装入 Control Plane、通用 `cmd/worker` 或浏览器。
- 持久 Job/Run 只含 Source/Revision/Gate/Checkpoint digest、Scope、Run ID、预算、fence epoch/owner/token hash；不含 endpoint、Secret、raw Token、PEM、cursor plaintext、Header/Body 或 Provider 错误。完整 sealed `LeaseFence` 只由 Claim 返回到当前 Worker 内存，绝不进入 Job/Task/Batch/audit/log payload。
- Raw lease token 只存 Worker 内存，DB 仅存 SHA-256；每次 reclaim 必须 `fence_epoch+1` 且旧 fence 无法 heartbeat/reconcile/checkpoint/complete。
- Checkpoint 使用 AES-256-GCM；唯一 AAD 构造器与 typed `CheckpointAAD` 由 `internal/discoverycheckpoint` 拥有，并用 `FramedTupleV1("asset-source-checkpoint.v1",Tenant,Workspace,Source,Provider,Source definition revision,canonical revision digest,source definition digest,checkpoint key ID,Checkpoint version)` 的精确九字段顺序。key 只通过 workload secret binding 读取。持久 AAD 不含 gate revision/fence epoch/token，因为 checkpoint 必须跨 reclaim 和后续 Run 恢复且 Claim 不得制造 checkpoint 版本变更；每次 Open、Provider call、Reconcile、checkpoint 提交和 Complete 仍分别要求 exact live owner/token/epoch。Codec 必须有 golden bytes/hash、九字段逐项篡改、NULL/empty 和 key-rotation 测试。
- 数据库通过 `asset_source_limit_buckets` 与 append-only `asset_source_limit_permits` 分别持久每 Source/Workspace/Provider 的 token bucket 和 active permit/terminal receipt；`not_before`、queue depth 与 failure streak 仍属于 Queue/Source backpressure。进程内 semaphore 只是二次保护，不是授权事实。
- Validation Run 可消费 `VALIDATING` revision；Discovery/Import/Ingestion Run 仅可消费 exact `PUBLISHED + ACTIVE + AVAILABLE`。任何漂移停止并关闭影响的 provider/source gate。
- Validation Run 的 checkpoint 输入固定为空；它不得比较、解密或推进当前 published revision 的 Source checkpoint。Discovery/Import/Ingestion 才消费 exact current checkpoint；checkpoint-lineage-rollover 仅走 Pack 01 的受治理同一 Run 例外。
- Credential open/session cleanup 是 terminal 成功的必要证据。每个 attempt 先持久化 Broker-owned opaque UUID，再允许 open；Broker 持有真实 revoke/session handle，Run/API/日志永不携带。cleanup 未知不能把 run 写为成功并必须暂停 Source gate。
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
  -> each provider durable integration（External CMDB = Task 18B）
  -> Task 28B recoverable cleanup-session transport/same-attempt authority
  -> Task 28C production constructor/registry/binary
  -> External CMDB Task 19A Control Plane profile/validation admission
  -> Task 29 two-worker HA/provider qualification
```

后继 Batch 只能从最新 `origin/main` 读取已合并 `Produces`。Task 18B 不得读取 Task 28A 未提交文件；Task 28B 不得读取 Task 18B 未合并 descriptor；Task 28C 不得读取 Task 28B 或其他 Provider 未合并实现。源文件核验发现 process-local Broker 不能满足 replacement Worker cleanup 后，原来的“Task 28A core + Task 28B production”最小拆分增加一个独立 transport Batch，并把 production 顺延为 Task 28C；所有新 Batch exact files 互不重叠，且都以 1–2 日为上限。

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

`AIOPS_TEST_POSTGRES_DSN` 缺失或任何 integration test Skip 都不能记为 PostgreSQL PASS。Expected: concurrent claims、lease expiry/reclaim、stale fence、exact attempt/terminal receipt recovery、checkpoint tamper/rotation、三 bucket concurrency 和 response-loss replay 继续通过。两 Worker、进程/数据库 restart、HA takeover 和完整 recovery 保留到 Task 29/G3；不得把单进程 G2 写成这些证据已完成。

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

G2 必须覆盖 dependency nil matrix、三 claim modes、exact ordered Reserve/Open/Resolve、same-opener/session/runtime-cell/handle/proof binding、Run/attempt/epoch/runtime-binding drift、validation/data split、Page/Delay XOR、fence drift、cleanup ordering、response-loss replay、panic/cancel 和 sensitive serialization。该 Batch 不声称真实 PostgreSQL/provider integration 或跨进程 attempt recovery；每个 Provider 在后继 integration Batch 以 `AIOPS_TEST_POSTGRES_DSN` 取得自己的真库 G2，跨进程 recovery 由 Task 28B/Task 29 证明。

**Deferred G3/G4:** 两 Worker、多进程 takeover、Worker/数据库 restart、HA/recovery、真实 Provider、production identity/config/binary 和 provider gate 全部 deferred。Task 28A 合并后只能记 `BUILT_CLOSED`，所有 Source/Worker 能力继续 `UNAVAILABLE/CLOSED`。

### Task 28B: Recoverable cleanup-session transport and attempt authority

**Batch:** C0/C1，1–2 日；只能消费已合并 Task 28A 与至少一个已合并 Provider descriptor/integration，必须先于 production constructor 与 Task 29 合并。

**Exact files:**

- Create: `internal/discoverycleanup/session_transport.go`
- Create: `internal/discoverycleanup/session_transport_test.go`
- Create: `internal/discoveryworker/attempt_session.go`
- Create: `internal/discoveryworker/attempt_session_test.go`

不得修改 Task 27 `broker.go`/`broker_test.go`、Task 28A 四文件或任一 Provider 文件。该额外 Batch 是源文件核验发现 process-local `attempts` map 与新进程 `ErrAttemptNotFound` 后的最小必要拆分，不把跨进程 recovery 伪装成 Task 29 脚本行为。

**Consumes（只读已合并）:**

- Task 27 exact `OpenAttemptRequest`、`SessionOpener`、`SessionHandle`、`AttemptSession`、proof verifier 与 Queue-owned `RunCoordinates/CleanupAttempt`。
- Task 28A `ClaimRuntimeResolver`/opaque `ClaimRuntime` seam，以及各 Provider 已合并的 neutral descriptor/runtime factory。
- 固定协议、mTLS workload identity 与共享 session authority endpoint；wire 只携带 exact Run/attempt/epoch/runtime-binding digest 和 opaque receipt，不携带 endpoint、credential、token、TLS key、`BoundRuntime` 或 raw `SessionHandle`。

**Produces:**

- `discoverycleanup.SessionTransport` fixed mTLS client contract：已预置的外部 shared session authority 必须以 exact `(Run,attempt_id,attempt_epoch,runtime_binding_digest)` 幂等 `OpenOrRecover/Revoke`，changed tuple fail closed。Task 28B 不实现或宣称拥有该外部 authority server/binary。
- `discoveryworker.AttemptSessionAuthority`：同一对象同时实现 Broker `SessionOpener` 与 Task 28A resolver；首次 open 只从同一 session cell 产生一个 process-local `BoundRuntime` 与一个 Broker-owned handle，replacement recovery-open 只返回同一外部 session 的 revoke handle，永不重新产生 Provider runtime。
- 可审计 recovery contract：新进程直接对空的 process-local Broker `RevokeAttempt` 仍是 `ErrAttemptNotFound`；正确路径必须以 Queue cleanup-only claim 的 exact coordinates/attempt 重新 `OpenAttempt`，经 shared authority 找回同一 session 后 revoke/proof。

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

**Deferred G3/G4:** 两个真实 Worker binary、kill owner、通过 opaque lab binding 连接的已预置真实外部 shared authority及其 reconnect/recovery、Worker/数据库 restart、HA takeover、credential resolver/key rotation 与 Provider canary 留给 Task 29/G3/G4。Task 28B 最多为 `BUILT_CLOSED`，不使任一 Provider 可用。

### Task 28C: Production constructor and Provider registry

**Batch:** C0/C1/C2，1–2 日；只能在 Task 28A、Task 28B 与需要注册的 provider-specific durable integrations 已合并后开始。

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
- 每个已合并 Provider 的 exact adapter/profile/fact-policy/runtime resolver descriptor；External CMDB 必须消费 Task 18B `Produces`。
- existing secure bootstrap/manifest/workload identity patterns；不把 Control Plane config 变成第二 owner。

**Produces:**

- Immutable exact Provider registry；只注册具有已合并 adapter + neutral profile descriptor/fact-policy + durable-integration evidence 的 Phase 1 row。External CMDB registry 必须比较 Task 18B `internal/sourceprofile` canonical descriptor digest，不能重建 metadata；`KUBERNETES_OPERATOR`、`AWX_INVENTORY` 和任何缺依赖 Provider 保持未注册/`UNAVAILABLE`，不得使用 family/default HTTP adapter。
- `internal/discoveryworker.NewProduction(...)`、`cmd/discovery-worker.newProduction(Config)` 和独立 binary startup/readiness/shutdown。
- Production constructor uses PostgreSQL Queue/PageCommitter/Limiter、Task 28B single `AttemptSessionAuthority`、由它构造的 process-local Broker、checkpoint keyring、low-cardinality metrics boundary and mTLS workload identity；constructor 不接受彼此独立的 `SessionOpener` 与 runtime resolver 注入，credential/session transport 只能由该 authority open/recover path 调用。它还产生仅含 Provider/Profile/canonical descriptor/runtime-recovery capability digest 的 safe content-addressed runtime-admission manifest，供 Task 19A Control Plane admission 只读消费；manifest 不含 endpoint、credential、socket、key 或 runtime material。

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

Run: `go test ./internal/discoveryworker ./cmd/discovery-worker -count=1`

Expected: FAIL because production constructor/registry/binary do not exist；Task 28A core itself is an already-merged `Consumes` and is not changed by this RED。

- [ ] **Step 2: Compose the merged Worker core and exact Provider descriptors**

Task 28C 不实现第二个 fenced run loop。它只把 Task 28A `New(Dependencies)` 与真实 PostgreSQL Queue/PageCommitter/Limiter、CheckpointCodec、Task 28B 唯一 `AttemptSessionAuthority` 和 immutable registry 组合；process-local Broker 与 resolver 必须由该同一 authority 构造，禁止分别注入、再次调用 credential resolver 或新建 session。每个 Provider descriptor 必须来自对应已合并 Provider Batch，并与 neutral metadata digest exact 相等。缺 descriptor、Task 28B transport、duplicate Provider/Profile、semantic drift、attempt binding 漂移或 unsupported kind 在创建 Worker 前 fail closed。Core 的 claim、Page/Delay、cleanup、terminal、panic 和 cancellation 行为继续由 Task 28A 四文件唯一拥有。

- [ ] **Step 3: Assemble the real binary without production fake branches**

`cmd/discovery-worker` requires PostgreSQL DSN file, workload identity certificate/key file, CA file, secure source-profile manifest file, Task 28B shared session-authority endpoint/socket, checkpoint keyring file, metrics private bind and worker ID. Files must be absolute, owner-only where secret-bearing, symlink-safe and loaded through existing secure bootstrap patterns. Startup verifies migrations through 000015, manifest digest/signature, registry completeness, mTLS identity, DB time and dependency health before readiness.

The binary does not import `internal/*/memory`, testdata, MSW, Control Plane handler or model/LLM packages. Add AST/import tests proving Provider SDK、Provider HTTP-client、credential/session transport packages are reachable only from `cmd/discovery-worker` production graph and never from `cmd/control-plane`；Control Plane 后续只能 import `internal/sourceprofile` neutral metadata/admission package，其既有 HTTP server graph 不受影响。

- [ ] **Step 4: Verify binary, race, shutdown, and commit**

**G2:**

Run:

~~~bash
gofmt -w $(rg --files internal/discoveryworker cmd/discovery-worker -g '*.go')
go test -race ./internal/discoveryworker ./cmd/discovery-worker -count=1
go build ./cmd/discovery-worker
go test ./cmd/control-plane ./cmd/discovery-worker -run 'Production|Registry|Boundary|Secret' -count=1
git diff --check
~~~

Expected: PASS; missing/stale configuration fails before ready, shutdown cleans credentials/leases, Control Plane has no Provider network/secret dependency and no test fake is production-reachable.

~~~bash
git add internal/discoveryworker/registry.go internal/discoveryworker/registry_test.go \
  internal/discoveryworker/production.go internal/discoveryworker/production_test.go \
  cmd/discovery-worker
git commit -m "feat(assetdiscovery): assemble production discovery worker"
~~~

**Deferred G3/G4:** 两个真实 binary、PostgreSQL reconnect/restart、HA takeover、real workload identity/credential resolver/keyring rotation、全 Provider lab matrix 和发布资格由 Task 29/G3/G4 执行。Task 28C 最多为 `BUILT_CLOSED`；binary 存在不代表任一 Provider 或 Worker 可用。

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
- Consumes Task 28C real binary/registry、Task 28B fixed mTLS recovery client/same-attempt composition、each Provider's merged G2 evidence，以及通过 opaque lab binding 预置的真实外部 shared session authority；Task 29 不拥有 authority server/binary，脚本不得启动或用 fake session map 代替它。
- Produces low-cardinality metrics `asset_source_claims_total{provider,result}`, `asset_source_pages_total{provider,result}`, `asset_source_backpressure_total{provider,reason}`, `asset_source_fence_rejections_total{boundary}`, `asset_source_gate_status{provider,status}`, `asset_source_checkpoint_age_seconds{provider}`.
- Produces signed provider acceptance matrix keyed by exact Provider profile/revision; missing providers remain explicitly `UNAVAILABLE`.
- HA scripts consume only test/lab binding IDs（包括 `AIOPS_DISCOVERY_SESSION_AUTHORITY_LAB_BINDING`）from environment and never print their values；missing binding、mTLS identity failure 或 authority unavailable 必须 fail closed，不能 Skip。

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

`verify-discovery-worker-ha.sh` starts two real Worker processes and PostgreSQL，then uses only `AIOPS_DISCOVERY_SESSION_AUTHORITY_LAB_BINDING` to connect through Task 28B production client to an already-provisioned real external shared session authority；the script neither starts nor implements that authority and never accepts its endpoint/credential as a flag。It queues validation and discovery for every CI protocol provider，kills the lease owner during Provider read、after final page commit and after `RecordCleanup` but before each of `Delay|Complete|Fail`。Replacement Worker 必须取得一个 reclaim/epoch increment 和 exact cleanup-only `RunCoordinates + CleanupAttempt`，先证明其新 process-local Broker 直接 revoke 会 `ErrAttemptNotFound`，再经 production recovery-open 找回同一外部 session 的 revoke handle；它不得获得 `BoundRuntime`、checkpoint、endpoint 或 credential，随后只完成 revoke/proof/receipt 与 deterministic persisted next intent。The drill proves no duplicate same-Run Observation/relation、one append-only unchanged Observation in a later Run、no stale checkpoint commit、one terminal receipt and correct gate. It separately loses the first `Complete/Fail` response and proves exact receipt-first replay succeeds after `LeaseFence.Destroy` while a changed digest is rejected. It also drifts a Source under an expired lease and proves `ReapDrifted` closes the Run/slot without any Provider call；cleanup uncertainty deterministically yields `FAILED + SUSPENDED`. The owned matrix restarts PostgreSQL/Workers and verifies authority reconnect/recovery through the external lab binding，saturates source/workspace/provider limits and proves durable Provider Retry-After/transport backoff/queue rejection/recovery。Missing/unreachable authority、mTLS failure、Skip 或任何脚本内 shared map/fake proof 均不得算 G3 PASS。

Run:

~~~bash
go test -race ./internal/discoveryworker ./internal/discoveryqueue/... ./internal/assetsource/... -count=1
test -n "${AIOPS_DISCOVERY_SESSION_AUTHORITY_LAB_BINDING:-}"
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
