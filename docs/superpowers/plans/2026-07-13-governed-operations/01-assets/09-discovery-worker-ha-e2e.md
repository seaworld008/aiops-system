# Discovery Worker, HA Fencing, Backpressure, and Provider Acceptance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 创建真实 `cmd/discovery-worker`、PostgreSQL HA queue/lease/fence、加密 checkpoint、持久限流/背压与全 Provider 生产验收门，使 Source 控制面与发现数据面形成可故障转移的闭环。

**Architecture:** Control Plane 只创建不可变 Source Revision 和 durable Run；Discovery Worker 通过 PostgreSQL `FOR UPDATE SKIP LOCKED` 领取 exact source/revision/gate 任务，使用单调 fence epoch/token 在 validation、runtime resolve、credential open、provider call、page reconcile、checkpoint、heartbeat 和 complete 边界复验。Provider runtime/credential 只在 Worker 内存；页结果经 Schema/DLP 后与加密 checkpoint 在一个事务提交。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4、pgx v5、AES-256-GCM、mTLS workload identity、existing `workerbootstrap`/`securemanifest`、Prometheus client_golang 1.23.2。

## Global Constraints

- 前置完成 [05-source-ingestion-csv-api.md](./05-source-ingestion-csv-api.md)、[06-source-external-cmdb.md](./06-source-external-cmdb.md)、[07-source-vsphere.md](./07-source-vsphere.md) 与 [08-source-proxmox-openstack-cloud.md](./08-source-proxmox-openstack-cloud.md)。
- 每个 Task 严格执行 `Red → Green → Refactor`：先运行并保留预期失败，再做最小生产实现，随后消除重复、复跑指定验证并按 Task 提交；不得跳过失败或弱化断言。
- 生产必须有独立 `cmd/discovery-worker`；不得把 Provider SDK、Credential Resolver 或目标网络客户端装入 Control Plane、通用 `cmd/worker` 或浏览器。
- 持久 Job/Run 只含 Source/Revision/Gate/Checkpoint digest、Scope、Run ID、预算、fence epoch/owner/token hash；不含 endpoint、Secret、raw Token、PEM、cursor plaintext、Header/Body 或 Provider 错误。完整 sealed `LeaseFence` 只由 Claim 返回到当前 Worker 内存，绝不进入 Job/Task/Batch/audit/log payload。
- Raw lease token 只存 Worker 内存，DB 仅存 SHA-256；每次 reclaim 必须 `fence_epoch+1` 且旧 fence 无法 heartbeat/reconcile/checkpoint/complete。
- Checkpoint 使用 AES-256-GCM；唯一 AAD 构造器与 typed `CheckpointAAD` 由 `internal/discoverycheckpoint` 拥有，并用 `FramedTupleV1("asset-source-checkpoint.v1",Tenant,Workspace,Source,Provider,Source definition revision,canonical revision digest,source definition digest,checkpoint key ID,Checkpoint version)` 的精确九字段顺序。key 只通过 workload secret binding 读取。持久 AAD 不含 gate revision/fence epoch/token，因为 checkpoint 必须跨 reclaim 和后续 Run 恢复且 Claim 不得制造 checkpoint 版本变更；每次 Open、Provider call、Reconcile、checkpoint 提交和 Complete 仍分别要求 exact live owner/token/epoch。Codec 必须有 golden bytes/hash、九字段逐项篡改、NULL/empty 和 key-rotation 测试。
- 数据库持久每 source/workspace/provider 并发、token bucket、`not_before`、queue depth 和 failure streak；进程内 semaphore 只是二次保护，不是授权事实。
- Validation Run 可消费 `VALIDATING` revision；Discovery/Import/Ingestion Run 仅可消费 exact `PUBLISHED + ACTIVE + AVAILABLE`。任何漂移停止并关闭影响的 provider/source gate。
- Validation Run 的 checkpoint 输入固定为空；它不得比较、解密或推进当前 published revision 的 Source checkpoint。Discovery/Import/Ingestion 才消费 exact current checkpoint；checkpoint-lineage-rollover 仅走 Pack 01 的受治理同一 Run 例外。
- Credential open/session cleanup 是 terminal 成功的必要证据。每个 attempt 先持久化 Broker-owned opaque UUID，再允许 open；Broker 持有真实 revoke/session handle，Run/API/日志永不携带。cleanup 未知不能把 run 写为成功并必须暂停 Source gate。
- `MANUAL` 不进 Worker；`KUBERNETES_OPERATOR` 由 Phase 3 注册；`AWX_INVENTORY` 由 Phase 5 固定 AWX 契约注册。未注册时都是 `UNAVAILABLE`，不得用通用 Provider 替代。
- 完成后进入 [10-overview-control-room.md](./10-overview-control-room.md)。

## Fast-build checkpoint/transaction ownership correction (2026-07-15)

The previous proposal to combine all Pack 02 Task 4 and Task 27 files into one `M1B-discovery-page-commit` is superseded because it creates a 21+ file XL Batch and a dependency cycle. M1B Source read and M1C `assetdiscovery`/`discoverysource` contracts are now merged. The safe remaining order is: M1D implements only the Checkpoint Codec；one later exact mutation Batch owns both the package-private PostgreSQL projection helper and `PageCommitter`；Queue ABI/PostgreSQL lifecycle、cleanup and limiter are frozen only with their first real consumer and then close in ownership-safe slices.

M1D has exactly two files: `internal/discoverycheckpoint/codec.go` and `codec_test.go`. It does not create `internal/discoveryqueue` or consume `LeaseFence`；existing `assetcatalog.LeaseFence` remains the exact alias of sealed `internal/leasefence.Fence` and is consumed unchanged by the later PageCommitter/Queue batches. This avoids freezing speculative Queue commands before their PostgreSQL state machine and cleanup consumers exist.

The complete M1D public ABI is fixed below；fields and method signatures may not be widened in implementation:

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

In the page mutation Batch, `PageCommitter` is the sole owner of the serializable page transaction. It consumes the concrete next `discoverysource.Checkpoint` from Worker memory, seals it outside SQL with exact `CheckpointAAD`, then begins one transaction that locks and revalidates Run/Source/revision/fence/checkpoint-before, calls the package-private PostgreSQL projection helper, derives the cursor-after hash from the sealed ciphertext, computes the page digest server-side, persists projection/ciphertext/key ID/hash/receipt/checkpoint CAS, revalidates the fence and commits once.

The old Pack 02 sketch in which `Batch` supplies `CursorAfterHash/PageDigest` and `Repository.ReconcileBatch` commits independently remains superseded. The later mutation manifest must list the exact projection/PageCommitter files under one owner with no concurrent edits；it must not pull unrelated queue/cleanup/limiter files into that review unit. No raw checkpoint、fence、`pgx.Tx` or SQL handle crosses a public interface；projection cannot commit without checkpoint, checkpoint cannot commit without projection, and neither path may open a nested transaction.

Because AES-GCM sealing is randomized, receipt replay cannot depend only on a newly sealed ciphertext hash. `ApplyPage` first looks up `(Scope,Run,page sequence)` and verifies normalized item/relation/final semantics plus `HMAC-SHA256(replay_mac_key, FramedTupleV1("asset-source-checkpoint-replay.v1",the same nine typed CheckpointAAD fields,canonical checkpoint bytes))` using the receipt's persisted opaque key ID. `replay_mac_key` is a distinct 32-byte subkey derived from that retained checkpoint master key by HKDF-SHA256 with empty salt and fixed info `asset-source-checkpoint-replay-key.v1`；the AEAD key is never reused directly for HMAC and the derived subkey is cleared after use. This keyed identity excludes ciphertext randomness without persisting a guessable plaintext cursor digest；a different next checkpoint is an idempotency mismatch, and a missing retained key fails closed. An exact receipt returns the persisted result/checkpoint hash before fence admission or sealing. A fresh page seals once and reuses that exact envelope across bounded serialization retries；after an ambiguous commit it performs receipt lookup before any reseal. The final committed page digest still binds the actual persisted ciphertext hash.

This ordering is normative: receipt lookup and semantic/checkpoint replay verification happen before any seal or reseal. Only a confirmed new page may call `Seal`, exactly once；the resulting envelope is reused through bounded serialization retries. An ambiguous commit always returns to receipt lookup before any possible reseal.

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
- Create: `internal/discoverycleanup/broker.go`
- Create: `internal/discoverycleanup/broker_test.go`

**Interfaces:**
- Produces `Queue.Claim/Reclaim/ReclaimFinalizing/ReapDrifted/CancelIneligible/Heartbeat/AdvanceStage/ReserveCleanupAttempt/RecordCleanup/Delay/ProposeValidationResult/PrepareFailureIntent/BeginCheckpointLineageRollover/Complete/Fail` and `PageCommitter.ApplyPage(ctx, LeaseFence, Batch)` with exact sealed `LeaseFence`; raw token is never a Batch field.
- Produces `CleanupBroker.OpenAttempt/RevokeAttempt`；only the Broker owns the revocation/session handle，while Queue stores a random opaque attempt UUID/epoch and verifies signed cleanup proof.
- Produces `CheckpointCodec.Seal/Open` and `Limiter.Acquire/Release/Delay` bound to Source/Workspace/Provider.
- Consumes ten-table `000015` schema, including immutable `asset_source_revision_authorities`; creates no new migration.

- [ ] **Step 1: Write failing reclaim, stale-fence, checkpoint-tamper, and global-limit tests**

~~~go
func TestExpiredRunReclaimInvalidatesOldFence(t *testing.T) {
	queue := openQueue(t)
	first := claimRun(t, queue, "worker-a", 30*time.Second)
	advanceClock(t, 31*time.Second)
	second := claimRun(t, queue, "worker-b", 30*time.Second)
	if second.Epoch != first.Epoch+1 {
		t.Fatalf("epochs = %d, %d", first.Epoch, second.Epoch)
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

func TestValidationRunNeverReadsOrChangesPublishedCheckpoint(t *testing.T) {
	fixture := sourceWithPublishedCheckpointAndNewDraftValidation(t)
	codec := failOnCallCheckpointCodec(t)
	before := fixture.rawSourceCheckpoint(t)
	claim := fixture.claimValidation(t, codec)
	fixture.heartbeatValidation(t, claim)
	fixture.proposeAndCompleteValidation(t, claim)
	if codec.Calls() != 0 || !bytes.Equal(before, fixture.rawSourceCheckpoint(t)) {
		t.Fatal("Validation touched the published Source checkpoint")
	}
}

func TestCleanupReceiptCrashConsumesExactPersistedNextIntent(t *testing.T) {
	fixture := runningRunWithAttempt(t)
	fixture.persistDelayIntent(t, "TRANSPORT_BACKOFF")
	fixture.recordRevokedCleanupThenCrash(t)
	reclaimed := fixture.reclaim(t)
	fixture.assertCleanupOnly(t, reclaimed)
	fixture.consumeDelayIntent(t, reclaimed)
	fixture.assertOneAttemptReceiptAndDelayed(t)
}

func TestCleanupUncertainOverridesPersistedSuccessWithoutReplacingIt(t *testing.T) {
	for _, kind := range []string{"DATA_PROJECTION", "VALIDATION_PROOF"} {
		fixture := finalizingSuccessfulRun(t, kind)
		original := fixture.workResultDigest(t)
		fixture.failCleanupUncertain(t)
		fixture.assertTerminal(t, "FAILED", "SUSPENDED")
		if fixture.workResultDigest(t) != original || fixture.failureOverride(t) != "CLEANUP_UNCERTAIN" {
			t.Fatalf("%s result was replaced", kind)
		}
		fixture.assertNoSuccessPointerAndValidationRejectedWhenApplicable(t)
	}
}

func TestFailureIntentSurvivesCrashesBeforeAndAfterCleanup(t *testing.T) {
	assertReclaimFinalizesPreparedFailureIntent(t, crashBeforeCleanup)
	assertReclaimFinalizesPreparedFailureIntent(t, crashAfterCleanupReceipt)
}

func TestReserveCleanupAttemptResponseLossReturnsSameAttempt(t *testing.T) {
	fixture := claimedRun(t)
	first := fixture.reserveThenLoseResponse(t)
	replay := fixture.reserveAgain(t)
	if replay.AttemptID != first.AttemptID || fixture.attemptCount(t) != 1 {
		t.Fatalf("reserve replay = %#v, first = %#v", replay, first)
	}
}

func TestOpenAttemptResponseLossRevokesKnownAttemptBeforeDelay(t *testing.T) {
	fixture := claimedRun(t)
	attempt := fixture.reserve(t)
	fixture.brokerOpenThenLoseResponse(t, attempt)
	fixture.assertNoSecondOpenOrAttempt(t)
	fixture.revokeRecordAndDelayTransportBackoff(t, attempt)
	fixture.assertBrokerHasNoLiveSession(t, attempt)
}

func TestRevokeAttemptResponseLossReturnsSameProofAndOneReceipt(t *testing.T) {
	fixture := claimedRunWithOpenedAttempt(t)
	first := fixture.brokerRevokeThenLoseResponse(t)
	replay := fixture.brokerRevokeAgain(t)
	if replay.Digest != first.Digest || replay.Status != first.Status {
		t.Fatalf("revoke replay = %#v, first = %#v", replay, first)
	}
	fixture.recordCleanup(t, replay)
	fixture.recordCleanupReplay(t, first)
	fixture.assertAttemptCleanedReceiptCount(t, 1)
}
~~~

Run: `go test ./internal/discoveryqueue/... ./internal/discoverycheckpoint ./internal/discoverylimit/... ./internal/discoverycleanup -count=1`

Expected: FAIL because durable queue/checkpoint/limiter are absent.

- [ ] **Step 2: Implement exact HA claim and fenced state transitions**

`Claim` uses one serializable transaction and `FOR UPDATE SKIP LOCKED`, filters `QUEUED|DELAYED` supported Provider Runs, `not_before<=now`, run-kind-specific source/gate/revision/checkpoint eligibility and persisted capacity. It generates 32 random bytes, returns a sealed process-local fence once, stores only token SHA-256, sets owner/lease/heartbeat sequence, increments epoch and moves stage to `VALIDATING` or `READING`. Validation binds its `VALIDATING` revision but neither compares nor returns the published Source checkpoint. Normal reclaim accepts only an expired `RUNNING` lease whose Source remains exact eligible. If the old attempt is `NOT_OPENED|NO_CREDENTIAL`, it may continue under the new fence；if an opaque attempt is `PENDING`, reclaim sets `CLEANING_UP`, persists/uses a bounded `TRANSPORT_BACKOFF` delay intent and returns cleanup-only work that must revoke then delay before a fresh claim—no Provider/checkpoint/page admission is available. If cleanup is already `REVOKED|NO_CREDENTIAL`, reclaim verifies `ATTEMPT_CLEANED` and executes the previously persisted delay intent；it never resumes Provider work. `ReclaimFinalizing` accepts only an expired `FINALIZING` row, increments the fence and returns cleanup-only work；an already-clean receipt goes directly to the persisted work-result `Complete|Fail`. `CancelIneligible` serializably cancels no-lease `QUEUED|DELAYED` rows after disable/drift and, for an exact Validation Run, atomically rejects the still-bound Revision with stable proof. For an expired drifted `RUNNING` row, `ReapDrifted` advances the fence without Provider/checkpoint access and fails directly only if no credential was opened；otherwise it enters cleanup-only work and requires Broker revocation before terminal failure. `Heartbeat` repeats run-kind-specific exact facts plus token/epoch/owner/strict-sequence：Validation verifies only its empty checkpoint shape，data Runs verify the current Source checkpoint. Maximum extension is 30s. The current holder may fail/clean up before expiry after drift but cannot extend.

`ReserveCleanupAttempt` must commit a random opaque attempt UUID plus the current fence epoch before `CleanupBroker.OpenAttempt` may resolve/open credentials or sessions. It is idempotent for exact `(run,fence epoch)`；a lost response is retried to retrieve the same UUID, never to allocate another. Broker `OpenAttempt(attempt_id)` creates at most one logical session and `RevokeAttempt(attempt_id)` returns one idempotent signed proof. If Open succeeds but its response is lost/ambiguous, Worker must not Open again for work, create a new attempt or make a Provider call；it persists `TRANSPORT_BACKOFF`, revokes the known attempt, records proof and delays. `RecordCleanup` accepts only a signed Broker proof bound to the same Run/attempt/epoch and writes an append-only `ATTEMPT_CLEANED` receipt；the current Run summary is not the history owner. A new Worker can therefore call `RevokeAttempt` using only the opaque UUID, without runtime、checkpoint、credential reference or endpoint. `REVOKED|NO_CREDENTIAL` are clean；missing/invalid/`UNCERTAIN` proof fails the Run and sets gate `SUSPENDED`.

`Delay` requires the current attempt's clean proof, then atomically transitions cleanup-only `RUNNING→DELAYED`, consumes the persisted closed reason `PROVIDER_RETRY_AFTER|TRANSPORT_BACKOFF` and bounded `not_before`, releases capacity and clears the lease while preserving committed page/checkpoint/count progress plus the immutable attempt receipt. The next claim creates a new fence and may clear the current cleanup summary to `NOT_OPENED` only after verifying that receipt. `ProposeValidationResult` persists exact revision/canonical/binding/outcome/proof digest as `VALIDATION_PROOF` and transitions `RUNNING→FINALIZING`；the invalid outcome proposes `FAILED`, never `PARTIAL`. Any other fatal path must call fenced `PrepareFailureIntent` **before cleanup** to persist stable code/digest and transition `RUNNING→FINALIZING/CLEANING_UP`；it cannot overwrite an existing data/validation result. `Complete/Fail` accept a safe terminal command containing Run ID、work-result/intent digest and cleanup digest. They first look up the immutable `TERMINAL_COMMITTED` receipt；an exact replay returns read-only even after the first call destroyed every fence copy, while any changed tuple is rejected. Only the first terminal mutation requires current fence, writes the receipt and atomically updates the bound Revision validation state. If cleanup is `UNCERTAIN` after a success result, `Fail` preserves that result and writes the sole `CLEANUP_UNCERTAIN` override/digest, producing `FAILED + SUSPENDED` and no success pointer. Both terminal methods release capacity, destroy the raw token and freeze terminal Run while preserving owner/token-hash/epoch/heartbeat evidence.

- [ ] **Step 3: Implement atomic page/checkpoint and persisted rate/backpressure**

Provider discovery returns the Pack 05 closed `DiscoverOutcome` with concrete `Page|Delay`, never a struct in which retry and data coexist. `Delay{Reason=PROVIDER_RETRY_AFTER,RetryAfter}` requires `0 < RetryAfter <= 60s` and by construction has no Items、Relations、next checkpoint or final flags. `Page` has no delay and contains the page/checkpoint/final fields. Transport ambiguity is created only by the Worker as Queue `TRANSPORT_BACKOFF` intent（exponential, max 15m）after stopping Provider calls and before cleanup. Neither delay path calls `ApplyPage` or changes checkpoint/counts.

Pack 05 `Checkpoint`/`BoundRuntime` raw access remains process-local and call-site allow-listed：Provider code may decode only temporary callback bytes into a private typed cursor；Worker and `PageCommitter` treat the cursor as opaque and only the checkpoint codec seals/opens canonical bytes. No raw checkpoint/runtime value enters Queue、job、Temporal、audit、receipt、error or log. Validation likewise remains three separate closures：the Worker first validates and recomputes the immutable Provider `ValidationProof` digest，then independently records Broker cleanup/`ATTEMPT_CLEANED`，and only terminal `Complete|Fail` combines the already-sealed validation work-result digest with the cleanup digest. No later cleanup fact may rewrite the Provider proof.

`ApplyPage(ctx, fence, batch)` outer order is fixed：perform exact persisted receipt lookup and semantic/keyed-checkpoint replay verification before any live-fence admission or seal；an exact receipt returns its persisted result. Only after confirming a genuinely new page may it verify the process-local sealed fence and call checkpoint `Seal` exactly once. It then starts the bounded serializable SQL attempt：lock run/source/revision；repeat the receipt guard；verify gate/revision/digest、stage、page sequence and checkpoint-before；call scoped Reconciler, which derives Source revision and Catalog acceptance time rather than accepting them from Provider items；revalidate the same live fence with database `clock_timestamp()`；persist that already-sealed ciphertext/key ID/hash/version、page digest and safe receipt；a final page persists `DATA_PROJECTION` and transitions only to `FINALIZING/CLEANING_UP`；commit. A serialization retry reuses the exact same sealed envelope；an ambiguous commit returns to receipt lookup before any possible reseal. Claim/reclaim never decrypt-and-reseal or bump checkpoint version. A crash before commit changes nothing；after commit an exact replay returns the persisted result even when final cleanup has already made the Run terminal. Checkpoint key rotation reads previous key IDs but every confirmed new page writes the current key.

`BeginCheckpointLineageRollover` is available only to Profiles with a closed expiry reason and a verified Adapter evidence digest. It binds that proof to the exact current fence/Run/revision/checkpoint, degrades the gate and leaves the old checkpoint untouched；the same Run must then emit an authoritative full-snapshot `Page` whose first commit CASes from the old hash into a new lineage. No API/Worker can clear、rewind or create a side Run. Recoverable Provider/transport failure cleans and delays this same Run. Only terminal `SUCCEEDED + effective complete snapshot` seals rollover and restores the gate；any terminal failure or cleanup/checkpoint uncertainty suspends it and requires a newly validated/published revision.

Limiter defaults come from immutable Source Profile and are clamped by server maxima. Persist active slots and next token time using source row/CAS so two replicas cannot exceed source/Workspace/provider limits. Queue depth beyond 10,000 runs/Workspace rejects new sync with `SOURCE_BACKPRESSURE`; no run is silently dropped. Provider `Retry-After` max 60s and exponential transport backoff max 15m are persisted.

- [ ] **Step 4: Verify PostgreSQL failover behavior and commit**

Run:

~~~bash
gofmt -w $(rg --files internal/discoveryqueue internal/discoverycheckpoint internal/discoverylimit internal/discoverycleanup -g '*.go')
go test -race ./internal/discoveryqueue/... ./internal/discoverycheckpoint ./internal/discoverylimit/... ./internal/discoverycleanup -count=1
TEST_DATABASE_URL="$TEST_DATABASE_URL" \
  go test -race ./internal/discoveryqueue/postgres ./internal/discoverylimit/postgres -run Integration -count=1
~~~

Expected: PASS for concurrent claims, lease expiry/reclaim, stale fence at every boundary, crash-before/after-page commit, crash after `RecordCleanup` but before `Delay|Complete|Fail`, exact attempt/terminal receipt recovery, checkpoint tamper/rotation, global limit across replicas, Provider/transport delay, queue overflow and PostgreSQL reconnect.

~~~bash
git add internal/discoveryqueue internal/discoverycheckpoint internal/discoverylimit internal/discoverycleanup
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
- Production constructor uses PostgreSQL Queue/Reconciler, secure Source Profile resolver, Broker-backed workload Credential/Trust resolver, checkpoint keyring, metrics and mTLS workload identity; no fake fallback exists.

- [ ] **Step 1: Write failing production dependency and secret-boundary tests**

~~~go
func TestProductionConstructorFailsClosedForEveryMissingDependency(t *testing.T) {
	valid := validProductionDependencies(t)
	for _, mutate := range []func(*Dependencies){
		func(d *Dependencies) { d.Queue = nil },
		func(d *Dependencies) { d.Reconciler = nil },
		func(d *Dependencies) { d.RuntimeResolver = nil },
		func(d *Dependencies) { d.CleanupBroker = nil },
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
2. for Validation, construct an empty checkpoint input and never read the published Source checkpoint；for data Runs, decrypt the exact checkpoint through keyring；then resolve the non-serializable RuntimeBinding;
3. call `ReserveCleanupAttempt` and only then `CleanupBroker.OpenAttempt` for this source/revision/run/epoch；the Worker receives a non-serializable process handle, never a durable secret payload;
4. advance the stable stage and, for Validation, call fixed `Validate` then fenced `ProposeValidationResult` with exact proof；for discovery, consume only the closed `DiscoverOutcome` (`Page|Delay`) and call `Discover` page-by-page;
5. before and after every network call heartbeat and revalidate the run-kind-specific fence/gate/revision/checkpoint facts;
6. for a Page outcome, advance `NORMALIZING→APPLYING`, perform DLP/schema/budget checks, then `ApplyPage`；cycle to `READING` only for another page;
7. for Provider Retry-After or transport ambiguity, stop all Provider calls；never combine it with data or guess/retry side effects；a verified token-expiry reason may only call `BeginCheckpointLineageRollover` and continue the same authoritative full Run;
8. before cleanup, persist exactly one next path：bounded delay intent for retry、`PrepareFailureIntent` for fatal error、or the already-recorded data/validation work result；then advance `CLEANING_UP`, close/zero runtime and provider response buffers, call Broker `RevokeAttempt`, and persist its signed cleanup proof/immutable attempt receipt;
9. call fenced `Delay` for the persisted `PROVIDER_RETRY_AFTER|TRANSPORT_BACKOFF` intent only after clean proof；otherwise call `Complete/Fail` using the already persisted work result/intent. Cleanup uncertainty preserves any prior work result and uses the closed failure override. Exact terminal replay is served from its receipt before fence matching.

Panic recovery only performs Broker cleanup/failure recording and process health degradation；it cannot mark success. Context cancellation stops new claims and gives current runs at most one lease interval to clean up. A reclaimed pending attempt is cleanup-only, then delayed or failed；it never resumes Provider work under the replacement fence. Unsupported provider closes only its source gate with `SOURCE_PROVIDER_UNAVAILABLE`.

- [ ] **Step 3: Assemble the real binary without production fake branches**

`cmd/discovery-worker` requires PostgreSQL DSN file, workload identity certificate/key file, CA file, secure source-profile manifest file, credential resolver socket, checkpoint keyring file, metrics private bind and worker ID. Files must be absolute, owner-only where secret-bearing, symlink-safe and loaded through existing secure bootstrap patterns. Startup verifies migrations through 000015, manifest digest/signature, registry completeness, mTLS identity, DB time and dependency health before readiness.

The binary does not import `internal/*/memory`, testdata, MSW, Control Plane handler or model/LLM packages. Add AST/import tests proving Provider SDK packages are reachable only from `cmd/discovery-worker` production graph and never from `cmd/control-plane`.

- [ ] **Step 4: Verify binary, race, shutdown, and commit**

Run:

~~~bash
gofmt -w $(rg --files internal/discoveryworker cmd/discovery-worker internal/config -g '*.go')
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

`verify-discovery-worker-ha.sh` starts two real Worker processes and PostgreSQL, queues validation and discovery for every CI protocol provider, kills the lease owner during Provider read、after final page commit and after `RecordCleanup` but before each of `Delay|Complete|Fail`, expires the lease, verifies one reclaim/epoch increment, cleanup-only Broker revocation/receipt consumption by opaque attempt ID, deterministic persisted next intent, no runtime/checkpoint access during that cleanup, no duplicate same-Run Observation/relation, one append-only unchanged Observation in a later Run, no stale checkpoint commit, one terminal receipt and correct gate. It separately loses the first `Complete/Fail` response and proves exact receipt-first replay succeeds after `LeaseFence.Destroy` while a changed digest is rejected. It also drifts a Source under an expired lease and proves `ReapDrifted` closes the Run/slot without any Provider call；cleanup uncertainty deterministically yields `FAILED + SUSPENDED`. It restarts PostgreSQL, saturates source/workspace/provider limits and proves durable Provider Retry-After/transport backoff/queue rejection/recovery.

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
