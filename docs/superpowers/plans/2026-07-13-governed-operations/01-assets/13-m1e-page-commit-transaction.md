# M1E — Atomic Page Commit Transaction

> 状态：`READY_FOR_IMPLEMENTATION / RUNTIME_CLOSED`。M1E0 已由 PR #46 合并，[M1C1 corrective](./14-m1c1-normalized-fact-contract-corrective.md) 已由 PR #49 合并；本任务包恢复为 Pack 02 Task 4 与 Pack 09 Task 27 之间唯一的 PageCommitter mutation manifest，fresh 实现 worktree 必须从 `origin/main@c427a6b` 或其后继最新提交创建。快速构建顺序与验证时机仍由[快速开发与真实验收计划](../../2026-07-15-fast-development-validation-program.md)统一拥有。

**Goal:** 在不开放 Queue、Worker 或 Provider 的前提下，实现一个真实 PostgreSQL `SERIALIZABLE` transaction owner，把 normalized asset/relation projection 与 encrypted checkpoint、receipt、Run/Source CAS 原子提交。

**Architecture:** `discoverysource.Page` 继续是 process-local next-checkpoint owner；sealed `assetcatalog.LeaseFence` 单独传入。PageCommitter receipt-first 校验 replay，confirmed-new page 只 Seal 一次，再由同一 SQL transaction 调用 package-private projection helper、持久 checkpoint 与安全 receipt 并完成 fence/CAS 复验。任何失败全部回滚。

## Consumes

- 最新 `origin/main`，其中必须已经合并 M1E0 与 M1C1 corrective；以及此前 M1A PostgreSQL Repository、M1C `assetdiscovery`/`discoverysource` contracts 和 M1D `discoverycheckpoint` Codec。
- `000015_assets_catalog` 现有 Source/Revision/Run/Observation/Asset/Type Detail/Conflict/Relationship、Audit、Outbox、deferred closure 和 sealed `assetcatalog.LeaseFence`。
- 已确认规范的 receipt-first、append-only fact、字段所有权、tombstone/restore、complete snapshot 与 fail-closed 边界。

## Produces

- `discoverysource.PageCommitter`、`PageCommitCoordinates`、`PageCommitResult` 与 exact Profile policy resolver 接口。
- `postgres.NewPageCommitter(...)` 和同包 package-private projection helper。
- 真实 PostgreSQL G2：projection、checkpoint、receipt、Run/Source CAS 与 final-page work result 的单事务证明。

本包最多产生 `BUILT_CLOSED`。Queue lifecycle、cleanup、limiter、Worker、Provider、生产装配、HA/恢复和运行能力均不在本包，继续 `NOT_STARTED/UNAVAILABLE/CLOSED`。

## C0 prerequisite — Observation immutable-prior ACL corrective

M1E 实现前必须先合并本节独立 C0 corrective。`000015` 的 `SECURITY INVOKER enforce_asset_observation_admission()` 继续先对 current Asset 执行 `FOR UPDATE`，由该行锁序列化同一资产的 Observation 投影；随后对 append-only prior Observation 的 exact identity/chain/freshness 复验必须是同一 `SERIALIZABLE` snapshot 内的普通 immutable read，不得获取物理 row lock。Application runtime 对 `asset_observations` 仍只有 `SELECT, INSERT`，不得扩 `UPDATE` ACL、改为 `SECURITY DEFINER`、关闭 immutable guard 或放宽任一 transaction closure。

该 corrective 恰好拥有以下四个文件，与下节 M1E 五文件实现边界分离：

1. `migrations/000015_assets_catalog.up.sql`
2. `internal/assetcatalog/postgres/migration_observation_acl_corrective_integration_test.go`
3. `internal/assetcatalog/postgres/schema_admission.go`，仅更新从 PostgreSQL 18.4 真实 manifest 复核所得 SHA-256
4. 本任务包

C0 corrective evidence：

- [x] RED：真实 PostgreSQL 18.4 application runtime 普通读取 prior Observation 成功、无 `UPDATE` 权限、显式 `SELECT ... FOR SHARE` 稳定返回 `42501`，合法 later Observation 经触发器同样因内部 row lock 返回 `42501`。
- [x] GREEN：仅移除 prior Observation 查询的物理 row lock；合法 later Observation、tombstone 与 restore 成功，previous-chain/freshness regression、伪 prior、并发 current Asset lock 与 fence drift 继续 fail closed。
- [x] ACL/immutable closure：普通 `SELECT` 仍成功；显式 `FOR SHARE`、`UPDATE`、`DELETE`、`TRUNCATE` 均以 runtime 身份返回 `42501`，失败前后 Observation count 与 Asset projection 不变。
- [x] SchemaAdmission：以生产等价只读 `REPEATABLE READ` transaction、固定 `search_path` 和 `quote_all_identifiers` 从真实 catalog manifest 双次重算唯一 SHA-256；旧摘要先关闭 admission，新摘要再通过。
- [x] 已完成 000015 up/down/up、受影响 PostgreSQL tests、G1/G2 与独立 P0/P1 reviewer；以精确四文件 clean commit 交接，G3/G4 仍 deferred，系统保持 `RUNTIME_CLOSED/UNAVAILABLE`。

## Exact file ownership

M1E 恰好新增以下五个文件，不得修改 migration、既有 Repository、M1C/M1D 文件、Queue、cleanup、limiter、Worker、Provider、OpenAPI、Web 或 status：

1. `internal/discoverysource/page_commit.go`
2. `internal/discoverysource/page_commit_test.go`
3. `internal/assetcatalog/postgres/page_committer.go`
4. `internal/assetcatalog/postgres/page_projection.go`
5. `internal/assetcatalog/postgres/page_committer_integration_test.go`

## Exact public ABI

`internal/discoverysource/page_commit.go` 的完整新增公共 ABI 固定为：

~~~go
var (
	ErrPageCommitInvalid     = errors.New("source page commit invalid")
	ErrPageCommitConflict    = errors.New("source page commit conflict")
	ErrPageCommitUnavailable = errors.New("source page commit unavailable")
)

type PageCommitCoordinates struct {
	Locator      assetcatalog.SourceLocator
	RunID        string
	PageSequence int64
}

type PageCommitResult struct {
	RunID                       string
	PageSequence                int64
	CheckpointVersion           int64
	CheckpointSHA256            string
	PageDigestSHA256            string
	RelationPageDigestSHA256    string
	FinalPage, CompleteSnapshot bool
	Replayed                    bool
}

type CrossEnvironmentRelationPolicyCoordinates struct {
	SourceEnvironmentID string
	TargetEnvironmentID string
	RelationshipType    assetcatalog.RelationshipType
	ProviderPathCode    string
}

type PageFactPolicyResolver interface {
	ResolvePageFactPolicy(context.Context, assetcatalog.SourceRevision) (assetdiscovery.FactPolicy, error)
	ResolveCrossEnvironmentRelationPolicy(context.Context, assetcatalog.SourceRevision, CrossEnvironmentRelationPolicyCoordinates) (assetcatalog.PolicyReferenceID, error)
}

type PageCommitter interface {
	ApplyPage(context.Context, assetcatalog.LeaseFence, PageCommitCoordinates, Page) (PageCommitResult, error)
}
~~~

`PageCommitCoordinates` 只含安全 Scope/Source/Run/page identity；concrete next checkpoint 只存在于既有 process-local `discoverysource.Page`，sealed fence 只作为独立方法参数存在。上述类型不得新增 token、raw checkpoint、caller cursor hash、caller page digest、endpoint、credential、runtime、SQL/`pgx.Tx` 或任意持久 transport 字段。

`PageFactPolicyResolver` 必须是确定性、无网络/数据库副作用的已安装 Profile resolver。PageCommitter 只向它传递事务内锁定并 clone 的 exact `SourceRevision`。`ResolvePageFactPolicy` 返回的 provider/freshness/mapping/trusted paths/relationship types 必须与 locked Revision、manifest 及同一 `SERIALIZABLE` snapshot 中按 canonical ordinal 读取的 immutable authority closure 精确复验，`AllowedDocumentFields` 只能来自该 exact profile code 的已安装 immutable policy，不能由 Page、数据库 JSON 猜测或默认放宽。对每条跨 Environment relation，PageCommitter 还必须以 exact locked Revision 和四字段 `CrossEnvironmentRelationPolicyCoordinates` 调用 `ResolveCrossEnvironmentRelationPolicy`；resolver 返回的 `PolicyReferenceID` 必须 non-empty、`Valid()` 且 exact 等于 normalized relation 携带的 lookup reference。字段语法合法本身不是策略许可；resolver 缺失、返回错误、空值、invalid 或 mismatch 均 fail closed。同 Environment relation 禁止携带该字段且不得调用 cross-Environment resolver。

PostgreSQL 公开构造器的完整签名固定为：

~~~go
func NewPageCommitter(
	repository *Repository,
	keyring *discoverycheckpoint.InMemoryKeyring,
	policyResolver discoverysource.PageFactPolicyResolver,
) (*PageCommitter, error)
~~~

构造器必须从传入的同一个 keyring 内部调用 `discoverycheckpoint.NewCheckpointCodec(keyring)`，不接受第二个预构造 Codec，因而不存在 active key ID 相同但 master/state 不同的 keyring/codec 配对。Nil/destroyed/misconfigured dependency 只返回稳定 `discoverysource.ErrPageCommitUnavailable`，不包装底层错误。实现复用现有 `Repository.pool`、安全错误映射和 bounded retry 原则，但不调用现有自开事务的写方法。`page_projection.go` 只提供同包、接收当前 `pgx.Tx` 的 projection helper；helper 不能 begin/commit/rollback，也不能导出 SQL handle。

## Fixed ApplyPage order

1. SQL 前验证 coordinates、Page 关闭形状与非敏感结构；以 exact Tenant/Workspace/Source/Run/page sequence 查询 `PAGE_APPLIED` receipt。若 receipt 存在，先要求 caller `NextCheckpoint.ProfileCode()` exact 等于 receipt closed details 中持久的 safe `profile_code`，再使用 receipt 的 opaque checkpoint key ID/AAD facts 调用 M1D `ReplayIdentity` 并重算整页 semantic identity。Exact match 在 fence admission、Seal 和 live gate 检查前直接返回持久 result 且 `Replayed=true`；missing retained key、wrong profile with same bytes、receipt 畸形或 changed checkpoint/fact/final flag 均 fail closed。
2. 仅对 confirmed-new page 读取 authoritative Source/Run/Revision/authority/checkpoint-before snapshot 与 active key ID；caller `NextCheckpoint.ProfileCode()` 必须先 exact 等于该 locked Revision 的 `ProfileCode`，随后才构造 exact nine-field `CheckpointAAD`。再用持久 owner/epoch/token hash 调用 sealed fence `Matches`，最后调用 `Seal` 恰好一次。Wrong profile 即使 canonical bytes 相同也在 Seal/写入前拒绝；该 sealed envelope 在所有 bounded serializable retries 中复用。
3. 每个 serializable attempt 按固定顺序锁 Run、Source 与 exact published Revision，随后在同一 `SERIALIZABLE` snapshot 中按 canonical ordinal 读取并复验 immutable authority rows，重复 receipt guard，并精确复验 run kind/status/stage、published/gate/revision digests、Revision ProfileCode、page sequence、checkpoint-before/version、lineage state、lease owner/epoch/token hash/expiry；`NextCheckpoint.ProfileCode()` 必须再次等于 locked Revision ProfileCode。Authority child 只可与其 `DRAFT/version=1` parent Revision 在同一创建事务追加，之后 `UPDATE/DELETE/TRUNCATE` 全部关闭；因此不得为物理 child row lock 向 runtime 增加 `UPDATE` 权限或新增 `SECURITY DEFINER` 旁路。PageCommitter 以事务内 locked Revision 解析 exact FactPolicy，先调用 `assetdiscovery.ValidateFacts` 完成结构闭包，再按上述 resolver 契约逐条授权跨 Environment relation并 exact 比较 Policy Reference；任一缺失、错误或不匹配整页关闭。随后以第一次 `transaction_timestamp()` 作为该 attempt 唯一 Catalog acceptance time；Provider item 不提供 Source revision、Catalog time、chain/provenance digest 或主键。
4. Package-private projection helper 以 canonical sorted item identity `(environment_id,provider_kind,external_id)` 和 relation identity `(source_environment_id,target_environment_id,from_external_id,to_external_id,type,provider_path_code)` 投影 append-only Observation、Type Detail、Asset、Conflict、Relationship、Audit 与 Outbox；字段 provenance/fingerprint map 也 canonical sort。它执行同 Run duplicate/碰撞、freshness regression、field ownership、tombstone/restore 与 authoritative final complete-snapshot soft stale/inactive closure，不能覆盖人工治理字段。任何拒绝计数都会使 `effective_complete_snapshot=false`。
5. 每个成功 Page 都封存一个 canonical relation page并把 `relation_page_sequence` 精确推进一次；无 relation 也写 canonical empty relation digest 与 `RELATION_PAGE_COMMITTED` receipt，使 relation/page sequence 始终同速且后续页不会被先前空页卡死。`PAGE_APPLIED` 与 relation receipt、projection、already-sealed ciphertext/key ID/hash/version、Source checkpoint CAS、Run counts/page digests/final work result 必须在同一事务；page/relation digest 由服务端 exact facts计算，不能来自 caller。
6. Receipt semantic identity 使用 domain `asset-source-page-semantic.v1`，绑定 coordinates、exact ProfileCode、按上述规则排序后的全部 item/relation/final semantics（跨 Environment relation 必须包含 M1C1 的 `CrossEnvironmentPolicyReferenceID`），以及 M1D `ReplayIdentity{CheckpointKeyID,DigestSHA256}`；它排除随机 nonce/ciphertext但不排除 checkpoint/profile/relationship-policy 语义。Committed `page_digest` 另绑定 locked revision/profile/gate/fence epoch、server acceptance time、actual sealed checkpoint hash/version、canonical item digest、relation page digest、counts 与 final flags。Receipt closed details 保存 safe ProfileCode、identity/result/AAD metadata，不保存 raw checkpoint、AAD bytes、ciphertext、fence 或 provider document。
7. 更新 Run/Source 后，用同一数据库 `clock_timestamp()` 再验证 lease 未过期且 sealed fence 与持久 owner/epoch/token hash exact match，然后只 commit 一次。Serialization/deadlock retry 复用同一 envelope；commit response ambiguous 时只能回到 receipt-first lookup，若仍无 exact receipt则返回 `ErrPageCommitUnavailable`，本次调用不得重新 Seal 或再次提交。
8. Invalid input/fact（含 normalized Policy Reference 与 resolver expected reference mismatch）映射 `ErrPageCommitInvalid`；idempotency mismatch、stale fence、gate/revision/page/checkpoint CAS drift 映射 `ErrPageCommitConflict`；resolver error/empty/invalid result、codec/keyring/database/ambiguous outcome映射 `ErrPageCommitUnavailable`。所有错误、format/log/receipt/audit/outbox 均不得泄漏底层数据库文本、raw checkpoint/AAD/key/fence/ciphertext、Provider document 或拒绝的 Policy Reference。

## C0/G2 evidence

- [ ] 先写 contract RED：精确 ABI、coordinates/result 安全字段、无 raw checkpoint/fence transport、错误 vocabulary。
- [ ] 再写真 PostgreSQL RED：缺 PageCommitter 时首次原子 page commit 失败；不得用 SQL 文本匹配或 memory fake 代替。
- [ ] 最小实现 receipt-first、single-Seal、bounded serializable retry、包内 projection 与 one-commit closure。
- [ ] Exact locked Revision resolver 对每条跨 Environment relation 绑定 source/target Environment、type、provider path 并返回 expected Policy Reference；missing/error/empty/invalid/mismatch fail closed，同 Environment 不调用 resolver。
- [ ] 真库证明 runtime 可按 canonical ordinal 普通读取 authority，但 `SELECT ... FOR SHARE` 因最小权限稳定拒绝；禁止以扩 `UPDATE` ACL 或 `SECURITY DEFINER` 绕过。
- [ ] 真库两事务交错证明：PageCommitter 锁 exact published Revision并读取 authority snapshot 后，并发向同 Revision 追加 authority 必须被 same-transaction-parent guard 回滚；原事务只能使用未漂移的 exact authority closure。
- [ ] 真库证明 published Revision 的 authority `UPDATE/DELETE/TRUNCATE` 全部拒绝，失败前后 count、ordinal 与 authority digest 不变；并发 publication/gate/revision 漂移只能触发 serializable retry 或 `ErrPageCommitConflict`，不得用旧 snapshot 提交。
- [ ] 真库覆盖首次原子提交、destroyed/stale fence 下 receipt-first exact replay、changed checkpoint/fact/final flag mismatch、wrong-profile/same-bytes 在 replay 与 fresh path 均无 Seal/无写入、missing retained key、每次新页只 Seal 一次、serialization retry envelope 复用、projection/receipt/checkpoint 任一步失败全回滚、空 relation page、final complete-snapshot stale/inactive closure、同 Run collision/freshness regression、Scope/gate/revision/checkpoint/fence drift，以及数据库/错误/日志/receipt 无敏感值。
- [ ] 运行受影响 tests、定向 race、G1/G2、`git diff --check` 与一次独立 P0/P1 复核；提交边界恰好五文件。

Commit-ambiguity 断连、两副本 HA/恢复、完整 Provider/Worker/浏览器/安全/发布资格保留为 G3/G4；这些未执行前不得标为 PASS。完成后由 Queue PostgreSQL lifecycle Batch 冻结 Queue/ClaimResult ABI，不能在本包提前创建。
