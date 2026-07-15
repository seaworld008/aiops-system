# M1E0 — Repeated Empty Relation Page Corrective

> 状态：`BUILT_CLOSED / RUNTIME_CLOSED`。已由 PR #46 squash merge 到 `origin/main@4ddb644`；这是 M1E PageCommitter 的 C0 schema 入口门，只修复已确认规范与 `000015` trigger closure 的一个精确冲突。

**Goal:** 允许同一 Run 连续提交两个 canonical empty relation pages，同时继续要求 relation sequence、checkpoint、fence、同事务 exact receipt 和 page closure 全部成立。

**Conflict:** Pack 01 已固定 empty relation page 为 `SHA256(FramedTupleV1("asset-relation-page.v1",0))`，因此任意两个空页 digest 必然相同；但 `enforce_asset_source_run_mutation()` 目前在 snapshot closure 与一般 relation-page advance 两处禁止新 digest 等于旧 digest。Provider 可先发 asset-only page、稍后发 relation page，M1E 又必须让 relation/page sequence 同速，所以当前约束会让连续空页确定性失败。实现不得改成 caller nonce、page-sequence-salted digest 或跳过空 relation receipt。

## Exact file ownership

M1E0 恰好修改四个文件：

1. `migrations/000015_assets_catalog.up.sql`
2. `internal/assetcatalog/postgres/migration_corrective_test.go`
3. `internal/assetcatalog/postgres/migration_adversarial_contract_integration_test.go`
4. `internal/assetcatalog/postgres/schema_admission.go`

不得修改 down migration、Go domain/public ABI、其他 migration、status 或 M1E 五文件。`000015` 尚未生产部署；本包不创建追加 migration。`schema_admission.go` 只允许把 `assetCatalogSchemaManifestSHA256` 更新为 PostgreSQL 18.4 从 corrected exact schema 真库复算的 lowercase SHA-256；不得修改 manifest query、准入逻辑、错误或 public API。

## Exact correction

Pack 01/现有 Go golden 已固定 canonical empty relation-page SHA-256 为 `b89ad607e709ef2ea85f7fc6eb0f80e32ae3ecf234220907a0fe718825f7c151`。只把 `public.enforce_asset_source_run_mutation()` 以下两个“digest 必须不同于上一页”条件收窄为：相等 digest 仅在它 exact 等于该 canonical-empty golden 时允许；相等的任意非空 relation-page digest 仍拒绝。

1. `snapshot_changed` complete-snapshot branch 中的 equality rejection；
2. `relation_page_sequence = OLD.relation_page_sequence + 1` branch 中的 equality rejection。

实现使用上述 exact lowercase SHA-256 literal，并由 `migration_corrective_test.go` 与现有 Go `framedDigest("asset-relation-page.v1","0")` golden 交叉锁定；不得在 PostgreSQL 中创建第二套 tuple encoder，也不得把所有 equality rejection 无条件删除。

以下条件全部保留：relation sequence 只能 stay 或 `+1`；advance 时 digest 必须 non-NULL、合法 SHA-256；相同非空 digest 拒绝；同事务存在 exact `RELATION_PAGE_COMMITTED` receipt，其 request ID 绑定 Run + 新 page sequence且 payload hash 等于 relation digest；Run/Source checkpoint、page、fence、lease、gate、revision、counts、final/effective snapshot 与 deferred closure 全部继续复验。相同 canonical-empty digest 只表示两个页面内容都为空，不表示同一个 page identity；page identity 由单调 sequence 与唯一 receipt request ID 区分。

## C0/G2 evidence

- [x] 先在 `migration_corrective_test.go` 写 source-shape RED，证明两处 equality rejection 仍存在。
- [x] 再在真实 PostgreSQL integration test 写行为 RED：同一 live fenced Run 连续提交两个 empty relation pages（第二个可为 final complete-snapshot empty closure），当前第二次 commit 必须被旧 trigger 拒绝。
- [x] 最小收窄两处 equality predicate，只为 exact canonical-empty golden 增加例外；不改 digest 算法、receipt、sequence 或其他 closure。
- [x] GREEN 证明连续空页提交、同 empty digest 不同 sequence/request ID；同时相同非空 digest、changed/missing receipt、NULL/invalid digest、sequence jump、stale fence、wrong checkpoint 与 non-serializable transaction继续拒绝并全回滚。
- [x] 在 PostgreSQL 18.4 corrected schema 上用生产 manifest query 复算 reviewed SHA-256，更新唯一常量，并证明旧摘要/任一函数体漂移仍被 SchemaAdmission 拒绝。
- [x] 运行受影响 PostgreSQL tests、schema/role admission、up/down/up、G1/G2、`git diff --check` 与一次独立 P0/P1 复核；提交边界恰好四文件。

完成并 squash merge 后验证远端 `main`，归档本任务，再从最新 `origin/main` 创建独立 M1E 实现窗口。M1E0 只关闭 schema 可实施性缺口，不开放任何 Source/Queue/Worker/Provider 能力。
