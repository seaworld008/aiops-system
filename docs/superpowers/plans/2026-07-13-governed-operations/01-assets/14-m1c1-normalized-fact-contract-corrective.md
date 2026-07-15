# M1C1 — Normalized Fact Contract Corrective

> 状态：`READY_FOR_IMPLEMENTATION / C0 / RUNTIME_CLOSED`。本包只修正已合并 M1C public normalized-fact ABI 与既有 Asset domain、已确认关系规范和 `000015` PostgreSQL schema 的两个闭包缺口；M1E 在本包 squash merge 前保持暂停。

**Goal:** 让 `assetdiscovery.ValidateFacts` 接受的每个非 tombstone Asset 与 Relationship 都能在不猜测授权事实、不截断数据的前提下进入后继 PageCommitter。

**Architecture:** 以已确认设计规范和 `000015` 为既有唯一契约，不修改 migration、Asset domain 或 Source/Provider outcome ABI。DisplayName 统一采用持久层 256-byte 上限。跨 Environment relationship 的 Policy Reference 由 normalized fact 显式携带并经 `assetcatalog.PolicyReferenceID` 做结构校验；同 Environment edge 禁止携带该值，`discoverysource.pageSemanticBytes` 必须把它按 present frame 计入 page budget。该 opaque ID 只是 untrusted lookup reference，不是策略许可；M1E 必须用 exact locked SourceRevision 和 relation coordinates 从 installed deterministic resolver 取得 expected reference并 exact 比较。既有六元 canonical relation identity 不变，Policy Reference 是同一 edge 的不可变授权元数据，不是制造第二条 edge 的 identity 维度。

## Evidence for reopening M1C

- `internal/assetdiscovery/contracts.go` 当前允许 `NormalizedItem.DisplayName` 1–512 bytes；`internal/assetcatalog/validation.go` 与 `migrations/000015_assets_catalog.up.sql` 均只允许 1–256。
- 已确认规范要求所有 relationship 同 Tenant/Workspace，跨 Environment edge 还必须有显式类型和策略许可。
- `assetcatalog.Relationship` 与 `000015.asset_relationships` 已有 `CrossEnvironmentPolicyReferenceID` / `cross_environment_policy_reference_id`，并强制 same Environment 为 NULL、cross Environment 为有效 opaque reference。
- 当前 `assetdiscovery.ObservedRelation` 没有对应字段，且现有 valid fixture 直接接受跨 Environment edge；后继 M1E 无法在不虚构 Policy Reference 的情况下持久化该事实。
- `internal/discoverysource.pageSemanticBytes` 枚举 relation semantic fields；新增字段若未同步计入，50,000 条 relation 最多可少计约 6.4 MiB，从而绕过 `DiscoverRequest.Limits.MaxPageBytes`。

## Consumes

- 最新 `origin/main` 上已合并的 M1C public contracts。
- 已确认设计规范的跨 Environment relationship policy 边界。
- `assetcatalog.PolicyReferenceID.Valid()`、Asset DisplayName validation 与 `000015` 既有 schema/check constraints。

## Produces

- `NormalizedItem.DisplayName` 的 exact 1–256-byte closed validation。
- `ObservedRelation.CrossEnvironmentPolicyReferenceID assetcatalog.PolicyReferenceID`。
- same Environment relation 必须使用空 Policy Reference；cross Environment relation 必须使用 non-empty 且 `Valid()` 的显式 Policy Reference。
- `discoverysource.pageSemanticBytes` 对每条 relation 把 Policy Reference 作为一个 present framed field计入；不存在的同 Environment值也按 zero-length frame 保持结构确定性。
- 不变的 relation canonical identity：`(source_environment_id,target_environment_id,from_external_id,to_external_id,type,provider_path_code)`；两条只有 Policy Reference 不同、其余六元 identity 相同的事实仍是 duplicate identity，不能成为两条边。
- M1E 的 exact locked Revision resolver 合同：opaque reference 的 `.Valid()` 只代表结构合法；只有 resolver 对 `(source_environment_id,target_environment_id,relationship_type,provider_path_code)` 返回的 non-empty valid expected reference 与 normalized value exact 相等，才代表本页可进入 projection。

本包最多恢复 M1C 的 `BUILT_CLOSED` 稳定输入，不开放 Source、Queue、Worker、Provider 或运行能力；它们继续 `NOT_STARTED/UNAVAILABLE/CLOSED`。

## Exact file ownership

只允许修改原 M1C 的以下四个既有文件：

1. `internal/assetdiscovery/contracts.go`
2. `internal/assetdiscovery/contracts_test.go`
3. `internal/discoverysource/contracts.go`
4. `internal/discoverysource/contracts_test.go`

不得修改 migration、`assetcatalog`、M1E、Queue、Provider、OpenAPI、Web、status 或任何第五个文件。若四文件不足以完成 exact contract，停止并报告主管理会话，不得扩权。

## Fixed implementation contract

1. 将非 tombstone `NormalizedItem.DisplayName` 的 `validSafeText` maximum 从 512 收敛为 256；ExternalID 等其他既有上限不变。
2. 在 `ObservedRelation` 增加且只增加：

~~~go
CrossEnvironmentPolicyReferenceID assetcatalog.PolicyReferenceID
~~~

3. `validateObservedRelation` 在 authority/identity 通过后执行 closed policy-reference structure validation：
   - `SourceEnvironmentID == TargetEnvironmentID`：字段必须为空；
   - `SourceEnvironmentID != TargetEnvironmentID`：字段必须非空且 `.Valid()`；
   - mismatch 或 invalid opaque reference 返回稳定 safe `ErrFactContractViolation`，不得回显被拒值；这里不得把 `.Valid()` 命名或解释为 policy admission。
4. relation duplicate identity map 保持既有六元组，不加入 Policy Reference。Policy Reference 的变化属于同一 edge 的语义/授权漂移，由后继 M1E semantic digest 与持久 immutable guard 处理。
5. 更新本包 fixture：标准跨 Environment relation 必须带合法 Policy Reference；改为 same Environment 的测试必须同时清空该字段。
6. `discoverysource.pageSemanticBytes` 的 relation framed fields 必须加入 `string(relation.CrossEnvironmentPolicyReferenceID)`；预算计算既不能漏计 non-empty reference，也不能依赖 map iteration或 Provider 自报长度。

## C0 RED/GREEN and G2

- [ ] RED：增加 257-byte DisplayName 当前被错误接受的行为测试；生产改动前定向运行并保存 FAIL。
- [ ] RED：增加 cross Environment missing Policy Reference 当前被错误接受的行为测试；生产改动前定向运行并保存 FAIL。
- [ ] GREEN：证明 256-byte DisplayName 接受、257-byte 拒绝。
- [ ] GREEN：证明 canonical cross Environment reference 接受，missing/invalid reference 拒绝；same Environment empty 接受、non-empty 拒绝。
- [ ] GREEN：证明相同六元 relation identity 仅更换合法 Policy Reference 仍返回 duplicate identity。
- [ ] RED/GREEN：构造只因 Policy Reference framed bytes 跨越 `MaxPageBytes` 的 page；生产改动前错误接受，改动后稳定返回 `ErrProviderContractViolation`。
- [ ] 运行：

~~~bash
go test ./internal/assetdiscovery ./internal/discoverysource -count=1
go test -race ./internal/assetdiscovery ./internal/discoverysource -count=1
go mod verify
test -z "$(gofmt -l .)"
git diff --check
go vet ./...
go build ./cmd/control-plane ./cmd/worker ./cmd/read-runner ./cmd/write-runner ./cmd/executor
~~~

- [ ] 审计最终 diff 恰好四个 owned files，定向 secret scan 无命中，工作树 clean。
- [ ] 一次独立 P0/P1 reviewer；发现问题修复后复跑受影响证据并归零。

不运行 PostgreSQL、全仓 race、真实 Provider、HA、恢复、安全、浏览器或发布资格；本包不修改数据库，已有 SQL 只作为 contract truth。以上均明确 deferred 到 M1E G2 或后续 G3/G4，不得写成 PASS。

## Handoff

完成后提交恰好四个 owned files并停止；主管理会话负责 PR、fresh G1、squash merge 和远端 main 验证。随后归档本窗口，从最新 `origin/main` 创建 fresh GPT-5.6 Sol ultra M1E 窗口；不得读取或复用旧 M1E worktree 的未提交内部实现。
