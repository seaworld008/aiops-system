# 02 — Connections / Runtime Publication 阶段索引

本目录是 Governed Operations 路线的第二阶段实施计划。目标不是做一个 demo 或只读 pilot，而是交付真实生产级 Connection 发布闭环：

```text
Operational Asset
  → immutable Connection Revision
  → isolated mTLS Validation Runner
  → durable validation/credential cleanup
  → typed Target + Capability compilation
  → immutable Runtime Publication
  → rolling deployment / attestation / rollback
  → Connection + Credential Reference + Runner Realm OIDC Web operations
  → production E2E and recovery acceptance
```

本阶段只发布 Prometheus 与 VictoriaLogs 的受控只读能力。它会形成后续 Grant、主动策略、Kill Switch 和受治理写执行所依赖的不可变 Connection/Realm/Runtime 基础，但不会在本阶段提前放开任何写能力。

## 固定执行顺序

| Order | Task package | Tasks | Outcome | Depends on |
|---:|---|---:|---|---|
| 1 | [01-schema-domain.md](./01-schema-domain.md) | 1–2 | `000016` Schema、Connection/Credential/Operation 领域状态机 | `000015` Asset Catalog |
| 2 | [02-repository-runtime.md](./02-repository-runtime.md) | 3–5 | HA/幂等 Repository、Target/Capability compiler、滚动 Runtime 发布/回滚 | 01 |
| 3 | [03-validation-identity-capsules.md](./03-validation-identity-capsules.md) | 6–7 | 独立 VALIDATION Root/Pool/Realm、签名 Capsule | 01 |
| 4 | [04-validation-protocol-runner.md](./04-validation-protocol-runner.md) | 8–9 | 持久 lease/fencing/cleanup、mTLS protocol、真实 Provider Runner | 01, 03 |
| 5 | [05-openapi-http.md](./05-openapi-http.md) | 10–11 | OIDC/authz、浏览器安全 OpenAPI/HTTP、Operations API | 01–04 |
| 6 | [06-web-publication-flow.md](./06-web-publication-flow.md) | 12–14 | typed client、Connections list/detail、六步验证发布向导 | 05 |
| 7 | [07-governance-inventory-web.md](./07-governance-inventory-web.md) | 15–18 | Credential References / Runner Realms 安全库存、Capability binding 详情、持久设计与真实 OIDC/API Web 验收 | 01–06 |
| 8 | [08-e2e-docs.md](./08-e2e-docs.md) | 19–21 | 生产装配、真实 OIDC/mTLS E2E、axe、运维/状态/CI | 01–07 |

顺序不可交换。02 与 03 的代码实现可以在 01 完成后并行，但 04 必须使用 03 的最终身份/Capsule 契约，05 必须等待后端生产接口稳定，06 必须从 05 OpenAPI 生成类型，07 必须在既有 API/client 上加固安全投影而不能另造契约；08 扩展 07 建立的真实 E2E stack，且是唯一阶段完成门。

## 跨任务包不变量

### Scope 与不可变性

- 所有数据库身份和外键显式包含 Tenant/Workspace/Environment。
- Profile 是稳定身份；Revision、Credential Reference Revision、Capability Definition、Published Target/Set、Runtime Artifact 不原地修改。
- Connection bootstrap 可选择来源有效、映射 `EXACT` 且生命周期为 `DISCOVERED|STALE|ACTIVE` 的 Asset；`QUARANTINED|RETIRED|MISSING|AMBIGUOUS` 和跨 Scope 一律 fail closed。Runtime 精确应用并完成凭据清理后，服务端才可把 `DISCOVERED|STALE` 原子激活为 `ACTIVE`；真实调查仍只允许 `ACTIVE+EXACT+PUBLISHED+AVAILABLE`。
- 运行时对象使用 canonical encoding + SHA-256 内容寻址；在途调查永久固定启动时的 Bundle digest。

### 安全边界

- Validation 与 Investigation 使用独立 Root、SPIFFE Pool、Realm、队列、凭据 issuer、Gateway listener 和 API；两边身份/协议双向不互认。
- Credential 只以 opaque Reference 出现在 Control Plane 和浏览器；secret、token、password、private key、CA PEM、DSN、Vault path、raw upstream body 不进入响应、日志、指标、审计、截图或测试 artifact。
- 发布生产 Revision 要求 ADMIN + recent authentication + change reason + If-Match + Idempotency-Key。
- 测试 fake/MSW 只存在于测试或显式开发环境；生产装配缺任何 PostgreSQL/OIDC/Signer/Realm/Credential/Trust/Network/Distributor 依赖即拒绝启动。

### HA、恢复与发布

- 多 Control Plane/Runner/worker 副本通过 PostgreSQL transaction、optimistic version、durable Operation、short lease、attempt、fencing 和 cleanup receipt 协调。
- 重复请求相同 Idempotency-Key + hash 返回原结果；不同 hash 返回稳定 conflict。
- 验证成功前必须有 Credential `REVOKED` 或 `NO_CREDENTIAL` cleanup receipt。
- Runtime Publication 按固定批次滚动；只有精确 deployment attestation 才打开 capability gate。
- drift、timeout 或 rollout failure 保持 gate closed 并恢复最后 `APPLIED` Bundle；旧 artifact 不修改/删除。

### 前端与可访问性

- OpenAPI 生成类型是唯一浏览器契约；TanStack Router URL state + TanStack Query server state，不引入 Redux。
- Connection、Validation、Health、Runtime 四类状态不合并。
- 六步流程固定为 Scope/Provider → Endpoint/Trust → Credential Reference → Capability/Realm → Validate → Review/Publish。
- `/credential-references` 与 `/runner-realms` 是顶级治理库存页；前者只展示 opaque 安全元数据，后者只展示已登记身份/证书状态与 attested Capability binding，不提供凭据读取或 Realm 扩权入口。
- `docs/design/frontend/connections-runtime.md` 与 `docs/design/frontend/credential-references-runner-realms.md` 是本阶段唯一持久前端细节契约；实现、测试与最终 E2E 必须运行对应 drift checker。
- 1440、1024、390 px 必须完整可操作；键盘、focus、semantic structure、aria-live、WCAG 2.2 A/AA axe gate 必须通过。
- Production Web 使用真实 OIDC authorization-code + PKCE 和真实 API；不得加载 MSW。

## 阶段完成定义

只有 [08-e2e-docs.md](./08-e2e-docs.md) 的最终门全部有真实 PASS 证据，才可将本阶段标为完成：

- migration up/down guard、Scope FK、immutable/state/lease 约束通过真实 PostgreSQL；
- Go unit/race/vet/build 全绿；
- 两个真实 mTLS Validation Runner 能 HA takeover，错误 Pool/Realm 被拒绝；
- Prometheus/VictoriaLogs 固定 Probe、短 Credential cleanup 和 Operation 恢复通过；
- 并发 publish 只产生一个 immutable closure；
- Runtime rolling apply、digest attestation、drift rollback 和在途 Bundle pinning 通过；
- OpenAPI generated contract clean，HTTP redaction/authz/ETag/idempotency 通过；
- Connections、Credential References、Runner Realms Web unit/build、两份设计契约 drift check、真实 Keycloak 测试 Realm OIDC Playwright、1440/1024/390、axe/keyboard 通过；
- Credential Reference 页面无 Secret create/read/edit/reveal/copy/revoke surface；Realm 页面无任意 binding/elevation/connect surface；Scope/filter-bound cursor 与 `effective_actions` 通过真实 API 验证；
- audit/metrics/recovery/runbook/CI 已持久化且不含敏感数据；
- capability registry、API 和 UI 中没有 write action。

## 执行方式

每个任务包都必须使用 `superpowers:subagent-driven-development`（推荐）或 `superpowers:executing-plans` 按 checkbox 执行。每个 Task 独立 TDD、验证和 commit；遇到与预期不一致的测试失败立即停止并诊断，不跳过、不用 fake 替代生产依赖。

建议每完成一个任务包，在本 README 下方维护实际状态，但不要修改固定顺序：

| Package | Status | Evidence commit |
|---|---|---|
| 01 | NOT_STARTED | — |
| 02 | NOT_STARTED | — |
| 03 | NOT_STARTED | — |
| 04 | NOT_STARTED | — |
| 05 | NOT_STARTED | — |
| 06 | NOT_STARTED | — |
| 07 | NOT_STARTED | — |
| 08 | NOT_STARTED | — |
