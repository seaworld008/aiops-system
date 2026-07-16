# 前端应用平台与资产治理基础规范

> 状态：Phase 1 唯一前端 Foundation 事实源
> 适用工程：`web/`
> 运行状态：`BUILDING_CLOSED / UNAVAILABLE`
> 上游契约：`api/openapi/control-plane-v1.yaml`

本文固定 Control Plane 浏览器应用的模块边界、状态所有权、认证、网络、共享交互、同源部署和视觉/无障碍规则。后续页面只能扩展领域细节，不得另建认证、路由、API 客户端、状态仓库、视觉系统或平行 Foundation 文档。页面或路由存在不表示对应 Provider、Capability、Action 或生产能力已经可用。

## 1. 产品与安全边界

浏览器是受治理运维控制平面的安全投影视图，不是授权主体、Runner、凭据代理或任意执行面。模型永远不是身份或授权 Principal，也不属于可信计算基。

智能能力只以可深链、可复核的领域对象呈现：

- `Investigation`
- `Evidence`
- `ActionProposal`
- `ActionPlan`
- `Operation`
- `Receipt`
- `Audit`

禁止全局聊天入口、AI 头像、对话气泡、自然语言执行面、通用终端、交互 SSH/WinRM、任意命令/脚本/SQL、任意 Endpoint/Header/Body、Secret 编辑器、凭据粘贴/回显、通用 JSON 编辑器和绕过治理链的快捷动作。

生产拓扑只有一个 Go Control Plane 进程和身份。同一 Origin 提供 `/api/*`、健康/就绪端点与编译后的 SPA；生产环境不运行 Node、Vite、`vite preview`、Next.js、Remix、Node BFF、独立 Web workload、微前端或宽泛 CORS。

## 2. 唯一工程与模块依赖

唯一前端根为 `web/`，模块方向固定为：

```text
app → features → shared
```

- `app/`：只负责 Browser Config bootstrap、OIDC、Provider、Router、AppShell、Scope、导航和全局样式，可组合 `features` 与 `shared`。
- `features/`：按纵向领域切片组织页面、适配器和局部组件；只能导入自身与 `shared`，不得直接导入另一 feature 的页面或组件。
- `shared/`：只包含生成 API、私有 transport、Problem/Operation、共享 UI 和纯工具；不得导入 `app` 或 `features`。
- 跨 feature 协作只传递 typed route、稳定 ID 和共享契约，不能共享可变页面状态。
- 所有 HTTP/SSE 访问只能由 `web/src/shared/api/` 发起。业务模块禁止直接 `fetch`、字符串泛型路径或手写重复 DTO。

ESLint 必须静态强制以上边界，并拒绝显式 `any`、非空断言、未治理的 `console`、生产代码中的测试入口，以及 `shared/api` 之外的直接网络访问。

## 3. 状态所有权

状态按语义分层，不引入 Redux、Zustand 或第二套客户端事实源：

| 状态 | 唯一所有者 | 规则 |
|---|---|---|
| Workspace、Environment、筛选、排序、Cursor、Tab、非敏感选中 ID、时间窗、Operation ID | 已校验 URL path/search | 刷新、后退、前进和分享恢复相同安全投影 |
| 服务端资源、Session、权限和 Operation 投影 | TanStack Query | 每个 key 必须包含 Workspace/Environment；不持久化缓存 |
| 临时表单与校验错误 | React Hook Form + Zod | 只保存在内存；不得成为服务端事实 |
| 抽屉、焦点、展开、临时菜单 | 组件本地 React state | 生命周期不超过当前视图 |
| Auth、Scope、Theme | Context | 仅这三类跨切面状态可使用 Context |

Workspace 和 Environment 只位于 URL，不写入 `localStorage`、`sessionStorage`、IndexedDB 或 Cookie。切换 Scope 前必须通过生成的 `getSession` 投影验证可选范围；切换时取消进行中的旧 Scope 查询并清除对应 Query 缓存。初次补齐缺失 Scope 使用 `replaceState` 并保留其余深链参数；真实 UI 切换使用 `pushState`。`popstate` 必须重新按 Session 白名单校验，授权目标先清理旧 Scope 查询再同步 Context，并保留目标历史项的完整安全深链；非法目标恢复当前安全 URL。

若当前存在 dirty draft，Scope 切换必须弹出阻止式确认：

- “取消”：保持原 Scope 和草稿。
- “放弃并切换”：只丢弃本地草稿，再切换并清理旧 Query。

浏览器后退/前进同样经过该确认：检测到 dirty draft 时先恢复当前 Scope URL，避免 URL 与 Context 分裂；取消保持当前项，确认后再以保存的授权目标 URL 执行受治理切换。

未授权深链接返回同一安全投影的 `403/404`，不得泄露对象是否存在于其他 Scope。

## 4. 公共契约、Problem 与 Operation

公共 API 唯一事实源是 `api/openapi/control-plane-v1.yaml`，唯一生成文件是 `web/src/shared/api/schema.d.ts`。该文件只由 `openapi-typescript` 生成，不得手工编辑或复制 DTO。

`controlPlaneClient` 只公开：

```ts
execute<K extends OperationID>(
  operation: K,
  input: OperationInput<K>,
  options?: {
    signal?: AbortSignal;
  },
): Promise<OperationResult<K>>
```

Operation ID、path/query/header/body input 与成功响应必须从生成的 `operations`/`paths` 推导。HTTP method/path registry 和底层 fetch 保持私有，并以 OpenAPI operation contract 测试覆盖。

可选 `options` 是 closed cancellation context，只允许 `AbortSignal`，不属于 API payload，也不能承载 base URL、任意 Header、path、body 或 transport 配置。Query/Operation adapter 必须把 TanStack Query 提供的同一 `signal` 传入 `execute`，使 Scope `cancelQueries` 能真实终止旧 Scope HTTP。

每个受认证请求：

- 先调用内存 Token Provider 的 `updateToken(30)`；
- 只使用 Browser Config 的同源 `api_base_path`；
- 使用 `credentials: "omit"` 与 `cache: "no-store"`；
- 只发送契约声明的 `Authorization`、`Idempotency-Key`、`If-Match` 和内容协商 Header；
- 不记录 Token、请求/响应 body、query 值、labels、external ID、原始 Problem detail 或上游正文。

RFC 9457 Problem 使用 closed Zod schema 校验，至少保留 `type`、`title`、`status`、稳定 `code` 和 `trace_id`。未知或畸形响应投影为 `unexpected_response`，只可使用响应 `X-Trace-ID` 作为安全关联信息。

Query key 采用：

```text
[domain, workspaceId, environmentId, normalizedFilters...]
```

共享 `useOperation` 只轮询已存在的 durable Operation：

- `operationId` 保存在 URL；
- 页面 hidden 或浏览器 offline 时暂停；
- focus/online 后恢复；
- 遵守有界 `Retry-After`，否则使用 capped backoff；
- adapter 把 query function 收到的 `AbortSignal` 原样传给 `controlPlaneClient.execute`；
- adapter 声明的 terminal 状态立即停止；
- 永不重放发起 Operation 的 mutation。

## 5. Browser Config 与 OIDC bootstrap

入口顺序不可交换：

```text
GET /api/v1/browser-config
  → closed Zod validation
  → keycloak-js init
  → authenticated getSession
  → render Providers / Router / AppShell
```

匿名 Browser Config 请求固定：

- URL：`/api/v1/browser-config`
- `cache: "no-store"`
- `credentials: "omit"`
- `redirect: "error"`
- 不发送 Authorization

closed schema 只接受：

```json
{
  "oidc": {
    "url": "https://identity.example.com",
    "realm": "aiops",
    "client_id": "control-plane-web"
  },
  "api_base_path": "/api/v1",
  "build": {
    "version": "1.0.0",
    "commit": "immutable-commit",
    "contract_digest": "sha256:..."
  }
}
```

`api_base_path` 必须是 same-origin 绝对路径；OIDC URL 始终使用 HTTPS，并拒绝 localhost、loopback、private/link-local IP、`.local`、`.internal`、`.test` 等非公开主机。额外字段、secret-like 字段、UserInfo、query、fragment、私有运行端点、Token、Credential Reference、Vault 路径、任意 Header 或畸形 build identity 均 fail closed。

Keycloak 固定为 Authorization Code + PKCE：

- `onLoad: "login-required"`
- `pkceMethod: "S256"`
- `checkLoginIframe: false`
- `enableLogging: false`
- 公共 Client：`control-plane-web`
- Token 只存在于 `keycloak-js` 实例内存
- 每次 API 请求前 `updateToken(30)`
- reauthentication 使用 `prompt: "login"`、`maxAge: 0`
- return URL 必须解析为当前 Origin

不得访问或写入 localStorage、sessionStorage、IndexedDB 和应用 Cookie。Browser Config、OIDC 或 Session 任一步失败都显示无匿名降级的关闭态错误页；重试必须重新从 Browser Config 开始。

## 6. 路由、导航与 URL schema

Phase 1 Foundation 建立稳定扁平路由入口：

```text
/overview
/incidents
/investigations
/action-plans
/proactive-policies
/assets
/assets/:assetId
/asset-mappings
/connections
/asset-sources
/credential-references
/runner-realms
/capabilities
/governance/policies
/platform/readiness
/audit
/production/releases
```

Task 9 不创建 Tasks 10–12 的 feature 页面。当前未实现路由只能在导航中以 `aria-disabled="true"` 和“后续阶段”展示，不能成为死链接、空成功页面或能力已开放的暗示。

所有路由继承 URL 中的 `workspace` 与 `environment`。领域页面后续可扩展 closed search schema，但必须遵循：

- 数组排序、去重后再写回 URL；
- 任意筛选/排序变化清除 Cursor trail；
- ID、Cursor、query 和枚举均有长度/格式上限；
- 不把 Token、Secret、原始 payload、凭据引用内部值或敏感 Evidence 写入 URL；
- Operation ID 仅指向服务端安全投影。

导航使用完整产品名称；“虚拟机”不得缩写为含糊的 “VM”，VictoriaMetrics、VictoriaLogs、VictoriaTraces 必须完整显示。

## 7. AppShell 与共享 primitives

桌面壳层固定：

```text
220px 领域导航 + 46px Scope 条 + 内容区 + 可选 460px Drawer
```

中文可见标签分组：

- 运行：总览、事件处置、调查记录、主动调查、受治理动作
- 资产与连接：资产目录、映射工作台、连接与数据源、发现与同步、凭据引用、Runner 与能力
- 治理：授权与策略、审计日志、生产发布

页面顺序为 Breadcrumb → 标题/状态/一个主操作 → 筛选/动作条 → 高密度数据面。提供跳到主内容的 skip link；焦点顺序与 DOM 顺序一致。

Phase 1 只实现一套共享 primitives：

- `DataTable`
- `FilterBar`
- `CursorPagination`
- `Drawer`
- `StatusBadge`
- `ProblemPanel`
- `OperationTimeline`
- `EffectiveActionGate`
- `ETagConflictReview`
- `ReauthBoundary`
- `AbsoluteTime`

权限只读取资源 DTO 的 `effective_actions`，不得按 `roles`、用户名、导航分组或前端枚举推断。状态必须使用文字与结构，颜色不是唯一载体。

## 8. 治理 mutation

治理 mutation 始终等待服务端确认：

- 禁止 optimistic update；
- 禁止自动 retry；
- 禁止自动重放副作用；
- 使用新的 `Idempotency-Key`；
- 更新使用当前 `ETag/If-Match`；
- 高风险动作先完成最近认证；
- 异步动作只跟随返回的 durable Operation。

`409` 保留当前上下文，使用 `ETagConflictReview` 展示旧值与服务端新值，要求“重新加载并审阅”；不得自动覆盖或再次提交。`401` 最近认证要求交给 `ReauthBoundary`，return URL 只保存 same-origin 非敏感状态。

发布、撤销、隔离、停止、策略启停等结果在操作附近持久展示审计/Trace/Operation ID；Toast 只用于低风险、可撤销反馈。

## 9. 视觉 Token 与无障碍

唯一 semantic tokens：

```css
--color-bg: #f4f6f8;
--color-surface: #ffffff;
--color-nav: #17212b;
--color-text: #17202a;
--color-muted: #52606d;
--color-border: #d7dde3;
--color-primary: #1f5ea8;
--color-success: #287a4b;
--color-warning: #9a5b0a;
--color-danger: #b42318;
--nav-width: 220px;
--context-height: 46px;
--drawer-width: 460px;
--table-row-height: 38px;
```

间距基线为 4px；圆角只使用 4px/6px；正文 14px/20px，元数据 12px，标题 20–24px。ID、Digest、绝对时间和计数使用等宽或 tabular numerals。页面主要依赖 1px 边界和背景分层，阴影只用于真实浮层。

禁止渐变、玻璃拟态、霓虹、发光、3D、装饰性 Bento、超大营销卡片和无信息价值动画。Focus 至少 2px 可见轮廓；所有图标有可访问名称；表单使用持久 Label；触控目标至少 44px；过渡为 120–180ms，并在 `prefers-reduced-motion: reduce` 下关闭。

目标为 WCAG 2.2 AA，包括键盘操作、skip link、焦点恢复、非颜色状态提示、屏幕阅读器名称和合理标题层级。

## 10. 响应式

- `≥1440px`：完整导航、高密度表格与 460px Drawer。
- `1024–1439px`：折叠次要筛选，保留身份/状态列。
- `768–1023px`：Drawer 改为独立详情路由，双栏降为单栏。
- `<768px`：只保证查询、筛选、查看健康、停止和升级人工；高风险治理 mutation 明确要求桌面完成。

窄屏不得通过挤压桌面 Drawer、缩小文字或隐藏安全状态制造“响应式”。键盘焦点和 URL 状态在布局切换后仍须可恢复。

## 11. Go 同源静态服务

`AIOPS_WEB_ROOT` 指向编译产物根；生产值固定为 `/opt/aiops/web`，且必须是安全的绝对 clean path。启动时必须同时存在：

- `index.html`
- `.vite/manifest.json`

缺任一文件即启动 fail closed。启动后 `index.html`、manifest 或 manifest 引用的任一哈希 asset 消失、不再是普通文件或越出 root 时 readiness fail closed；该检查与现有数据库/OIDC/Schema readiness 使用 AND 关系。

SPA fallback 规则：

- `/api` 及其全部子路径、`/healthz`/`/readyz` 及其子路径永不 fallback；
- 非 `GET/HEAD` 永不 fallback；
- 只允许 normalized、extensionless、Accept HTML 的浏览器路由 fallback 到 `index.html`；
- 拒绝 traversal、`//`、literal backslash、NUL、dot segment、编码或双重编码的 `/`、`\`、`.`、`..`、root escape、文件/目录 symlink escape 和畸形路径；
- 已存在静态文件按实际路径服务，未知带扩展名路径返回 404。
- 禁止目录列表；目录请求只可按明确的 SPA fallback 规则处理。

缓存与响应头：

- `index.html`：`Cache-Control: no-store`
- 哈希 `/assets/*`：`Cache-Control: public,max-age=31536000,immutable`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: no-referrer`
- CSP：

```text
default-src 'self';
script-src 'self';
style-src 'self';
connect-src 'self' <OIDC-origin>;
frame-ancestors 'none';
base-uri 'none';
object-src 'none';
form-action <OIDC-origin>
```

不允许 inline script/style 例外、`unsafe-inline`、`unsafe-eval`、通配 connect、跨域表单目标或 permissive CORS。

## 12. 测试与关闭态交付

Vitest/jsdom 使用测试专用 MSW；生产 `main.tsx` 和 production bundle 不得导入 MSW、fixture、loopback transport 或 fake identity。Playwright、真实 Keycloak 和真实浏览器资格属于后续 G3/G4，本 Task 只建立可测试接口并保持能力关闭。

Task 9 完成至少证明：

- Browser Config 在 OIDC 前加载且畸形时关闭；
- Token 不持久化，每请求刷新；
- generated contract 独立 drift 检查可真实失败；
- method/path registry 与 OpenAPI operation IDs 一致；
- Scope query key、切换取消/清理和 dirty draft 确认；
- Operation hidden/offline/polling/terminal 行为且不重放 mutation；
- AppShell skip link、键盘、响应式和 reduced motion；
- SPA reserved path、fallback、cache、traversal、CSP 和 readiness；
- production bundle 无 source map、Token、Client Secret、MSW 或第二套运行时。

这些证据最多把本批次标记为 `BUILT_CLOSED`，不得描述为生产可用或完整资产治理闭环。
