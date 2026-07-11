# Gateway Journal

## 2026-07-11 Runner API v1

- Runner API 使用独立 TLS listener/Router；公共路由绝不复用。
- mTLS 握手只验证静态证书形状，数据库吊销/禁用/scope revision 在每个请求及状态事务重验。
- v1 保留 10 个既定端点；`:release` 仅在 `LEASED` 合法，`:start` 后失败必须完成为
  `UNCERTAIN`。
- 为保持公共控制面无 Vault manager/revoker 能力，WRITE 顺序固定为
  `start(PREPARED + one-time permit) -> credential-anchor(AUTHORIZE/RECORD_ANCHOR/ACTIVATE) -> GO`。
  WRITE Runner 持有 manager；child token 和动态 Secret 永不经过 Gateway。
- job/revocation token 仅由 claim 响应返回，后续只走专用 Authorization scheme。
- OpenAPI 使用 3.1 JSON，便于用 Go 标准库做仓库内合同测试而不引入 YAML 依赖。
- 已合并 migration 不重写；M3 使用 `000009`，investigation 顺延 `000010`。
