# AIOps Control Plane

面向中小企业内部使用的证据驱动运维调查与受控执行平台。当前实现以 `AIOPS-IMPLEMENTATION-BLUEPRINT-2026-V3.md` 为权威输入。

## 开发要求

- Go 1.26.5（仓库 `toolchain` 会自动选择）
- PostgreSQL 16+（作用域完整性迁移使用生成列）
- 完整集成测试还需要 Temporal、Keycloak、Vault 和 S3 兼容对象存储

## 本地命令

```bash
make test
make vet
make build
make run
```

启动后可访问：

```text
GET http://localhost:8080/healthz
GET http://localhost:8080/readyz
GET http://localhost:8080/api/v1/session
```

Alertmanager/夜莺 Webhook 必须携带 `X-AIOPS-Signature: sha256=<hex>`，签名内容为原始请求体的 HMAC-SHA256。开发环境可用 `AIOPS_WEBHOOK_HMAC_SECRET`；生产环境必须通过 `AIOPS_WEBHOOK_HMAC_SECRETS_JSON` 按 `integration_id/provider` 隔离，并同时配置 `AIOPS_DATABASE_URL`、`AIOPS_OIDC_ISSUER` 和 `AIOPS_OIDC_CLIENT_ID`，否则控制面拒绝启动。OIDC discovery 只接受 HTTPS；Keycloak Token 还必须携带 `auth_time`、平台角色以及 `aiops_workspaces`、`aiops_environments` 作用域，服务负责人另需 `aiops_services`。数据库 Integration 记录再次校验 Workspace、Provider 和启停状态；后续 Vault 适配器会用其中的 `secret_ref` 替代环境变量密钥。

本机没有 PostgreSQL 时，迁移集成测试会跳过。可设置以下变量运行真实 PostgreSQL 16 的 up/down、作用域和 pgx 仓储测试：

```bash
AIOPS_TEST_POSTGRES_DSN='postgres://aiops:password@127.0.0.1:5432/aiops_test?sslmode=disable' go test -count=1 ./internal/store/postgres
```

当前阶段已提供领域、信号接入和首批只读连接器；真实企业连接器必须使用各环境凭据配置，不随仓库分发。
