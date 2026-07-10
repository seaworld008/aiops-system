# AIOps Control Plane

面向中小企业内部使用的证据驱动运维调查与受控执行平台。当前实现以 `AIOPS-IMPLEMENTATION-BLUEPRINT-2026-V3.md` 为权威输入。

## 开发要求

- Go 1.26.5（仓库 `toolchain` 会自动选择）
- 后续集成测试需要 PostgreSQL、Temporal、Keycloak、Vault 和 S3 兼容对象存储

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
```

当前阶段只提供平台骨架和健康端点；真实企业连接器必须使用各环境凭据配置，不随仓库分发。

