# Runner Gateway mTLS 与凭据保护文件 staging

Runner Gateway 对服务端证书、私钥、READ/WRITE Client CA 和凭据保护 keyring 采用严格的
fail-closed 文件加载：路径必须是干净的绝对路径；最终对象必须是当前进程 euid
拥有的普通文件；私钥不得有 group/world 权限；证书和 CA 不得 group/world
可写；symlink、hardlink 角色复用、扩展 ACL 和未知 xattr 均被拒绝。
keyring 还必须是 `0400` 或 `0600`、硬链接计数为 1；它不能与任何 TLS 输入共用文件。

Kubernetes Secret/Projected Volume 使用 AtomicWriter：容器看到的固定文件名是
指向时间戳目录的 symlink，并且通常由 root 拥有。因此，不得把主容器的
`AIOPS_RUNNER_GATEWAY_*_FILE` 直接指向 Secret mount。严格 loader 保持拒绝
这种布局；部署必须先将五个固定输入复制到仅存于内存的 staging volume。

## Kubernetes 模板

以下片段假定 control-plane 和 staging init container 都以固定 UID/GID `65532`
运行。`IDENTITY_STAGER_IMAGE` 必须在渲染清单时替换为经过 SBOM、签名和漏洞审查的
内部镜像 digest，例如
`registry.example.com/aiops/identity-stager@sha256:<64-hex-digest>`；禁止 tag、
`latest` 或未替换的占位值进入集群。stager 镜像只需提供 POSIX `sh`、`cp`、
`chmod`、`mv` 和 `stat`，且不得包含网络客户端。

```yaml
spec:
  template:
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        fsGroupChangePolicy: OnRootMismatch
        seccompProfile:
          type: RuntimeDefault
      initContainers:
        - name: stage-runner-gateway-identity
          image: ${IDENTITY_STAGER_IMAGE}
          imagePullPolicy: IfNotPresent
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 65532
            runAsGroup: 65532
            capabilities:
              drop: ["ALL"]
          command:
            - /bin/sh
            - -ec
            - |
              umask 077
              for name in server-chain.pem server-key.pem read-client-roots.pem write-client-roots.pem credential-keyring.json; do
                test -s "/source/${name}"
                cp "/source/${name}" "/staged/.${name}.new"
                chmod 0400 "/staged/.${name}.new"
                mv "/staged/.${name}.new" "/staged/${name}"
                test -f "/staged/${name}"
                test ! -L "/staged/${name}"
                test "$(stat -c '%u:%g:%a' "/staged/${name}")" = "65532:65532:400"
              done
          volumeMounts:
            - name: runner-gateway-identity-source
              mountPath: /source
              readOnly: true
            - name: runner-gateway-identity-staged
              mountPath: /staged
      containers:
        - name: control-plane
          # This value must also be a reviewed, immutable image digest.
          image: ${AIOPS_CONTROL_PLANE_IMAGE}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 65532
            runAsGroup: 65532
            capabilities:
              drop: ["ALL"]
          env:
            - name: AIOPS_RUNNER_GATEWAY_SERVER_CERT_FILE
              value: /var/run/aiops/runner-gateway-identity/server-chain.pem
            - name: AIOPS_RUNNER_GATEWAY_SERVER_KEY_FILE
              value: /var/run/aiops/runner-gateway-identity/server-key.pem
            - name: AIOPS_RUNNER_GATEWAY_READ_CLIENT_CA_FILE
              value: /var/run/aiops/runner-gateway-identity/read-client-roots.pem
            - name: AIOPS_RUNNER_GATEWAY_WRITE_CLIENT_CA_FILE
              value: /var/run/aiops/runner-gateway-identity/write-client-roots.pem
            - name: AIOPS_CREDENTIAL_PROTECTION_KEYRING_FILE
              value: /var/run/aiops/runner-gateway-identity/credential-keyring.json
          volumeMounts:
            - name: runner-gateway-identity-staged
              mountPath: /var/run/aiops/runner-gateway-identity
              readOnly: true
      volumes:
        - name: runner-gateway-identity-source
          projected:
            defaultMode: 0440
            sources:
              - secret:
                  name: aiops-runner-gateway-identity
                  items:
                    - key: server-chain.pem
                      path: server-chain.pem
                    - key: server-key.pem
                      path: server-key.pem
                    - key: read-client-roots.pem
                      path: read-client-roots.pem
                    - key: write-client-roots.pem
                      path: write-client-roots.pem
              - secret:
                  name: aiops-credential-protection-keyring
                  items:
                    - key: credential-keyring.json
                      path: credential-keyring.json
        - name: runner-gateway-identity-staged
          emptyDir:
            medium: Memory
            sizeLimit: 8Mi
```

安全不变量：

- source volume 只挂载到 init container；主容器看不到 AtomicWriter symlink。
- staging 使用 `emptyDir.medium: Memory`，该 volume 本身不落节点持久盘；节点还必须
  禁用 swap，并按企业基线保护 core dump、休眠镜像和物理内存采集。
- init container 与主进程使用相同固定 euid；复制结果是该 euid 拥有的 regular
  file，五个文件统一 `0400`。
- 主容器只读挂载 staging volume；不得再通过 `fsGroup`、sidecar 或 lifecycle hook
  修改文件。
- READ/WRITE CA 必须来自不同签发链；只允许目标 workload 引用该 Secret，且不得给
  control-plane ServiceAccount 授予 Secret `get/list/watch` 权限。
- 凭据保护 keyring 使用独立 Secret 和独立密钥材料，不得复用服务端私钥、Client CA
  私钥或 webhook/OIDC Secret；主容器同样不得拥有其 Kubernetes Secret 读取权限。

如果集群的准入控制器、CSI 驱动或 LSM 为 staging 文件附加未知 xattr/ACL，loader
会拒绝启动。这是预期的 fail-closed 行为。上线前必须在目标 kind/集群、SELinux 或
AppArmor 配置下运行启动验收；不要通过放宽 loader 绕过失败。

## 轮换与恢复

`LoadFiles` 在进程启动时一次性读取并钉住当前内容。Projected Secret 的自动更新
不会替换已复制的 regular file，也不会热更新运行中的 TLS 配置。证书或 CA 轮换必须：

1. 先登记下一证书/信任根并保留当前证书的重叠有效窗口；
2. 更新 Secret 后执行受控滚动重启，让 init container 重新 staging；
3. 验证新 Pod 的 `:8443` TLS 1.3/mTLS 和 READ/WRITE 跨链拒绝；
4. drain 旧连接和旧 Pod 后，再吊销旧证书并移除旧根。

staging、文件校验或 Gateway 初始化任一失败时，Pod 必须保持 NotReady 并停止
rollout。禁止回退到直接 Secret mount、symlink 跟随、root 运行或 group-readable
私钥。由于 staging volume 随 Pod 删除而销毁，重建 Pod 是标准恢复路径。

## 凭据保护 keyring 格式与轮换

keyring 是严格 JSON；未知字段、重复字段（包括转义后的重复字段）、尾随值、非规范
base64url 和超过 32 个 key 都会拒绝启动。每个加密/HMAC key 必须分别由 32 字节随机
材料生成，二者不得相同；以下仅展示结构，尖括号不是可部署值：

```json
{
  "schema_version": "credential-protection-keyring.v1",
  "active_key_id": "key-2026-07",
  "keys": [
    {
      "id": "key-2026-07",
      "encryption_key_b64u": "<32-byte-unpadded-base64url>",
      "hmac_key_b64u": "<different-32-byte-unpadded-base64url>"
    }
  ]
}
```

轮换采用 add-before-remove：先加入新 key 并把它设为 `active_key_id`，同时保留所有仍
被数据库 `encryption_key_id` 引用的旧 key；滚动重启全部 Gateway/吊销 worker；确认
旧引用全部完成吊销或受控重加密后，才能在后续滚动中移除旧 key。loader 不热加载，
文件替换但不重启不会改变运行中进程。任何缺 key 或解密失败都会保持 `REVOKING`、
产生脱敏告警并阻止目标锁释放，禁止为恢复可用性而清空 keyring 或跳过吊销。
