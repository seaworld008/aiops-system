# Validation Identity and Capsule Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 建立与 Investigation 完全隔离的 VALIDATION 身份/Realm，并签发、验证不可替换的短生命周期 Validation Capsule。

**Architecture:** Control Plane 固定 Realm 和能力绑定，独立 Ed25519 keyring 对 JCS Capsule 签名；Gateway 同时校验 mTLS workload identity、数据库注册和 Capsule claims。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、SPIFFE URI、mTLS、JCS、SHA-256、Ed25519。
## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- 本任务包是生产闭环的一部分，不是 demo；测试 fake 只允许存在于测试进程，生产装配缺依赖必须 fail closed。
- 每个数据库读写显式绑定 Tenant/Workspace/Environment；Revision、Capsule、Target 和 Runtime Artifact 都不可变且内容寻址。
- Validation 与 Investigation 使用独立 Root、SPIFFE Pool、Realm、队列、凭据租约和 Gateway 路由，任何身份或协议不得互认。
- 所有外部输入严格 Schema 校验；公开响应、日志、指标、审计和错误禁止 Credential、token、DSN、PEM、Vault path 或 raw upstream error。
- HA 正确性依赖 PostgreSQL identity registration、Realm revision、keyring revision 和可恢复状态，不依赖进程内 fake。
- 新增行为遵循 TDD：先写失败测试并确认原因，再实现最小生产代码；任务末运行 race 与边界测试。
- 不删除或覆盖用户现有 worktree/改动；完整 Go 质量门使用不包含用户 `.worktrees/` 的隔离 worktree。

### Task 6: Add an isolated VALIDATION Runner identity and Realm boundary

**Files:**
- Modify: `internal/runneridentity/identity.go`
- Modify: `internal/runneridentity/identity_test.go`
- Modify: `internal/runneridentity/files.go`
- Modify: `internal/runneridentity/files_test.go`
- Modify: `internal/runneridentity/postgres/repository.go`
- Modify: `internal/runneridentity/postgres/repository_test.go`
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Create: `internal/connectionvalidation/realm.go`
- Create: `internal/connectionvalidation/postgres/realm.go`
- Create: `internal/connectionvalidation/postgres/realm_test.go`

**Interfaces:**
- Consumes: package 01 Task 1 的 `runner_realms`、`runner_capability_bindings` and `runner_registrations.runner_realm_id`。
- Produces:
  - `runneridentity.PoolValidation`
  - `runneridentity.Options.ValidationRoots []*x509.Certificate`
  - `runneridentity.FileOptions.ValidationClientCAFile string`
  - `connectionvalidation.RealmReader.Resolve(context.Context, ResolveRealmRequest) (Realm, error)`

- [ ] **Step 1: Write failing three-pool identity tests**

```go
func TestIdentityAcceptsValidationURIOnlyUnderValidationRoot(t *testing.T) {
    now := time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC)
    readCA, writeCA, validationCA := newThreePoolAuthorities(t, now)
    verifier, err := runneridentity.NewVerifier(runneridentity.Options{
        TrustDomain: "aiops.example",
        ReadRoots: []*x509.Certificate{readCA.Certificate},
        WriteRoots: []*x509.Certificate{writeCA.Certificate},
        ValidationRoots: []*x509.Certificate{validationCA.Certificate},
        Clock: func() time.Time { return now },
    })
    if err != nil {
        t.Fatalf("NewVerifier() error = %v", err)
    }
    client, err := validationCA.IssueClient(
        "spiffe://aiops.example/runner/validation/validator-01", now,
    )
    if err != nil {
        t.Fatalf("IssueClient() error = %v", err)
    }
    identity, err := verifier.VerifyCertificate(client.TLS.Certificate)
    if err != nil || identity.Pool() != runneridentity.PoolValidation ||
        identity.Instance() != "validator-01" {
        t.Fatalf("VerifyCertificate() = %#v, %v", identity, err)
    }

    wrong, err := readCA.IssueClient(
        "spiffe://aiops.example/runner/validation/validator-01", now,
    )
    if err != nil {
        t.Fatalf("IssueClient(wrong root) error = %v", err)
    }
    if _, err := verifier.VerifyCertificate(wrong.TLS.Certificate); err == nil {
        t.Fatal("validation URI signed by READ root was accepted")
    }
}
```

- [ ] **Step 2: Run the focused identity tests**

Run:

```bash
go test ./internal/runneridentity ./internal/runneridentity/postgres ./internal/config -run 'Validation|ThreePool' -count=1
```

Expected: FAIL because `PoolValidation` and Validation root configuration are absent.

- [ ] **Step 3: Extend the identity enum and SPIFFE parser**

Apply these exact declarations and branches in `internal/runneridentity/identity.go`:

```go
const (
    PoolRead       Pool = "READ"
    PoolWrite      Pool = "WRITE"
    PoolValidation Pool = "VALIDATION"
)

func (pool Pool) Valid() bool {
    return pool == PoolRead || pool == PoolWrite || pool == PoolValidation
}

type Options struct {
    TrustDomain     string
    ReadRoots       []*x509.Certificate
    WriteRoots      []*x509.Certificate
    ValidationRoots []*x509.Certificate
    Clock           func() time.Time
}
```

把构造器中的 root set 固定为三个互不重叠集合：

```go
rootSets := []struct {
    pool  Pool
    roots []*x509.Certificate
}{
    {pool: PoolRead, roots: options.ReadRoots},
    {pool: PoolWrite, roots: options.WriteRoots},
    {pool: PoolValidation, roots: options.ValidationRoots},
}
```

在 `parseSPIFFE` 的严格四段路径解析中增加：

```go
switch parts[2] {
case "read":
    pool = PoolRead
case "write":
    pool = PoolWrite
case "validation":
    pool = PoolValidation
default:
    return "", "", "", false
}
```

三个 Pool 的 CA 证书或 SPKI 发生复用时构造器必须整体拒绝。Validation Registration 必须满足数据库 Pool、SPIFFE Pool、Root Pool、Realm、Scope Revision 和证书全部一致；不要把 `VALIDATION` 映射为 `executionlease.PoolRead`。

- [ ] **Step 4: Add exact Realm resolution**

`internal/connectionvalidation/realm.go`:

```go
package connectionvalidation

import (
    "context"
    "errors"

    "github.com/seaworld008/aiops-system/internal/assetcatalog"
)

var ErrRealmRejected = errors.New("validation Runner Realm rejected")

type Realm struct {
    ID string
    Scope assetcatalog.Scope
    Mode string
    AdapterFamily string
    NetworkZone string
    Enabled bool
    Revision int64
    CapabilityBindingDigest string
}

type ResolveRealmRequest struct {
    Scope assetcatalog.Scope
    RealmID string
    ProviderKind string
    CapabilityKind string
}

type RealmReader interface {
    Resolve(context.Context, ResolveRealmRequest) (Realm, error)
}
```

`postgres.RealmRepository.Resolve` 必须使用一条带 `FOR SHARE OF realm, binding` 的查询，同时要求：

```sql
SELECT
    realm.id::text, realm.tenant_id::text, realm.workspace_id::text,
    realm.environment_id::text, realm.mode, realm.adapter_family,
    realm.network_zone, realm.enabled, realm.revision,
    binding.binding_digest
FROM runner_realms AS realm
JOIN runner_capability_bindings AS binding
  ON binding.tenant_id = realm.tenant_id
 AND binding.workspace_id = realm.workspace_id
 AND binding.environment_id = realm.environment_id
 AND binding.realm_id = realm.id
WHERE realm.tenant_id = $1::uuid
  AND realm.workspace_id = $2::uuid
  AND realm.environment_id = $3::uuid
  AND realm.id = $4::uuid
  AND realm.mode = 'VALIDATION'
  AND realm.enabled = true
  AND realm.adapter_family = $5
  AND binding.provider_kind = $5
  AND binding.capability_kind = $6
  AND binding.status = 'AVAILABLE'
FOR SHARE OF realm, binding
```

- [ ] **Step 5: Add file/config fields and run all identity tests**

新增配置键：

```go
type RunnerGatewayConfig struct {
    Addr                   string
    TrustDomain            string
    ServerCertFile         string
    ServerKeyFile          string
    ReadClientCAFile       string
    WriteClientCAFile      string
    ValidationClientCAFile string
    CredentialKeyringFile  string
}
```

Run:

```bash
go test ./internal/runneridentity ./internal/runneridentity/postgres ./internal/connectionvalidation/postgres ./internal/config -count=1
```

Expected: PASS；任意 root/SPKI 跨 Pool 复用、错误 URI、错误 Realm/Provider/Environment 和 disabled binding 都被拒绝。

- [ ] **Step 6: Commit**

```bash
git add internal/runneridentity internal/config internal/connectionvalidation/realm.go internal/connectionvalidation/postgres/realm.go internal/connectionvalidation/postgres/realm_test.go
git commit -m "feat: isolate validation runner identities"
```

### Task 7: Build and verify signed Validation Capsules

**Files:**
- Create: `internal/connectionvalidation/capsule.go`
- Create: `internal/connectionvalidation/capsule_test.go`
- Create: `internal/connectionvalidation/keyring.go`
- Create: `internal/connectionvalidation/keyring_test.go`

**Interfaces:**
- Consumes: `connectionprofile.Revision`、`connectionvalidation.Realm`、package 01 Task 1 capability definitions。
- Produces:

```go
func BuildCapsule(BuildCapsuleRequest) (Capsule, error)
func SealCapsule(context.Context, Capsule, Signer) (SignedCapsule, error)
func VerifyCapsule(context.Context, SignedCapsule, KeyResolver, time.Time) (Capsule, error)
```

- [ ] **Step 1: Write failing seal/tamper/redaction tests**

```go
func TestSignedCapsuleBindsAttemptScopeTargetBudgetAndExpiry(t *testing.T) {
    publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        t.Fatalf("GenerateKey() error = %v", err)
    }
    signer, err := connectionvalidation.NewEd25519Signer(
        "validation-2026-07", privateKey,
    )
    if err != nil {
        t.Fatalf("NewEd25519Signer() error = %v", err)
    }
    now := time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC)
    capsule, err := connectionvalidation.BuildCapsule(validCapsuleRequest(now))
    if err != nil {
        t.Fatalf("BuildCapsule() error = %v", err)
    }
    sealed, err := connectionvalidation.SealCapsule(
        context.Background(), capsule, signer,
    )
    if err != nil {
        t.Fatalf("SealCapsule() error = %v", err)
    }
    verified, err := connectionvalidation.VerifyCapsule(
        context.Background(), sealed,
        connectionvalidation.StaticKeys{
            "validation-2026-07": {
                PublicKey: publicKey,
                ActiveAt: now.Add(-time.Hour),
                RetireAt: now.Add(time.Hour),
            },
        },
        now,
    )
    if err != nil || verified.Digest() != sealed.Digest {
        t.Fatalf("VerifyCapsule() = %#v, %v", verified, err)
    }

    tampered := sealed
    payload, err := base64.RawURLEncoding.DecodeString(tampered.Payload)
    if err != nil {
        t.Fatal(err)
    }
    payload[len(payload)-1] ^= 1
    tampered.Payload = base64.RawURLEncoding.EncodeToString(payload)
    if _, err := connectionvalidation.VerifyCapsule(
        context.Background(), tampered,
        connectionvalidation.StaticKeys{
            "validation-2026-07": {PublicKey: publicKey},
        },
        now,
    ); !errors.Is(err, connectionvalidation.ErrCapsuleRejected) {
        t.Fatalf("VerifyCapsule(tampered) error = %v", err)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
go test ./internal/connectionvalidation -run Capsule -count=1
```

Expected: FAIL because Capsule constructors and key types do not exist.

- [ ] **Step 3: Implement the complete public Capsule contract**

`internal/connectionvalidation/capsule.go`:

```go
package connectionvalidation

import (
    "context"
    "crypto/ed25519"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "errors"
    "strings"
    "time"

    "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
    "github.com/seaworld008/aiops-system/internal/assetcatalog"
)

const CapsuleSchemaVersion = "connection-validation-capsule.v1"

var ErrCapsuleRejected = errors.New("connection validation capsule rejected")

type Endpoint struct {
    Origin string `json:"origin"`
    ServerName string `json:"server_name"`
}

type CredentialBinding struct {
    ReferenceID string `json:"reference_id"`
    Revision int64 `json:"revision"`
    BindingDigest string `json:"binding_digest"`
    MaxTTLSeconds int `json:"max_ttl_seconds"`
}

type Budget struct {
    MaxDurationSeconds int `json:"max_duration_seconds"`
    MaxResultItems int `json:"max_result_items"`
    MaxResultBytes int `json:"max_result_bytes"`
}

type PrometheusProbe struct {
    Operation string `json:"operation"`
    Expression string `json:"expression"`
    StepSeconds int `json:"step_seconds"`
    LookbackMinutes int `json:"lookback_minutes"`
}

type VictoriaLogsProbe struct {
    Operation string `json:"operation"`
    Query string `json:"query"`
    LookbackMinutes int `json:"lookback_minutes"`
    Limit int `json:"limit"`
}

type BuildCapsuleRequest struct {
    OperationID string
    AttemptEpoch int64
    Scope assetcatalog.Scope
    AssetID string
    ConnectionID string
    ConnectionRevision int64
    ProviderKind string
    Endpoint Endpoint
    TrustReference string
    TrustBundlePEM []byte
    Credential CredentialBinding
    NetworkPolicyReference string
    AllowedPrefixes []string
    RealmID string
    RealmRevision int64
    CapabilityBindingDigest string
    Budget Budget
    Prometheus *PrometheusProbe
    VictoriaLogs *VictoriaLogsProbe
    NotBefore time.Time
    ExpiresAt time.Time
}

type capsuleWire struct {
    SchemaVersion string `json:"schema_version"`
    OperationID string `json:"operation_id"`
    AttemptEpoch string `json:"attempt_epoch"`
    Scope assetcatalog.Scope `json:"scope"`
    AssetID string `json:"asset_id"`
    ConnectionID string `json:"connection_id"`
    ConnectionRevision int64 `json:"connection_revision"`
    ProviderKind string `json:"provider_kind"`
    Endpoint Endpoint `json:"endpoint"`
    TrustReference string `json:"trust_reference"`
    TrustBundlePEM string `json:"trust_bundle_pem_base64"`
    Credential CredentialBinding `json:"credential"`
    NetworkPolicyReference string `json:"network_policy_reference"`
    AllowedPrefixes []string `json:"allowed_prefixes"`
    RealmID string `json:"realm_id"`
    RealmRevision int64 `json:"realm_revision"`
    CapabilityBindingDigest string `json:"capability_binding_digest"`
    Budget Budget `json:"budget"`
    Prometheus *PrometheusProbe `json:"prometheus,omitempty"`
    VictoriaLogs *VictoriaLogsProbe `json:"victorialogs,omitempty"`
    NotBefore time.Time `json:"not_before"`
    ExpiresAt time.Time `json:"expires_at"`
}

type Capsule struct {
    wire capsuleWire
    digest string
}

func (capsule Capsule) Digest() string { return strings.Clone(capsule.digest) }
func (capsule Capsule) OperationID() string {
    return strings.Clone(capsule.wire.OperationID)
}
func (Capsule) String() string { return "<connection-validation-capsule>" }
func (Capsule) GoString() string { return "<connection-validation-capsule>" }

type SignedCapsule struct {
    SchemaVersion string `json:"schema_version"`
    Payload string `json:"payload"`
    Digest string `json:"digest"`
    KeyID string `json:"key_id"`
    Signature string `json:"signature"`
}

type Signer interface {
    KeyID() string
    Sign(context.Context, []byte) ([]byte, error)
}

type KeyRecord struct {
    PublicKey ed25519.PublicKey
    ActiveAt time.Time
    RetireAt time.Time
    Revoked bool
}

type KeyResolver interface {
    Resolve(string) (KeyRecord, bool)
}

type StaticKeys map[string]KeyRecord

func (keys StaticKeys) Resolve(keyID string) (KeyRecord, bool) {
    record, found := keys[keyID]
    record.PublicKey = append(ed25519.PublicKey(nil), record.PublicKey...)
    return record, found
}

func canonicalCapsule(wire capsuleWire) ([]byte, string, error) {
    encoded, err := json.Marshal(wire)
    if err != nil || len(encoded) == 0 || len(encoded) > 128<<10 {
        return nil, "", ErrCapsuleRejected
    }
    canonical, err := jsoncanonicalizer.Transform(encoded)
    if err != nil {
        return nil, "", ErrCapsuleRejected
    }
    digest := sha256.Sum256(canonical)
    return canonical, hex.EncodeToString(digest[:]), nil
}
```

实现以下精确行为：

- `BuildCapsule`：严格验证 UUID Scope、`AttemptEpoch > 0`、小写 canonical HTTPS Origin、ServerName、1–16 个非重叠 CIDR、30–300 秒 Credential TTL、1–20 秒 Probe、唯一 Provider 联合、`NotBefore < ExpiresAt` 且有效期不超过 2 分钟；复制所有 byte/slice。
- `SealCapsule`：签名消息固定为 `"aiops.connection-validation-capsule.v1\x00" + canonical payload`，签名必须 64 字节。
- `VerifyCapsule`：严格 base64url/JCS/Schema/Digest/Key 生命周期/Ed25519/当前时间，重新调用同一结构验证；任何错误只返回 `ErrCapsuleRejected`。
- `NewEd25519Signer`：复制私钥，`String/GoString/MarshalJSON` 固定脱敏；不得复用 `action.Signer` 或 Action keyring。
- 为 Validation Runner 提供只读深拷贝 getter；不得提供返回可修改 backing slice 的方法。

- [ ] **Step 4: Add keyring file loading and negative tests**

Keyring wire 固定为：

```json
{
  "schema_version": "connection-validation-signing-keyring.v1",
  "active_key_id": "validation-2026-07",
  "keys": [
    {
      "key_id": "validation-2026-07",
      "private_key_file": "/run/aiops/validation-signing/validation-2026-07.key"
    }
  ]
}
```

使用现有 `securemanifest.Load` 读取 owner-only 文件；拒绝未知/重复字段、symlink、宽权限、重复 SPKI、无活动 key 和 Action keyring schema。测试 canary 不得出现在 error、`String`、JSON 或日志。

- [ ] **Step 5: Run Capsule tests**

Run:

```bash
go test ./internal/connectionvalidation -run 'Capsule|Keyring' -count=1
go test -race ./internal/connectionvalidation -run 'Capsule|Keyring' -count=1
```

Expected: PASS；字段、预算、时间、签名或 key 生命周期任一漂移均 fail closed。

- [ ] **Step 6: Commit**

```bash
git add internal/connectionvalidation/capsule.go internal/connectionvalidation/capsule_test.go internal/connectionvalidation/keyring.go internal/connectionvalidation/keyring_test.go
git commit -m "feat: seal validation runner capsules"
```
