# Production Security Network and Identity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在人的 Keycloak 身份、工作负载 Vault/PKI 身份、Runner Realm、Kubernetes 网络和 DLP/audit 边界上完成生产只读安全闭环，并以多层负向测试证明生产写不可达。

**Architecture:** 人员只通过 Keycloak OIDC 访问 Control Plane；服务使用 audience-bound Kubernetes JWT 向 Vault 认证，并以本地生成 CSR 获取短期 mTLS 证书。每个组件/Realm 使用独立 ServiceAccount、Vault/PKI role 和 default-deny NetworkPolicy；Control Worker 内的 Realm policy controller 只把已发布 Target 的固定 CIDR/port materialize 为版本化策略。Gateway 绑定证书 SAN、workload digest、Realm、Scope revision 与 Grant。DLP 和安全审计覆盖 API、Temporal、Runner、Evidence 和故障输出。

**Tech Stack:** Keycloak Server 26.6.3/keycloak-js 26.2.4、OIDC Authorization Code + PKCE、Vault Kubernetes Auth/PKI/Transit、TLS 1.3/mTLS、Kubernetes projected ServiceAccount tokens/RBAC/NetworkPolicy/Pod Security、Go 1.26.5、OpenAPI、Playwright、gosec/Trivy（CI）。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- Human OIDC 与 workload mTLS 是独立 trust domains；人的 bearer 不能调用 Runner routes，workload certificate 不能调用 human management API。
- Keycloak 使用 production mode、HTTPS、固定 issuer/hostname/audience/client；缺 issuer/JWKS/realm/client 配置立即关闭 human API。
- 浏览器使用 `login-required` + Authorization Code/PKCE；access/refresh token 只存内存，不进 localStorage/sessionStorage/IndexedDB/cookie/log。
- 服务不使用共享 static token/AppRole Secret；只用 audience-bound、短期 projected Kubernetes JWT 登录 Vault。
- mTLS private key 在进程内生成且不可导出，CSR 由 Vault PKI 签名；不得让 Vault 生成并返回 private key。
- 每个 ServiceAccount 只能登录一个或明示的一组最小 Vault roles；READ/VALIDATION/control/PKI/backup roles 分离，WRITE role 不存在。
- certificate SAN、issuer、serial digest、Realm、Scope revision、platform revision 和 workload ServiceAccount 必须同时匹配。
- default-deny ingress/egress；浏览器只到 Control Plane，Runner 只到 Gateway/DNS/time 和 exact Target，SHADOW Runner 无目标 egress，Gateway 不连接 Target。
- Kubernetes NetworkPolicy 不以 DNS 名称做安全承诺；外部 Target 用验证后固定 CIDR/port 或受治理 egress enforcement，DNS 变化使 contract drift 并关闭。
- 不允许 hostNetwork/hostPID/hostIPC/privileged、capability、root、可写 rootfs、任意 hostPath、token auto-mount、exec/port-forward/impersonate/broad RBAC。
- Secret、Token、PEM、DSN、Vault path、endpoint、query/SQL/command、raw error/evidence 不进入可观察面；DLP 命中先停止后审计 code/count。
- Keycloak/Vault/PKI/identity/network/DLP 任一不确定都阻止新 claim；已有工作最多运行到证书/Grant/lease 最短到期。
- 六级 Kill Switch 在 Claim/Start/Heartbeat/Complete 实时覆盖；安全演练不得用直接 SQL 改状态。
- production chart、binary import graph、API/effective actions、Vault policy 和 network graph 都必须证明 WRITE 为空。
- 新增行为严格 TDD，每个 Task 独立 commit。

---

## Fixed Trust and Network Matrix

| Role | Ingress | Egress | Identity |
|---|---|---|---|
| Control Plane | ingress/load balancer HTTPS | PostgreSQL、Keycloak JWKS、audit/evidence、telemetry | `control-plane` SA + Vault control role |
| Control Worker | none | PostgreSQL、Temporal、Vault、audit/telemetry、Kubernetes policy API | `control-worker` SA |
| Outbox | none | PostgreSQL、Temporal、audit/telemetry | `outbox` SA |
| Scheduler | none | PostgreSQL、Temporal、audit/telemetry | `scheduler` SA |
| Discovery Worker | none | PostgreSQL、audit/telemetry + exact allowlisted source endpoints through provider-specific policy | `discovery-worker` SA + source-specific workload binding |
| Gateway | Runner mTLS only | PostgreSQL、Vault/PKI、audit/evidence、telemetry | `runner-gateway` SA |
| Validation Runner | none | Gateway mTLS + exact validation Target | per-Realm validation SA/cert |
| READ Runner | none | Gateway mTLS + exact published Target | per-Realm/family READ SA/cert |

DNS and trusted time egress are separately fixed. No role has Kubernetes Secret read, pod exec, port-forward or WRITE target egress.

### Task 1: Materialize exact Realm and default-deny network policy

**Files:**
- Create: `internal/realmnetwork/model.go`
- Create: `internal/realmnetwork/model_test.go`
- Create: `internal/realmnetwork/controller.go`
- Create: `internal/realmnetwork/controller_test.go`
- Create: `internal/realmnetwork/kubernetes/client.go`
- Create: `internal/realmnetwork/kubernetes/client_test.go`
- Modify: `deploy/helm/aiops/templates/networkpolicy.yaml`
- Create: `deploy/helm/aiops/templates/networkpolicy_test.go`
- Create: `test/security/network/realm_isolation_test.go`

**Interfaces:**
- Consumes: published Runner Realm/Binding、Target origin CIDR/port closure、Platform/Rollout revision、Kill Switch.
- Produces: content-addressed NetworkPolicy revision and readiness/attestation digest.
- Safety: controller cannot accept browser/task/model CIDR/port；unknown CNI feature or target drift closes policy/admission.

- [ ] **Step 1: Write failing policy/model tests**

```go
func TestRealmPolicyUsesOnlyPublishedTargetCIDRPortAndExactServiceAccount(t *testing.T)
func TestRealmPolicyRejectsDNSWildcardLoopbackMetadataAndPrivateExpansion(t *testing.T)
func TestValidationReadAndControlRealmsArePairwiseIsolated(t *testing.T)
func TestShadowRealmHasZeroTargetEgress(t *testing.T)
func TestRenderedNetworkPoliciesDefaultDenyEveryPod(t *testing.T)
func TestNetworkPolicyControllerFencesOldTargetAndPlatformRevision(t *testing.T)
func TestNoPolicyAllowsWriteIngestionSSHDatabaseAdminOrInternetWildcard(t *testing.T)
```

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/realmnetwork/... ./deploy/helm/aiops/templates ./test/security/network -run 'Test(RealmPolicy|ValidationRead|ShadowRealm|RenderedNetwork|NetworkPolicyController|NoPolicy)' -count=1
```

Expected: FAIL because Realm network controller/exact policies are absent.

- [ ] **Step 3: Implement immutable network contract**

```go
type EgressRule struct {
    Protocol string
    CIDRs    []netip.Prefix
    Ports    []uint16
    Purpose  string
}

type RealmPolicy struct {
    ScopeRevision        int64
    RealmID              string
    RealmRevision        int64
    ServiceAccount       string
    TargetDigest         string
    PlatformDigest       string
    RolloutStage         productionplatform.RolloutStage
    Rules                 []EgressRule
    ManifestDigest        string
}

func Compile(RealmBinding, PublishedTarget, PlatformBinding) (RealmPolicy, error)
```

Compiler sorts/deduplicates exact prefixes/ports and rejects `0.0.0.0/0`, `::/0`, loopback, link-local/metadata, multicast, unspecified and any CIDR wider than validation result. Internal Kubernetes Target uses namespace+pod selector only when exact owner/UID projection is available. External DNS is re-resolved through validation, pinned to allowed prefixes and drift-monitored.

- [ ] **Step 4: Reconcile with lease/fence and exact RBAC**

Controller runs in Control Worker, holds Scope+Realm lease, applies policy labeled with digest/revision, reads back normalized spec, compares digest, then marks Realm ready. Old controller fence cannot update readiness. RBAC permits only get/list/watch/create/patch on namespaced NetworkPolicy with fixed label selector；no delete-all/Secret/exec.

- [ ] **Step 5: Render and run real cluster isolation tests**

```bash
helm template aiops deploy/helm/aiops > /tmp/aiops-network.yaml
go test -race ./internal/realmnetwork/... ./deploy/helm/aiops/templates -count=1
go test -tags=e2e ./test/security/network -count=1 -timeout=20m
```

Expected: PASS；every forbidden pair/port fails and exact allowed path succeeds.

- [ ] **Step 6: Commit Realm networking**

```bash
git add internal/realmnetwork deploy/helm/aiops/templates/networkpolicy.yaml deploy/helm/aiops/templates/networkpolicy_test.go test/security/network
git commit -m "feat(security): isolate production read realms"
```

### Task 2: Issue and rotate Vault PKI workload identities

**Files:**
- Create: `internal/workloadidentity/identity.go`
- Create: `internal/workloadidentity/identity_test.go`
- Create: `internal/workloadidentity/vault/client.go`
- Create: `internal/workloadidentity/vault/client_test.go`
- Create: `internal/workloadidentity/rotator.go`
- Create: `internal/workloadidentity/rotator_test.go`
- Modify: `internal/runneridentity/identity.go`
- Modify: `internal/runneridentity/identity_test.go`
- Modify: `internal/productionassembly/dependencies.go`
- Modify: `internal/productionassembly/dependencies_test.go`
- Create: `deploy/vault/policies/production-read.hcl`
- Create: `deploy/vault/policies/production-read_test.go`
- Create: `test/integration/vault/workload_pki_test.go`
- Modify: `deploy/helm/aiops/templates/serviceaccounts.yaml`

**Interfaces:**
- Consumes: projected JWT FD, cluster trust domain, fixed ServiceAccount/namespace/role, Vault TLS endpoint and Realm binding.
- Produces: in-memory non-exportable key + short certificate chain/identity digest and role-specific clients.
- Safety: JWT/cert/key never persists or logs；Vault policy contains no WRITE issuer/path.

- [ ] **Step 1: Write failing identity/role/rotation tests**

```go
func TestVaultLoginBindsAudienceNamespaceServiceAccountAndPlatformRevision(t *testing.T)
func TestCSRKeepsPrivateKeyLocalAndRequiresExactSPIFFESAN(t *testing.T)
func TestWorkloadCertificateTTLIsAtMostThirtyMinutesAndRotatesBeforeHalfLife(t *testing.T)
func TestOldCertificateAndScopeRevisionFailEveryGatewayBoundary(t *testing.T)
func TestVaultPoliciesSeparateControlValidationReadPKIAndBackupRoles(t *testing.T)
func TestVaultPoliciesContainNoWriteCredentialOrBroadPath(t *testing.T)
func TestIdentityFailureClosesReadinessAndNewClaims(t *testing.T)
```

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/workloadidentity/... ./internal/runneridentity ./internal/productionassembly ./deploy/vault/policies -run 'Test(VaultLogin|CSR|WorkloadCertificate|OldCertificate|VaultPolicies|IdentityFailure)' -count=1
```

Expected: FAIL because workload PKI implementation/policies are absent.

- [ ] **Step 3: Implement local-key CSR identity**

```go
type Binding struct {
    TrustDomain      string
    ClusterID        string
    Namespace        string
    ServiceAccount   string
    Component        productionplatform.ComponentKind
    RealmID          string
    RealmRevision    int64
    ScopeRevision    int64
    PlatformDigest   string
}

type Certificate struct {
    Leaf              *x509.Certificate
    Chain             []*x509.Certificate
    Signer            crypto.Signer
    IdentityDigest    string
    NotAfter          time.Time
}
```

Generate ECDSA P-256 key in memory, create CSR with one exact URI SAN, authenticate using JWT audience `vault.aiops.workload`, call only PKI sign endpoint, verify chain/SAN/TTL/key match locally. Zero JWT/CSR buffers after use. Identity digest excludes private material and binds cert serial/SAN/issuer/platform/Realm/Scope.

- [ ] **Step 4: Rotate and fail closed**

Rotate at 50% lifetime with jitter bounded 0–10%；new client connections use new cert, old in-flight connection may finish only before Grant/lease/cert expiry. Three consecutive failures or remaining TTL <5m closes readiness/claims. Revoked/expired cert never maps to Runner identity.

- [ ] **Step 5: Run Vault integration tests**

```bash
go test -race ./internal/workloadidentity/... ./internal/runneridentity ./internal/productionassembly ./deploy/vault/policies -count=1
go test -tags=integration ./test/integration/vault -run 'TestProductionWorkloadPKI' -count=1 -timeout=15m
```

Expected: PASS；private key remains local, roles isolated and rotation/failure closed.

- [ ] **Step 6: Commit workload identity**

```bash
git add internal/workloadidentity internal/runneridentity internal/productionassembly deploy/vault/policies deploy/helm/aiops/templates/serviceaccounts.yaml
git commit -m "feat(identity): issue short production workload certificates"
```

### Task 3: Harden Keycloak Server 26.6.3 human identity and recent authentication

**Files:**
- Modify: `internal/authn/authenticator.go`
- Modify: `internal/authn/authenticator_test.go`
- Modify: `internal/authz/authorizer.go`
- Modify: `internal/authz/authorizer_test.go`
- Create: `internal/authn/keycloak/validator.go`
- Create: `internal/authn/keycloak/validator_test.go`
- Create: `deploy/keycloak/realm-production.json`
- Create: `deploy/keycloak/realm-production_test.go`
- Modify: `web/src/app/auth/keycloak.ts`
- Modify: `web/src/app/auth/keycloak.test.ts`
- Modify: `web/package.json`
- Modify: `web/pnpm-lock.yaml`
- Create: `test/integration/keycloak/oidc_test.go`

**Interfaces:**
- Consumes: fixed issuer/audience/client/realm, HTTPS JWKS and server-side permission mapping.
- Produces: authenticated Subject, `auth_time` recent-auth gate, effective actions and memory-only browser session.
- Safety: no Keycloak admin credential/runtime role-name inference/token persistence.

- [ ] **Step 1: Write failing OIDC/browser tests**

```go
func TestKeycloakValidatorRequiresExactIssuerAudienceAZPNonceTimeAndAlgorithm(t *testing.T)
func TestKeycloakValidatorRejectsJWKSStaleUnknownKIDAndIssuerOutage(t *testing.T)
func TestPlatformDecisionsRequireAuthTimeWithinFiveMinutes(t *testing.T)
func TestPermissionsAreExplicitAndEffectiveActionsServerComputed(t *testing.T)
func TestKeycloakRealmUsesProductionTLSStrictHostnameAndNoDirectGrant(t *testing.T)
```

```tsx
it('uses keycloak-js 26.2.4 login-required and authorization code PKCE')
it('keeps tokens out of every browser persistence API and application cookie')
it('fails closed when production OIDC configuration is absent')
```

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/authn/... ./internal/authz ./deploy/keycloak ./test/integration/keycloak -run 'Test(Keycloak|PlatformDecisions|Permissions)' -count=1
pnpm --dir web test -- --run src/app/auth/keycloak.test.ts
```

Expected: FAIL because production Keycloak contract is incomplete.

- [ ] **Step 3: Implement strict server validation**

Permit only asymmetric `RS256|ES256` configured algorithm, exact HTTPS issuer, audience and authorized party；validate exp/nbf/iat/auth_time with 60s skew, nonce/state/PKCE at browser boundary and KID from fresh TLS JWKS. JWKS cache max age 5m and cannot serve past key-set validity during outage. Map subject/groups to internal permissions through versioned server policy；never trust token-provided effective actions.

- [ ] **Step 4: Pin production realm/client and browser flow**

Realm export has access type public, standard flow enabled, implicit/direct grants/password grants disabled, exact redirect/post-logout origins, WebAuthn/MFA policy for operators, brute-force protection, session idle/max, audit events and no embedded user/password. Keycloak starts `kc.sh start`, not dev mode. Browser initializes once with `onLoad:'login-required'`, `pkceMethod:'S256'`, refreshes before API and clears memory on logout/error.

- [ ] **Step 5: Run real Keycloak tests**

```bash
go test -race ./internal/authn/... ./internal/authz ./deploy/keycloak -count=1
pnpm --dir web test -- --run src/app/auth/keycloak.test.ts
go test -tags=integration ./test/integration/keycloak -count=1 -timeout=15m
```

Expected: PASS using Keycloak Server 26.6.3 production mode and TLS issuer.

- [ ] **Step 6: Commit human identity**

```bash
git add internal/authn internal/authz deploy/keycloak web/src/app/auth web/package.json web/pnpm-lock.yaml test/integration/keycloak
git commit -m "feat(identity): harden production Keycloak access"
```

### Task 4: Exercise DLP, confused-deputy, Kill Switch and complete WRITE closure

**Files:**
- Create: `internal/securityboundary/production_read.go`
- Create: `internal/securityboundary/production_read_test.go`
- Create: `internal/securityboundary/dependency_graph_test.go`
- Create: `test/security/production/dlp_test.go`
- Create: `test/security/production/identity_replay_test.go`
- Create: `test/security/production/kill_switch_test.go`
- Create: `test/security/production/write_closure_test.go`
- Create: `test/security/production/artifact_scan_test.go`
- Create: `test/security/production/run.sh`
- Modify: `internal/executionlease/postgres/repository_test.go`
- Modify: `cmd/write-runner/main_test.go`
- Modify: `deploy/helm/aiops/chart_contract_test.go`

**Interfaces:**
- Consumes: all human/workload/network/Gateway/DLP/audit boundaries and chart/binary graph.
- Produces: signed exercise evidence for `SCOPE_REALM_EXACT`, `NETWORK_DEFAULT_DENY`, `OIDC_RECENT_AUTH`, `WORKLOAD_IDENTITY_VALID`, `DLP_SCAN_CLEAN` and `UNAUTHORIZED_WRITE_SURFACE_ABSENT` gates.
- Safety: tests use unique canaries and scan every durable/observable surface after failure.

- [ ] **Step 1: Write failing adversarial tests**

```go
func TestHumanBearerCannotCallRunnerAndWorkloadCertCannotCallHumanAPI(t *testing.T)
func TestCrossRealmScopeCertificateReplayFailsAllFourBoundaries(t *testing.T)
func TestDNSRebindingSSRFMetadataAndArbitraryEndpointHaveZeroRequests(t *testing.T)
func TestDLPSecretPEMDSNEmailIPCustomerCanariesCreateNoEvidence(t *testing.T)
func TestEveryKillSwitchLevelStopsClaimAndTerminatesAtNextBoundary(t *testing.T)
func TestProductionWriteSurfacesMatchAcceptedManifestAndDenyEverythingElse(t *testing.T)
func TestSecurityArtifactsContainNoCanaryOrRawError(t *testing.T)
```

- [ ] **Step 2: Run tests and verify current boundary gaps**

```bash
go test ./internal/securityboundary ./test/security/production ./internal/executionlease/postgres ./cmd/write-runner ./deploy/helm/aiops -run 'Test(HumanBearer|CrossRealm|DNSRebinding|DLP|EveryKillSwitch|ProductionWrite|SecurityArtifacts)' -count=1
```

Expected: FAIL until all production boundaries and exercises exist.

- [ ] **Step 3: Implement shared preflight and architecture closure**

`securityboundary.Preflight` verifies current platform/rollout, identity, Realm/network digest, Grant/Runtime/Kill Switch and DLP profile before any private Target/credential lookup. Architecture test scans production imports, constructors, chart, Vault policies, OpenAPI and `effective_actions`; any production WRITE symbol/reference/deployment/role/capability fails.

- [ ] **Step 4: Execute real security matrix**

Run tests against the production stack; inject canaries into identity claims, upstream response, Temporal failure, Vault error, Runner completion, browser input and audit outage. Capture DB, Temporal history, Vault audit metadata, app logs, traces, metrics, API/HAR, evidence store and reports; scan for literal/encoded/HMAC-known canaries. DLP match records only fixed class/count/digest.

- [ ] **Step 5: Run security suite**

```bash
./test/production/up.sh
./test/security/production/run.sh
go test -tags=e2e ./test/security/production -count=1 -timeout=45m
./test/production/down.sh
```

Expected: PASS；zero unsafe request/evidence/leak, all Kill Switch levels effective, and every WRITE surface outside the accepted manifest unavailable. The Phase 6 fixture uses an empty manifest；a later accepted Phase 7 successor must pass by exact match, never by disabling this test.

- [ ] **Step 6: Commit security closure**

```bash
git add internal/securityboundary test/security/production internal/executionlease/postgres/repository_test.go cmd/write-runner/main_test.go deploy/helm/aiops/chart_contract_test.go
git commit -m "test(security): prove production read isolation"
```

## Pack Completion Gate

```bash
go test -race ./internal/realmnetwork/... ./internal/workloadidentity/... ./internal/runneridentity ./internal/authn/... ./internal/authz ./internal/securityboundary -count=1
go test ./deploy/helm/aiops ./deploy/vault/policies ./deploy/keycloak ./test/security/network ./test/security/production -count=1
pnpm --dir web test -- --run src/app/auth/keycloak.test.ts
git diff --check
```

Expected: all commands exit 0；network/Realm/workload/human identities isolated, DLP/Kill Switch fail closed and production WRITE graph empty.
