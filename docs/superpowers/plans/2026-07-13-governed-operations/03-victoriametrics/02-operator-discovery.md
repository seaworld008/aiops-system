# VictoriaMetrics Operator Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 通过 Kubernetes API 安全发现 VictoriaMetrics Operator 的全部 21 种公开资源、生成组件与拓扑关系，并以 HA、幂等、Secret 零读取的方式写入统一资产目录。

**Architecture:** API discovery 先解析集群实际 served GVR；配置 CRD 永远使用 `PartialObjectMetadata`，长期运行 CR 使用严格字段投影，原始 `unstructured` 对象不跨越 projector。发现 worker 通过 PostgreSQL advisory lock 单活、watch/relist 恢复与 Phase 1 complete-snapshot reconciliation 保证 HA；Owner UID 是唯一拓扑依据，名称和镜像仅用于安全展示与版本证据。

**Tech Stack:** Go 1.26.5、Kubernetes client-go v0.36.2、dynamic/metadata/discovery clients、pgx v5、Phase 1 `assetdiscovery.Reconciler`、Prometheus metrics。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- 必须覆盖 Operator 资源页当前列出的 21 种 CR；目录缺项、重复项或未知项都使测试失败。
- 优先 served `operator.victoriametrics.com/v1`，并支持集群仍提供的 `v1beta1`；不固定 storage version，也不扫描无关 API group。
- 发现进程不得对 core `Secret` 发出 LIST/GET/WATCH；RBAC 中不得出现 `secrets` resource 或通配符 resource/verb。
- `VMUser` 只通过 metadata client 读取，Operator 生成 Secret 只成为不可逆 Opaque Credential Reference ID；用户名、密码、bearer、Secret data/stringData 均不得进入内存投影。
- 所有配置 CRD 使用 metadata-only 路径；不得读取 VMRule expressions、scrape config、VMUser inline credential 或 AlertManager config body。
- 长期运行 CR 只读取固定 allowlist：identity、generation、replica count、product version、condition type/status；禁止 marshal 原始对象、spec、status、annotations、managedFields。
- Pod/Deployment/StatefulSet/Service 只投影 owner UID、固定 Operator labels、replicas、ready replicas、service port role 和 image version；禁止 env、args、volumes、SecretRef、ConfigMapRef、annotation 与 Service account token。
- 拓扑关系只接受 exact UID/OwnerReference；禁止名称相似、namespace fallback、label-only 猜测。
- Insert、storage、agent、configuration 和 tool 即使被发现也不获得 Query Target；资格由 taxonomy 包决定。
- complete snapshot 只有在全部 mandatory GVR 成功列举后才为 true；部分失败不得把现有资产标记 missing。
- 所有错误只包含固定 resource code、scope/source/run/trace ID 和计数，不包含 Kubernetes 对象 bytes、namespace/name、credential locator 或 API response body。
- 新增行为严格 TDD，每个 Task 独立提交。

---

## Consumed and Produced Interfaces

Consumes from Phase 1:

```go
type NormalizedItem struct {
    ProviderKind      string
    ExternalID        string
    Kind              assetcatalog.Kind
    DisplayName       string
    SourceRevision    string
    SchemaVersion     string
    Document          json.RawMessage
    DocumentSHA256    string
    Fingerprints      map[string]string
    ObservedRelations []ObservedRelation
}

type Batch struct {
    Scope      assetcatalog.Scope
    SourceID   string
    RunID      string
    ObservedAt time.Time
    Complete   bool
    CursorHash string
    Items      []NormalizedItem
}

type Reconciler interface {
    Reconcile(context.Context, Batch) (Result, error)
}
```

Produces provider kind `victoriametrics-operator`, schema version `victoria-operator-asset.v1`, exact UID fingerprints and explicit relationships.

### Task 1: Build the exhaustive resource catalog and safe projectors

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`
- Create: `internal/assetdiscovery/victoriametrics/resource_catalog.go`
- Create: `internal/assetdiscovery/victoriametrics/resource_catalog_test.go`
- Create: `internal/assetdiscovery/victoriametrics/projector.go`
- Create: `internal/assetdiscovery/victoriametrics/projector_test.go`
- Create: `internal/assetdiscovery/victoriametrics/testdata/operator_v1_resources.json`
- Create: `internal/assetdiscovery/victoriametrics/testdata/operator_v1beta1_resources.json`

**Interfaces:**
- Consumes: Kubernetes `APIResourceList`, `PartialObjectMetadata`, `unstructured.Unstructured` and taxonomy descriptors.
- Produces: a complete GVR catalog and secret-safe `NormalizedItem` candidates.
- Safety: config/VMUser projectors accept metadata types at compile time; runtime projectors copy field-by-field into owned structs and immediately discard the source object.

- [ ] **Step 1: Pin Kubernetes client libraries**

```bash
go get k8s.io/api@v0.36.2 k8s.io/apimachinery@v0.36.2 k8s.io/client-go@v0.36.2
go mod tidy
```

Expected: `go.mod` contains the three direct v0.36.2 requirements and no Kubernetes version split.

- [ ] **Step 2: Write failing resource coverage and projection tests**

```go
func TestOperatorResourceCoverage(t *testing.T)
func TestOperatorResourceCoverageSupportsV1AndV1Beta1(t *testing.T)
func TestConfigurationResourcesUseMetadataOnly(t *testing.T)
func TestRuntimeProjectorUsesStrictAllowlist(t *testing.T)
func TestSecretProjectionDenied(t *testing.T)
func TestVMUserProducesOnlyOpaqueCredentialReference(t *testing.T)
```

`TestSecretProjectionDenied` injects canaries into `spec.password`, `spec.bearerToken`, `data`, `stringData`, annotations, env, args, volumes and status message. It scans normalized JSON, fingerprints, errors and captured logs for every canary and fails on any match.

- [ ] **Step 3: Run focused tests and confirm failure**

```bash
go test ./internal/assetdiscovery/victoriametrics -run 'TestOperatorResourceCoverage|TestConfigurationResources|TestRuntimeProjector|TestSecretProjection|TestVMUser' -count=1
```

Expected: FAIL because the discovery package is absent.

- [ ] **Step 4: Implement the literal 21-resource catalog**

```go
type ReadMode string

const (
    ReadMetadataOnly  ReadMode = "METADATA_ONLY"
    ReadSafeRuntimeCR ReadMode = "SAFE_RUNTIME_CR"
)

type ResourceDescriptor struct {
    Kind       string
    Plural     string
    ReadMode   ReadMode
    RootKind   assetcatalog.Kind
    Components []ComponentDescriptor
}

var resourceCatalog = []ResourceDescriptor{
    {Kind: "VMAgent", Plural: "vmagents", ReadMode: ReadSafeRuntimeCR, RootKind: assetcatalog.KindVMAgent},
    {Kind: "VMAnomaly", Plural: "vmanomalies", ReadMode: ReadSafeRuntimeCR, RootKind: assetcatalog.KindVMAnomaly},
    {Kind: "VMAlert", Plural: "vmalerts", ReadMode: ReadSafeRuntimeCR, RootKind: assetcatalog.KindVMAlert},
    {Kind: "VMAlertManager", Plural: "vmalertmanagers", ReadMode: ReadSafeRuntimeCR, RootKind: assetcatalog.KindVMAlertManager},
    {Kind: "VMAlertManagerConfig", Plural: "vmalertmanagerconfigs", ReadMode: ReadMetadataOnly, RootKind: assetcatalog.KindVMAlertManagerConfig},
    {Kind: "VMAuth", Plural: "vmauths", ReadMode: ReadSafeRuntimeCR, RootKind: assetcatalog.KindVMAuth},
    {Kind: "VMCluster", Plural: "vmclusters", ReadMode: ReadSafeRuntimeCR, RootKind: assetcatalog.KindVictoriaMetricsCluster, Components: metricsComponents},
    {Kind: "VMNodeScrape", Plural: "vmnodescrapes", ReadMode: ReadMetadataOnly, RootKind: assetcatalog.KindVMNodeScrape},
    {Kind: "VMPodScrape", Plural: "vmpodscrapes", ReadMode: ReadMetadataOnly, RootKind: assetcatalog.KindVMPodScrape},
    {Kind: "VMProbe", Plural: "vmprobes", ReadMode: ReadMetadataOnly, RootKind: assetcatalog.KindVMProbe},
    {Kind: "VMRule", Plural: "vmrules", ReadMode: ReadMetadataOnly, RootKind: assetcatalog.KindVMRule},
    {Kind: "VMServiceScrape", Plural: "vmservicescrapes", ReadMode: ReadMetadataOnly, RootKind: assetcatalog.KindVMServiceScrape},
    {Kind: "VMStaticScrape", Plural: "vmstaticscrapes", ReadMode: ReadMetadataOnly, RootKind: assetcatalog.KindVMStaticScrape},
    {Kind: "VMSingle", Plural: "vmsingles", ReadMode: ReadSafeRuntimeCR, RootKind: assetcatalog.KindVictoriaMetricsSingle},
    {Kind: "VMUser", Plural: "vmusers", ReadMode: ReadMetadataOnly, RootKind: assetcatalog.KindVMUser},
    {Kind: "VMScrapeConfig", Plural: "vmscrapeconfigs", ReadMode: ReadMetadataOnly, RootKind: assetcatalog.KindVMScrapeConfig},
    {Kind: "VLSingle", Plural: "vlsingles", ReadMode: ReadSafeRuntimeCR, RootKind: assetcatalog.KindVictoriaLogsSingle},
    {Kind: "VLAgent", Plural: "vlagents", ReadMode: ReadSafeRuntimeCR, RootKind: assetcatalog.KindVLAgent},
    {Kind: "VLCluster", Plural: "vlclusters", ReadMode: ReadSafeRuntimeCR, RootKind: assetcatalog.KindVictoriaLogsCluster, Components: logsComponents},
    {Kind: "VTSingle", Plural: "vtsingles", ReadMode: ReadSafeRuntimeCR, RootKind: assetcatalog.KindVictoriaTracesSingle},
    {Kind: "VTCluster", Plural: "vtclusters", ReadMode: ReadSafeRuntimeCR, RootKind: assetcatalog.KindVictoriaTracesCluster, Components: tracesComponents},
}
```

Define `metricsComponents`, `logsComponents` and `tracesComponents` as literal role/kind/port lists: vmselect 8481, vminsert 8480, vmstorage 8482; vlselect 9471, vlinsert 9481, vlstorage 9491; vtselect 10471, vtinsert 10481, vtstorage 10491. Ports are identity hints only and never copied into a public Target.

- [ ] **Step 5: Implement safe owned projections**

```go
type SafeDocument struct {
    APIVersion          string          `json:"api_version"`
    ResourceKind        string          `json:"resource_kind"`
    NamespaceDigest     string          `json:"namespace_digest"`
    ObjectUID           string          `json:"object_uid"`
    Generation          int64           `json:"generation"`
    TaxonomyClass       string          `json:"taxonomy_class"`
    ProductVersion      string          `json:"product_version,omitempty"`
    DesiredReplicas     *int32          `json:"desired_replicas,omitempty"`
    ReadyReplicas       *int32          `json:"ready_replicas,omitempty"`
    Conditions          []SafeCondition `json:"conditions,omitempty"`
    CredentialReference string          `json:"credential_reference,omitempty"`
}

type SafeCondition struct {
    Type   string `json:"type"`
    Status string `json:"status"`
}
```

Allowed conditions are exactly `Available`, `Ready`, `Progressing`, `Degraded`; messages/reasons/timestamps are discarded. `VMUser` sets `CredentialReference` to `vmuser-credential-v1-<sha256(scope,clusterUID,namespaceUID,objectUID)>`; no Secret name or locator is in `SafeDocument`.

- [ ] **Step 6: Run projector tests**

```bash
go test ./internal/assetdiscovery/victoriametrics -run 'TestOperatorResourceCoverage|TestConfigurationResources|TestRuntimeProjector|TestSecretProjection|TestVMUser' -count=1
```

Expected: PASS; coverage count is exactly 21 and canary scan is empty.

- [ ] **Step 7: Commit catalog and projectors**

```bash
git add go.mod go.sum internal/assetdiscovery/victoriametrics/resource_catalog.go internal/assetdiscovery/victoriametrics/resource_catalog_test.go internal/assetdiscovery/victoriametrics/projector.go internal/assetdiscovery/victoriametrics/projector_test.go internal/assetdiscovery/victoriametrics/testdata/operator_v1_resources.json internal/assetdiscovery/victoriametrics/testdata/operator_v1beta1_resources.json
git commit -m "feat(victoria): catalog operator resources safely"
```

### Task 2: Implement API discovery, metadata isolation and Secret-denying RBAC

**Files:**
- Create: `internal/assetdiscovery/victoriametrics/kubernetes_client.go`
- Create: `internal/assetdiscovery/victoriametrics/kubernetes_client_test.go`
- Create: `internal/assetdiscovery/victoriametrics/request_guard.go`
- Create: `internal/assetdiscovery/victoriametrics/request_guard_test.go`
- Create: `deploy/helm/aiops/templates/victoria-discovery-rbac.yaml`
- Create: `deploy/helm/aiops/templates/victoria-discovery-rbac_test.go`

**Interfaces:**
- Consumes: a private REST config resolved from Operator Source Revision and Kubernetes discovery/dynamic/metadata clients.
- Produces: served GVR resolution, bounded list/watch streams and zero-sensitive request audit counters.
- Safety: an HTTP RoundTripper denies any core Secret URL before network I/O; RBAC is allowlist-only and namespace-scoped where configured.

- [ ] **Step 1: Write failing client and RBAC tests**

```go
func TestResolveServedResourcesPrefersV1AndFallsBackToV1Beta1(t *testing.T)
func TestResolveServedResourcesFailsClosedOnMissingMandatoryGVR(t *testing.T)
func TestMetadataOnlyResourcesNeverUseDynamicClient(t *testing.T)
func TestRequestGuardRejectsEverySecretVerb(t *testing.T)
func TestDiscoveryRBACContainsNoSecretsWildcardOrWriteVerb(t *testing.T)
func TestDiscoveryListUsesResourceVersionAndBoundedPagination(t *testing.T)
```

The fake API server records method/path only. Assert no path contains `/secrets`, every list uses `limit=500`, watch uses the list resourceVersion, and allowed verbs are exactly `get,list,watch` for CRDs plus `get,list,watch` for Services/Deployments/StatefulSets/Pods.

- [ ] **Step 2: Run focused tests and verify failure**

```bash
go test ./internal/assetdiscovery/victoriametrics ./deploy/helm/aiops/templates -run 'TestResolveServed|TestMetadataOnly|TestRequestGuard|TestDiscoveryRBAC|TestDiscoveryList' -count=1
```

Expected: FAIL because client, guard and chart template are absent.

- [ ] **Step 3: Implement explicit client boundaries**

```go
type Clients struct {
    Discovery discovery.DiscoveryInterface
    Metadata  metadata.Interface
    Dynamic   dynamic.Interface
}

type ServedResource struct {
    Descriptor ResourceDescriptor
    GVR        schema.GroupVersionResource
}

type ResourceResolver interface {
    Resolve(context.Context, discovery.DiscoveryInterface) ([]ServedResource, error)
}

type Lister interface {
    ListMetadata(context.Context, schema.GroupVersionResource, []string) ([]metav1.PartialObjectMetadata, string, error)
    ListRuntime(context.Context, schema.GroupVersionResource, []string) ([]unstructured.Unstructured, string, error)
}
```

Resolver only accepts group `operator.victoriametrics.com`; it selects v1 when served, otherwise v1beta1. A missing mandatory kind returns `VICTORIAMETRICS_RESOURCE_UNSUPPORTED` and causes `Complete=false`.

Wrap the transport before any client construction:

```go
func denySecretRequest(req *http.Request) error {
    for _, segment := range strings.Split(strings.ToLower(req.URL.EscapedPath()), "/") {
        if segment == "secrets" {
            return ErrSecretRequestDenied
        }
    }
    return nil
}
```

The guard also rejects non-GET methods and watch/list paths outside the fixed group/core workload resource allowlist.

- [ ] **Step 4: Add exact RBAC rules**

Render separate Roles per configured namespace. Operator CRD resources list all 21 plurals literally; core group includes only `services` and `pods`; apps group includes only `deployments` and `statefulsets`. Verbs are `get`, `list`, `watch`. Do not include `secrets`, `configmaps`, `events`, `*`, `create`, `patch`, `update`, `delete`, `impersonate` or non-resource URLs.

- [ ] **Step 5: Run client and RBAC tests**

```bash
go test ./internal/assetdiscovery/victoriametrics ./deploy/helm/aiops/templates -run 'TestResolveServed|TestMetadataOnly|TestRequestGuard|TestDiscoveryRBAC|TestDiscoveryList' -count=1
```

Expected: PASS with no Secret request captured.

- [ ] **Step 6: Commit client and RBAC**

```bash
git add internal/assetdiscovery/victoriametrics/kubernetes_client.go internal/assetdiscovery/victoriametrics/kubernetes_client_test.go internal/assetdiscovery/victoriametrics/request_guard.go internal/assetdiscovery/victoriametrics/request_guard_test.go deploy/helm/aiops/templates/victoria-discovery-rbac.yaml deploy/helm/aiops/templates/victoria-discovery-rbac_test.go
git commit -m "feat(victoria): discover operator APIs without secrets"
```

### Task 3: Normalize topology, versions and opaque credential references

**Files:**
- Create: `internal/assetdiscovery/victoriametrics/topology.go`
- Create: `internal/assetdiscovery/victoriametrics/topology_test.go`
- Create: `internal/assetdiscovery/victoriametrics/normalizer.go`
- Create: `internal/assetdiscovery/victoriametrics/normalizer_test.go`
- Create: `internal/assetdiscovery/victoriametrics/credential_reference.go`
- Create: `internal/assetdiscovery/victoriametrics/credential_reference_test.go`

**Interfaces:**
- Consumes: safe CR projections plus safe workload/service projections and a credential-reference broker.
- Produces: deterministic Phase 1 `NormalizedItem` values and exact `CONTAINS`, `MANAGED_BY`, `CONFIGURES`, `PRIMARY_RUNTIME_FOR` relationships.
- Safety: relationships require exact UID evidence; credential broker receives an opaque issuer descriptor and returns only reference ID/revision/digest.

- [ ] **Step 1: Write failing topology and normalization tests**

```go
func TestClusterCreatesRootAndThreeComponentAssets(t *testing.T)
func TestTopologyRejectsNameAndLabelOnlyMatches(t *testing.T)
func TestGeneratedWorkloadRelationsRequireOwnerUID(t *testing.T)
func TestNormalizerIsDeterministicAcrossListOrder(t *testing.T)
func TestUnknownVersionRemainsVisibleButUnsupported(t *testing.T)
func TestVMUserCredentialBrokerNeverReturnsLocatorMaterial(t *testing.T)
func TestToolArtifactsNeverReceiveCapabilityRelations(t *testing.T)
```

Fixtures cover VM/VL/VT cluster, single nodes, VMOperator Deployment, governed VMGateway workload, VMBackupManager workload and all four tool image artifacts. Include an evil same-name workload with a different UID and assert no relation is emitted.

- [ ] **Step 2: Run focused tests and verify failure**

```bash
go test ./internal/assetdiscovery/victoriametrics -run 'TestClusterCreates|TestTopology|TestGeneratedWorkload|TestNormalizer|TestUnknownVersion|TestVMUserCredential|TestToolArtifacts' -count=1
```

Expected: FAIL because topology and normalizer are absent.

- [ ] **Step 3: Implement deterministic identities and relations**

```go
func rootExternalID(clusterUID, objectUID string) string {
    return "k8s://" + clusterUID + "/uid/" + objectUID
}

func componentExternalID(rootID string, role victoriametrics.Role) string {
    return rootID + "#component/" + strings.ToLower(string(role))
}

type ExactOwner struct {
    APIVersion string
    Kind       string
    UID        string
    Controller bool
}
```

Sort items by `(Kind,ExternalID)` and relations by `(Type,FromExternalID,ToExternalID)` before canonicalization. Fingerprints contain `cluster_uid`, `object_uid`, `owner_uid` and `component_role`; namespace is a SHA-256 fingerprint, not raw text. Unknown version sets `compatibility_status=UNSUPPORTED` and never suppresses the asset.

- [ ] **Step 4: Implement the opaque credential broker call**

```go
type VMUserIssuer struct {
    Scope        assetcatalog.Scope
    ClusterUID   string
    NamespaceUID string
    VMUserUID    string
}

type CredentialReferenceBroker interface {
    EnsureVMUserReference(context.Context, VMUserIssuer) (credentialreference.ReferenceSummary, error)
}
```

`ReferenceSummary` contains only `ID`, `Revision`, `IssuerKind`, `Status`, `ManifestDigest`. The broker owns the private Kubernetes locator and does not perform a Secret GET during discovery. Normalized document only records `ID`, `Revision`, `Status`, `ManifestDigest`.

- [ ] **Step 5: Require provenance for Operator, gateway, backup manager and tools**

```go
type DeclaredArtifact struct {
    WorkloadUID    string
    OwnerUID       string
    OCIImageDigest string
    Kind           assetcatalog.Kind
}
```

Load `DeclaredArtifact` only from the signed artifact inventory whose digest is captured by `OperatorSourceRevision`. Create `VMOPERATOR`, `VMGATEWAY`, `VMBACKUPMANAGER`, `VMCTL`, `VMBACKUP`, `VMRESTORE` or `VMALERT_TOOL` only when workload UID and OCI digest both match a declared row；an image/name/label match alone is insufficient. These rows can create exact `MANAGED_BY`/`CONTAINS` relations when Owner UID matches, but never capability relations.

- [ ] **Step 6: Run topology and safety tests**

```bash
go test -race ./internal/assetdiscovery/victoriametrics -run 'TestClusterCreates|TestTopology|TestGeneratedWorkload|TestNormalizer|TestUnknownVersion|TestVMUserCredential|TestToolArtifacts' -count=1
```

Expected: PASS and deterministic digests across 100 shuffled inputs.

- [ ] **Step 7: Commit normalization**

```bash
git add internal/assetdiscovery/victoriametrics/topology.go internal/assetdiscovery/victoriametrics/topology_test.go internal/assetdiscovery/victoriametrics/normalizer.go internal/assetdiscovery/victoriametrics/normalizer_test.go internal/assetdiscovery/victoriametrics/credential_reference.go internal/assetdiscovery/victoriametrics/credential_reference_test.go
git commit -m "feat(victoria): normalize operator topology"
```

### Task 4: Assemble the HA discovery source and worker

**Files:**
- Create: `internal/assetdiscovery/victoriametrics/source.go`
- Create: `internal/assetdiscovery/victoriametrics/source_test.go`
- Create: `internal/assetdiscovery/victoriametrics/worker.go`
- Create: `internal/assetdiscovery/victoriametrics/worker_test.go`
- Create: `internal/assetdiscovery/victoriametrics/metrics.go`
- Create: `cmd/asset-discovery-worker/main.go`
- Create: `cmd/asset-discovery-worker/main_test.go`

**Interfaces:**
- Consumes: published Operator Source Revision, private client factory, Phase 1 Reconciler and PostgreSQL advisory-lock connection.
- Produces: scheduled and watch-triggered complete snapshots, source-run completion and bounded operational metrics.
- Safety: only the lock holder reconciles; losing the DB session cancels list/watch context; partial discovery never emits a complete snapshot.

- [ ] **Step 1: Write failing worker lifecycle tests**

```go
func TestSourceCompleteOnlyAfterEveryMandatoryResourceList(t *testing.T)
func TestSourceRelistsAfterExpiredResourceVersion(t *testing.T)
func TestSourceCoalescesWatchEventsBySourceRevision(t *testing.T)
func TestTwoWorkersHaveExactlyOneAdvisoryLockHolder(t *testing.T)
func TestLostLockCancelsReconcileBeforeCompletion(t *testing.T)
func TestRepeatedCompleteSnapshotIsIdempotent(t *testing.T)
func TestWorkerMetricsUseBoundedLabels(t *testing.T)
func TestDiscoveryWorkerProductionAssemblyHasNoFakeClient(t *testing.T)
```

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/assetdiscovery/victoriametrics ./cmd/asset-discovery-worker -run 'TestSource|TestTwoWorkers|TestLostLock|TestRepeatedComplete|TestWorkerMetrics|TestDiscoveryWorker' -count=1
```

Expected: FAIL because source and worker are absent.

- [ ] **Step 3: Implement source snapshot semantics**

```go
type Source struct {
    resolver   ResourceResolver
    lister     Lister
    normalizer *Normalizer
    clock      clockwork.Clock
}

type Snapshot struct {
    Items         []assetdiscovery.NormalizedItem
    ResourceRV    map[schema.GroupVersionResource]string
    CursorHash    string
    Complete      bool
    FailureCodes  []string
}

func (s *Source) Snapshot(context.Context, OperatorSourceRevision) (Snapshot, error)
func (s *Source) Watch(context.Context, OperatorSourceRevision, Snapshot) (<-chan Trigger, error)
```

All 21 mandatory CR resources must list successfully. Workload/service failures also force `Complete=false` because they affect topology. HTTP 410 Gone clears only the affected RV, performs a full relist, recomputes cursor hash and then resumes watch. A 2-second debounce coalesces events but never crosses Source Revision.

- [ ] **Step 4: Implement PostgreSQL advisory-lock HA**

Worker acquires a dedicated pgx connection and calls `pg_try_advisory_lock(hashtextextended(scope||source_id,0))`. It derives a child context canceled when the connection health check fails; releases the lock on shutdown; starts a Phase 1 source run with deterministic request hash; calls Reconciler only for a complete or explicitly partial batch; and records partial failure without missing-marking. No process-local state is needed after restart.

- [ ] **Step 5: Expose bounded metrics**

```text
aiops_victoria_discovery_runs_total{result}
aiops_victoria_discovery_resources_total{resource_kind,result}
aiops_victoria_discovery_duration_seconds{result}
aiops_victoria_discovery_items{taxonomy_class}
aiops_victoria_discovery_lock_held
aiops_victoria_discovery_relist_total{reason}
aiops_victoria_discovery_projection_rejections_total{reason}
```

Allowed labels are literal enums; never label by tenant/workspace/environment/source, cluster, namespace, resource name, UID, version or error text.

- [ ] **Step 6: Run worker tests and race detector**

```bash
go test -race ./internal/assetdiscovery/victoriametrics ./cmd/asset-discovery-worker -count=1
```

Expected: PASS; two-worker test has one reconciler call and lock-loss test has zero completion.

- [ ] **Step 7: Commit the worker**

```bash
git add internal/assetdiscovery/victoriametrics/source.go internal/assetdiscovery/victoriametrics/source_test.go internal/assetdiscovery/victoriametrics/worker.go internal/assetdiscovery/victoriametrics/worker_test.go internal/assetdiscovery/victoriametrics/metrics.go cmd/asset-discovery-worker/main.go cmd/asset-discovery-worker/main_test.go
git commit -m "feat(victoria): run HA operator discovery"
```

## Pack Completion Gate

```bash
go test -race ./internal/assetdiscovery/victoriametrics ./cmd/asset-discovery-worker -count=1
go test ./deploy/helm/aiops/templates -run 'TestDiscoveryRBAC' -count=1
go vet ./internal/assetdiscovery/victoriametrics ./cmd/asset-discovery-worker
git diff --check
```

Expected: all commands exit 0; exact 21-resource coverage; no Secret API request or canary material; complete snapshots are HA-safe, deterministic and topology-exact.
