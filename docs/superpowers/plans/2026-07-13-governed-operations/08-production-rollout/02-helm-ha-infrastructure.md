# Helm, High Availability, and Production Infrastructure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Package every production process as an independently scalable, identity-separated, fail-closed Kubernetes workload with reproducible configuration and availability controls.

**Architecture:** Harden the Phase 6 Helm chart and the Phase 7 WRITE-only extensions without renaming their files. It renders separate Control Plane, Control Worker, Outbox Dispatcher, Scheduler, Discovery Worker, Runner Gateway, Validation Runner, READ Runner, Action Worker and WRITE Runner workloads. Configuration references externally managed PostgreSQL, Temporal, Keycloak, Vault and PKI services；AWX-enabled release additionally verifies the Phase 5-owned governed AWX/EnrollmentCleanupBroker/L7/host-attestor deployment bundle rather than cloning it into the core chart. NetworkPolicies, ServiceAccounts, PodDisruptionBudgets, topology spread, health probes and explicit resources make the trust boundaries operationally enforceable.

**Tech Stack:** Helm 3, Kubernetes 1.36.2 APIs, OCI images pinned by digest, Go production binaries, Kubernetes NetworkPolicy, Pod Security Standards, workload identity, Prometheus metrics, and `helm-unittest` or server-side dry-run validation.

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- Execute only after `01-release-schema-gates.md` and Phase 1–7 acceptance.
- Production values contain Secret names, issuer roles and trust-bundle references only; no token, password, private key, DSN, kubeconfig, PEM or Vault response is committed or rendered.
- READ, WRITE and Validation Runner identities, queues, namespaces and egress policies remain distinct.
- Production processes use PostgreSQL/Temporal/Vault/Keycloak/PKI integrations. In-memory repositories, fake issuers, fake identity, test OIDC and loopback Runner transports must fail startup.
- Every image is immutable by digest. Mutable tags cannot pass values-schema validation or release gates.
- WRITE Runner has no direct browser/model ingress and cannot call observability ingestion, arbitrary database, arbitrary host or control-plane admin endpoints.
- Deployment changes do not widen the eligible Action manifest; capability availability remains a separate server-side gate.
- Phase 6 owns the exact base filenames and Phase 7 only adds `write-runner-deployment.yaml`, `write-runner-networkpolicy.yaml` and `action-workers-deployment.yaml`; Phase 8 modifies those paths in place and never creates a second chart or alias template.
- Kubernetes `1.36.2` is the sole render、kubeconform、server-side dry-run and production-cluster target. Alpha APIs and version-skew-based conditional security behavior are forbidden.
- AWX admission is release-eligible only when the digest-pinned AWX 24.6.1 governed image、two or more Broker replicas、PDB/zone anti-affinity、separate ServiceAccount/mTLS identity、Vault 2.0.3 TLS Raft/KV/three Transit keys、purpose-specific L7 egress and host-attestor compatibility evidence are all current；stock launch、single Broker、shared identity or broad AWX egress fail closed。

### Task 1: Harden the production chart contract and fail-closed values schema

**Files:**
- Modify: `deploy/helm/aiops/Chart.yaml`
- Modify: `deploy/helm/aiops/values.yaml`
- Modify: `deploy/helm/aiops/values.schema.json`
- Modify: `deploy/helm/aiops/templates/_helpers.tpl`
- Create: `deploy/helm/aiops/templates/NOTES.txt`
- Create: `deploy/helm/aiops/tests/values_contract_test.yaml`
- Create: `deploy/helm/aiops/tests/fixtures/production-values.yaml`
- Create: `deploy/helm/aiops/README.md`
- Modify: `deploy/helm/aiops/chart_contract_test.go`
- Verify: `deploy/images.lock`
- Verify: `test/production/images.lock`
- Verify: `deploy/helm/aiops/action-surface-manifest.yaml`

**Interfaces:**
- Consumes: production endpoint names, workload identity subjects, image digests, external Secret/trust-bundle references
- Produces: versioned and schema-validated Helm input contract

- [ ] **Step 1: Write failing values-contract tests**

Add tests that reject missing image digest, divergence between `deploy/images.lock` and `test/production/images.lock`, a values/image-lock mismatch, HTTP upstreams, embedded DSNs, absent OIDC issuer/audience, overlapping READ/WRITE service accounts, absent resource limits, replica count below availability minimum, and enabled test mode. The accepted Phase 7 successor digest must bind the immutable Phase 6 READ baseline, exact `action-surface-manifest.yaml` and current image-lock digest.

```yaml
suite: production values contract
templates:
  - templates/control-plane.yaml
tests:
  - it: rejects an image without sha256 digest
    set:
      images.controlPlane.repository: registry.example/aiops/control-plane
      images.controlPlane.digest: latest
    asserts:
      - failedTemplate:
          errorMessage: images.controlPlane.digest must be sha256
  - it: renders no Kubernetes Secret data
    asserts:
      - notExists:
          path: stringData
      - notExists:
          path: data
```

Run:

```bash
helm lint deploy/helm/aiops --strict
helm unittest deploy/helm/aiops
```

Expected: FAIL because the Phase 6/7 chart does not yet implement the complete release schema and hardening contract.

- [ ] **Step 2: Extend Chart metadata and enforce a closed JSON schema**

Use `apiVersion: v2` and make `appVersion` informational only. Require explicit immutable images for every process:

```yaml
images:
  controlPlane:
    repository: registry.invalid/aiops/control-plane
    digest: sha256:0000000000000000000000000000000000000000000000000000000000000000
  controlWorker:
    repository: registry.invalid/aiops/control-worker
    digest: sha256:0000000000000000000000000000000000000000000000000000000000000000
  outboxDispatcher:
    repository: registry.invalid/aiops/outbox-dispatcher
    digest: sha256:0000000000000000000000000000000000000000000000000000000000000000
  scheduler:
    repository: registry.invalid/aiops/scheduler
    digest: sha256:0000000000000000000000000000000000000000000000000000000000000000
  discoveryWorker:
    repository: registry.invalid/aiops/discovery-worker
    digest: sha256:0000000000000000000000000000000000000000000000000000000000000000
  runnerGateway:
    repository: registry.invalid/aiops/runner-gateway
    digest: sha256:0000000000000000000000000000000000000000000000000000000000000000
  validationRunner:
    repository: registry.invalid/aiops/validation-runner
    digest: sha256:0000000000000000000000000000000000000000000000000000000000000000
  readRunner:
    repository: registry.invalid/aiops/read-runner
    digest: sha256:0000000000000000000000000000000000000000000000000000000000000000
  actionWorker:
    repository: registry.invalid/aiops/action-worker
    digest: sha256:0000000000000000000000000000000000000000000000000000000000000000
  writeRunner:
    repository: registry.invalid/aiops/write-runner
    digest: sha256:0000000000000000000000000000000000000000000000000000000000000000
```

The schema must require:

- `global.environment: production` and `global.testMode: false`.
- HTTPS or mTLS endpoints for Keycloak, Vault, Temporal and PKI.
- Secret reference names matching Kubernetes DNS labels.
- Different service account names for Control Plane, Control Worker, Outbox, Scheduler, Discovery Worker, Gateway, Action Worker, Validation, READ and WRITE.
- Minimum replicas/PDB: Control Plane 3/2, Control Worker 3/2, Runner Gateway 3/2, Outbox、Scheduler and Discovery Worker 2/1, Validation and READ Runner 2/1 per enabled Realm, Action Worker and WRITE Runner 2/1 when their accepted Action types are enabled.
- External enrollment-control evidence requires EnrollmentCleanupBroker at least 2 replicas/PDB 1 across zones, L7 gateway at least 2/PDB 1, exact ServiceAccount/SAN/policy bindings, signed readiness/cleanup receipts and immutable image/SBOM/patch digests；these refs are required only when an AWX capability is admitted and contain no Secret or endpoint.
- Requests and limits for CPU, memory and ephemeral storage.
- Positive shutdown grace, lease-drain and credential-cleanup deadlines with cleanup shorter than shutdown grace.
- A nonempty cluster/region identifier and at least three topology zones for full production values.
- Empty default eligible production Action list.

Do not put real endpoint, issuer, tenant, role, namespace or Secret names in `values.yaml`. Use syntactically invalid-safe examples and document an external encrypted values workflow.

- [ ] **Step 3: Add deterministic helper names and labels**

All workload, Service, ServiceAccount, PDB and NetworkPolicy selectors use the same immutable labels:

```yaml
app.kubernetes.io/name: aiops
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: {{ .component }}
aiops.seaworld.io/trust-domain: {{ .trustDomain }}
aiops.seaworld.io/release-digest: {{ required "release digest is required" .Values.global.releaseDigest | quote }}
```

Reject label values derived from user display names. Keep release digest in annotations if it exceeds label limits.

- [ ] **Step 4: Pass lint and commit the chart contract**

```bash
helm lint deploy/helm/aiops --strict
helm unittest deploy/helm/aiops
git add deploy/helm/aiops
git commit -m "feat(deploy): define production Helm contract"
```

Expected: lint and tests pass; rendered manifests contain references but no Secret data.

### Task 2: Render independent HA workloads and production-only startup configuration

**Files:**
- Modify: `deploy/helm/aiops/templates/control-plane.yaml`
- Modify: `deploy/helm/aiops/templates/control-worker.yaml`
- Modify: `deploy/helm/aiops/templates/outbox-dispatcher.yaml`
- Modify: `deploy/helm/aiops/templates/scheduler.yaml`
- Modify: `deploy/helm/aiops/templates/discovery-worker.yaml`
- Modify: `deploy/helm/aiops/templates/runner-gateway.yaml`
- Modify: `deploy/helm/aiops/templates/validation-runner.yaml`
- Modify: `deploy/helm/aiops/templates/read-runner.yaml`
- Modify: `deploy/helm/aiops/templates/write-runner-deployment.yaml`
- Modify: `deploy/helm/aiops/templates/action-workers-deployment.yaml`
- Modify: `deploy/helm/aiops/templates/services.yaml`
- Modify: `deploy/helm/aiops/templates/pdb.yaml`
- Modify: `deploy/helm/aiops/templates/hpa.yaml`
- Modify: `deploy/helm/aiops/templates/config.yaml`
- Modify: `deploy/helm/aiops/templates/recovery-job.yaml`
- Modify: `deploy/helm/aiops/templates/recovery-job_test.go`
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Create: `internal/config/production_test.go`

**Interfaces:**
- Consumes: validated chart values, external Secret volumes, trust bundles, process-specific configuration
- Produces: multi-replica workloads and a production configuration validator shared by every binary

- [ ] **Step 1: Write failing render and startup-denial tests**

Assert every Deployment has at least two replicas where enabled, rolling update `maxUnavailable: 0`, readiness/liveness/startup probes, termination grace, preStop drain, PDB, topology spread, anti-affinity, resource requests/limits, read-only root filesystem, non-root UID/GID, seccomp RuntimeDefault, dropped capabilities and disabled service-account-token automount unless workload identity requires it.

Add Go tests:

```go
func TestProductionConfigRejectsTestDependencies(t *testing.T) {
    invalid := []Config{
        {Environment: "production", RepositoryDriver: "memory"},
        {Environment: "production", OIDCMode: "test"},
        {Environment: "production", CredentialIssuer: "fake"},
        {Environment: "production", RunnerTransport: "loopback"},
        {Environment: "production", PostgreSQLTLSMode: "disable"},
    }
    for _, cfg := range invalid {
        require.Error(t, cfg.ValidateProduction())
    }
}
```

Run:

```bash
go test ./internal/config -run TestProductionConfig -count=1
helm template aiops deploy/helm/aiops -f deploy/helm/aiops/tests/fixtures/production-values.yaml | kubeconform -strict -summary -
```

Expected: FAIL until templates, fixture and validator exist.

- [ ] **Step 2: Implement hardened pod templates**

Each container must include:

```yaml
securityContext:
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: 65532
  runAsGroup: 65532
  seccompProfile:
    type: RuntimeDefault
```

Mount a writable `emptyDir` only for bounded temporary files and set `sizeLimit`. Mount trust bundles and credential-agent sockets read-only. Never mount Kubernetes Secret files into a process that does not need them. WRITE Runner receives only its realm trust, workload identity token and broker/issuer endpoint references.

Define startup/readiness as semantic checks: configuration valid, database reachable, Temporal namespace registered, OIDC discovery valid, PKI trust loaded, and required Runner Realm publication present. Liveness must not depend on optional upstreams and must not create a restart storm during a dependency outage.

- [ ] **Step 3: Implement production configuration validation**

`ValidateProduction` rejects default/empty trust domains, private-key file paths, inline credentials, plaintext endpoints, wildcard audiences, mixed READ/WRITE queues, unbounded timeouts, test modes, and missing audit/outbox dependencies. Every `cmd/*` main calls it before starting listeners or workers.

Add assembly-boundary tests to prove production constructors cannot import or call memory/fake constructors.

Run:

```bash
go test -race -shuffle=on -count=1 ./internal/config/... ./cmd/...
helm template aiops deploy/helm/aiops -f deploy/helm/aiops/tests/fixtures/production-values.yaml | kubeconform -strict -summary -
```

Expected: PASS; no production process becomes Ready with a test dependency.

- [ ] **Step 4: Commit workloads and startup gates**

```bash
git add deploy/helm/aiops internal/config cmd
git commit -m "feat(deploy): assemble hardened HA workloads"
```

### Task 3: Enforce network, identity, and credential-plane separation

**Files:**
- Modify: `deploy/helm/aiops/templates/serviceaccounts.yaml`
- Modify: `deploy/helm/aiops/templates/networkpolicy.yaml`
- Modify: `deploy/helm/aiops/templates/networkpolicy_test.go`
- Modify: `deploy/helm/aiops/templates/write-runner-networkpolicy.yaml`
- Create: `deploy/helm/aiops/templates/podmonitors.yaml`
- Create: `deploy/helm/aiops/tests/network_policy_test.yaml`
- Create: `deploy/helm/aiops/tests/identity_separation_test.yaml`
- Create: `tests/production/network_policy_probe_test.go`

**Interfaces:**
- Consumes: Runner Realm endpoint allowlists, workload identity subjects, DNS and telemetry destinations
- Produces: default-deny ingress/egress and process-specific least-privilege paths

- [ ] **Step 1: Write failing policy-matrix tests**

Encode the allowed matrix:

| Source | Allowed destinations |
|---|---|
| Control Plane | PostgreSQL, Keycloak discovery/JWKS, audit/evidence and telemetry |
| Control Worker | PostgreSQL, Temporal, Vault, audit/telemetry and exact Realm policy API |
| Outbox Dispatcher | PostgreSQL, Temporal and audit/telemetry |
| Scheduler | PostgreSQL, Temporal and audit/telemetry |
| Discovery Worker | PostgreSQL、audit/telemetry and only the exact endpoints admitted by each accepted source-adapter binding |
| Runner Gateway | PostgreSQL, Vault/PKI, credential issuers, audit/evidence and telemetry |
| EnrollmentCleanupBroker | dedicated Vault 2.0.3 KV/Transit, purpose-specific mTLS L7 gateway and telemetry only；no direct AWX or Control API egress |
| Action Worker | PostgreSQL, Temporal, Runner Gateway and trusted READ verification path; never provider mutation egress |
| Validation Runner | Runner Gateway, DNS/trusted time and exact published validation Targets |
| READ Runner | Runner Gateway, DNS/trusted time and exact published READ Targets |
| WRITE Runner | Runner Gateway, DNS/trusted time and exact approved execution Targets |
| Ingress | edge proxy to Control Plane only; Runner mTLS identities to Runner Gateway only |

Tests must deny READ-to-WRITE issuer, WRITE-to-READ issuer, browser-to-Runner, Runner-to-PostgreSQL, Broker-to-AWX bypassing the L7 gateway, static control credentials attempting launch/cancel/list/search, cross-Realm Runner traffic, metadata service, Kubernetes API by default, and unrestricted `0.0.0.0/0` egress.

Run:

```bash
helm unittest -f 'tests/*_test.yaml' deploy/helm/aiops
go test ./tests/production -run TestNetworkPolicyMatrix -count=1
```

Expected: FAIL until policies and the probe harness exist.

- [ ] **Step 2: Implement default-deny and allow policies**

Render namespace-wide default-deny ingress/egress, then one narrowly selected allow policy per workload. Use explicit namespaces/service-account selectors and named ports. DNS access is UDP/TCP 53 only to the cluster DNS selector. External endpoints use the cluster's approved egress gateway/CIDR set; no template derives CIDRs from ConnectionProfile input.

Set distinct ServiceAccounts and projected workload identity tokens with process-specific audiences and short expiration. Disable legacy token mounting. Map identities to Vault/PKI roles outside Helm and document the required subject/audience contract. The Phase 5-owned enrollment-control bundle must receive the same hardening checks for two-replica Broker/L7 PDB、anti-affinity、readiness metrics、mTLS PKI rotation and exact Vault/AWX egress；Phase 8 modifies that registered bundle in place and does not create a second deployment source。

- [ ] **Step 3: Add production-cluster policy probes**

The probe test deploys unprivileged ephemeral clients using each service account, verifies allowed mTLS handshakes, and verifies denied connections time out or receive policy rejection. It records cluster, chart/release digest, policy digest, source identity, destination class and result without credentials.

Run in a disposable production-equivalent cluster:

```bash
AIOPS_E2E_CLUSTER=production-equivalent go test ./tests/production -run 'TestNetworkPolicyMatrix|TestWorkloadIdentityAudience' -count=1 -timeout=20m
```

Expected: PASS with every allow and deny cell observed; skipped tests fail CI for a release candidate.

- [ ] **Step 4: Commit trust-boundary policies**

```bash
git add deploy/helm/aiops tests/production
git commit -m "feat(security): isolate production runner realms"
```

### Task 4: Add reproducible rendering and upgrade checks to CI

**Files:**
- Modify: `.github/workflows/ci.yml`
- Create: `.github/workflows/production-release-candidate.yml`
- Create: `scripts/verify-production-chart.sh`
- Verify: `deploy/helm/aiops/tests/fixtures/production-values.yaml`
- Create: `deploy/helm/aiops/tests/golden/production-manifests.yaml`

**Interfaces:**
- Consumes: chart, image digests, generated OpenAPI/types, migration chain
- Produces: deterministic chart artifact and release-candidate verification evidence

- [ ] **Step 1: Add a failing local verification target**

The script must run strict lint, unit tests, schema validation, deterministic render, Kubernetes schema validation, prohibited-secret scan, mutable-image scan, securityContext assertions, migration ordering, OpenAPI generation cleanliness and backend/frontend quality checks.

Run:

```bash
bash scripts/verify-production-chart.sh
```

Expected: FAIL until all commands and golden manifests are wired.

- [ ] **Step 2: Implement deterministic verification**

The script uses `set -euo pipefail`, pins tool versions in the release workflow, writes temporary output under `mktemp -d` with a cleanup trap, and rejects these patterns in rendered YAML: `kind: Secret`, `stringData:`, base64-like private-key blocks, `:latest`, unqualified images, privileged containers, host network/PID/IPC, hostPath and wildcard RBAC.

Render twice and compare SHA-256 digests. Run the migration chain against an ephemeral PostgreSQL database, including down/up for `000022`.

- [ ] **Step 3: Add CI and signed chart packaging**

The release-candidate workflow runs only from protected branches/tags, requires environment approval, packages the chart, generates provenance/SBOM references, signs the OCI artifact, and submits artifact digests to release governance. It never receives runtime credentials used by a Runner.

Run locally and inspect workflow syntax:

```bash
bash scripts/verify-production-chart.sh
actionlint .github/workflows/ci.yml .github/workflows/production-release-candidate.yml
git diff --check
```

Expected: all commands pass and two renders have the same digest.

- [ ] **Step 4: Commit deployment verification**

```bash
git add .github/workflows scripts/verify-production-chart.sh deploy/helm/aiops
git commit -m "ci(release): verify reproducible production manifests"
```
