# AIOps System

[![CI](https://github.com/seaworld008/aiops-system/actions/workflows/ci.yml/badge.svg)](https://github.com/seaworld008/aiops-system/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26.5-00ADD8?logo=go)](go.mod)

Evidence-first operations intelligence with policy-governed automation.

**English** · [简体中文](README.zh-CN.md)

> [!IMPORTANT]
> AIOps System is in active pre-alpha development. Read-only investigation foundations are usable for development and evaluation. Production write automation has no configurable enablement path and remains disabled until every safety and quality gate in the pilot plan has passed.

## Why this project exists

Modern operations teams already have metrics, logs, Kubernetes, virtual machines, CI/CD, GitOps, and incident channels. What they often lack is a trustworthy layer that can correlate those facts, explain its evidence, and execute a very small set of changes without handing authority to an LLM.

AIOps System is designed around four rules:

- **Evidence before conclusions.** Every operational claim must cite bounded, traceable evidence.
- **Models propose; deterministic systems decide.** CEL policy, identity, approvals, live state, and signed plans govern execution.
- **Uncertain means stop and reconcile.** Side effects are fenced, verified, and never blindly retried.
- **Least privilege is an architecture boundary.** Read and write runners have separate identities, queues, credentials, and network paths.

## Current capabilities

| Area | Status | What is available |
| --- | --- | --- |
| Signal ingestion | Implemented | Scoped and signed Alertmanager/Nightingale webhooks, idempotency, deduplication foundations |
| Read-only evidence | Implemented | Bounded clients for Prometheus, VictoriaLogs, Kubernetes, AWX, Argo CD, GitLab, Jenkins, and GitHub Actions |
| Investigation | Implemented foundation | Persistent facts, a strict mTLS READ Task Gateway, an atomic connector/target/egress/executor Bundle, a recovery-first Temporal v2 Workflow, fixed READ Runner Activity, immutable assembly Snapshot, role-isolated Temporal Starter/Control Worker, monitored fatal/stop subprocess containment, a sealed pre-assembly child lifecycle arbiter, and a kill-bounded fixed-root public-source loader plus sealed FD4 handoff exist; the child independently revalidates the immutable frame but does not yet construct a semantic Snapshot, the fixed factory still prevents READY, live Outbox/Runner assembly is absent, and the non-configurable Admission remains closed pending M5C2-4c and external Go/No-Go gates |
| Identity and policy | Implemented foundation | Keycloak OIDC, workspace/environment RBAC, signed ActionEnvelope, three-stage CEL decisions |
| Execution safety | Implemented foundation | Exact runner scopes, durable credential revocation, TLS 1.3 mTLS Gateway, split READ/WRITE images, fixed killable executor, target locks, heartbeat, cancellation, and reconciliation |
| Production automation | **Disabled** | Requires fixed real adapters, external sandbox/network gates, non-production drills, and formal Go/No-Go approval |
| Web console / ChatOps | Planned | React console and Feishu workflows are not yet shipped |

“Implemented foundation” means the contracts and testable core exist; it does **not** mean a connector or mutation path is ready for unattended production use.

## Architecture

```mermaid
flowchart LR
    UI["Web / Feishu / Alert Webhooks"] --> IN["Verified ingestion and service mapping"]
    IN --> CP["Go modular control plane"]
    CP --> PG[(PostgreSQL)]
    CP --> OBJ[(S3-compatible evidence store)]
    CP --> TW["Temporal workflows"]
    CP --> CEL["CEL policy engine"]
    CP --> AI["Private / cloud model adapters"]

    TW --> GW["Outbound Runner Gateway"]
    GW --> RR["Read-only runners"]
    GW --> WR["Split write runners + fixed executor"]
    RR --> OBS["Metrics / logs / K8s / AWX / CI / Argo"]
    WR --> MUT["Typed K8s / GitOps / AWX actions"]

    KC["Keycloak"] --> CP
    VAULT["Vault short-lived credentials"] --> RR
    VAULT --> WR
```

The first release targets a single self-hosted organization with multiple workspaces. PostgreSQL is the domain source of truth; Temporal is used only for durable orchestration. Runner communication is outbound-only through a dedicated TLS 1.3 mTLS Gateway.

## Safety model

The only accepted mutation input is a canonical, signed `ActionEnvelope`. It binds the exact target, parameters, observed resource version, preconditions, verification, compensation, risk, policy version, credential scope, idempotency key, and expiry.

Before a write starts, the system must verify:

1. an exact service/environment mapping;
2. a valid signature and immutable plan hash;
3. current policy at plan, credential, and execution stages;
4. non-self approval bound to the exact plan and live target state;
5. a single-target, short-lived credential anchored before use and durably revoked after execution;
6. all global, environment, connector, and action kill switches;
7. target locking and the pilot-wide production concurrency limit;
8. a fixed isolated executor that must be killed and reaped before release, followed by post-action verification or an `UNCERTAIN` state that retains the lock until reconciliation.

See the [security model and implementation blueprint](docs/architecture/implementation-blueprint-v3.md) for the complete contract.

## Quick start

Requirements:

- Go 1.26.5
- PostgreSQL 16+ for persistence and migration tests
- Temporal, Keycloak, Vault, and S3-compatible storage for the intended production architecture

Run the development control plane with its in-memory repository:

```bash
make test
make vet
make build
make run
```

Then check:

```text
GET http://localhost:8080/healthz
GET http://localhost:8080/readyz
GET http://localhost:8080/api/v1/session
```

The in-memory mode is for local development only. Production mode fails closed unless PostgreSQL, scoped webhook secrets, and Keycloak OIDC are configured. Copy [.env.example](.env.example) as a reference; never commit real credentials.

To run real PostgreSQL migration and repository tests:

```bash
AIOPS_TEST_POSTGRES_DSN='postgres://aiops:password@127.0.0.1:5432/aiops_test?sslmode=disable' \
  go test -count=1 ./internal/store/postgres ./internal/execution/postgres
```

With Docker/BuildKit available, build the physically separate Runner images with:

```bash
make runner-images
```

The WRITE image defaults to `disabled`; M4 only performs a Linux isolation capability probe in `non-production` mode and still claims no jobs. See the [isolated Runner runtime gates](docs/operations/isolated-runner-runtime.md).

## Documentation

- [Documentation index](docs/README.md)
- [Architecture overview](docs/architecture/overview.md)
- [2026 V3 implementation blueprint](docs/architecture/implementation-blueprint-v3.md)
- [SME internal pilot plan](docs/plans/2026-07-10-sme-internal-aiops-pilot.md)
- [M4 isolated executor design](docs/plans/2026-07-11-isolated-executor-m4.md)
- [Isolated Runner image and Linux runtime gates](docs/operations/isolated-runner-runtime.md)
- [READ runtime Bundle and closed Admission](docs/operations/read-runtime-bundle.md)
- [Roadmap and release gates](docs/roadmap.md)
- [Historical designs](docs/archive/README.md)

## Repository layout

```text
cmd/                       control-plane, worker, separate READ/WRITE runners, fixed executor
build/package/             separate minimal READ and WRITE Runner image definitions
internal/                  domain, policy, connectors, investigation, execution
migrations/                ordered PostgreSQL schema migrations
docs/architecture/         current architecture and trust contracts
docs/plans/                executable delivery plans
docs/archive/              superseded designs kept for traceability
.github/                   CI and community templates
```

## Contributing and security

We welcome design reviews, connector work, threat modeling, tests, documentation, and carefully scoped features. Start with [CONTRIBUTING.md](CONTRIBUTING.md) and open a proposal before large architectural changes.

Do not report vulnerabilities in public issues. Follow [SECURITY.md](SECURITY.md) instead.

## License

Licensed under the [Apache License 2.0](LICENSE).
