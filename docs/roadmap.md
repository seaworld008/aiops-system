# Roadmap and Release Gates

This roadmap is deliberately gate-driven. Calendar progress never enables production writes by itself.

## Delivery status

| Workstream | Current state | Next exit condition |
| --- | --- | --- |
| Repository and domain foundation | Implemented | Keep migrations and domain contracts backward compatible |
| Scoped signal ingestion | Implemented foundation | Validate against real Alertmanager and Nightingale endpoints |
| Read-only connectors | Implemented foundation | Run contract and failure tests against pilot environments |
| Investigation and model routing | Persistent runtime, authenticated READ Task Gateway, atomic runtime Bundle, independent READ-only client, fixed READ HTTP executor, recovery-first Temporal v2, READ Runner Activity, immutable Snapshot, role-isolated Temporal control boundary, fail-closed subprocess containment, deterministic late-FATAL containment, a static process-escape gate, fixed-root sealed public-source capability, and a post-`SECRET_READY` contained production secret-loader implemented. The loader reads only an independent fixed tmpfs root and writes three role-bound frames on its FD3–FD5, which map to the control child's FD5–FD7, without exposing secret bytes to the parent. Live clients, Outbox and Runner remain unassembled, and sealed Admission blocks both new claims and legacy lease progression | Assemble the real supervised child clients/runtime while retaining zero claims, then connect Runner/Gateway/Outbox and local E2E in M5C2-4c; finally pass external identity/network gates and build a replay set of at least 100 historical incidents |
| Identity, RBAC, policy, and signed plans | Implemented foundation | Complete real Keycloak/Vault integration and adversarial tests |
| Fenced action execution | Secure queue, durable revocation, mTLS Gateway, split Runner images, and killable Executor foundation implemented | Add only fixed non-production adapters after external sandbox/network gates |
| Temporal orchestration | Digest/Bundle-bound READ runtime v2, DB-only result recovery, strict payload/failure History allowlist, server-attested separate Starter/Control mTLS capabilities, fixed Control Worker, monitored TERM/FATAL and deterministic kill/reap, a sealed pre-assembly child lifecycle arbiter, static process-escape gates, a kill-bounded public-source loader, and an independently contained secret-loader are implemented. After `SECRET_READY`, the latter uses fixed self-reexec, PIDFD/PGID/Pdeathsig, an independent tmpfs root, and exact FD3–FD5 output mapping; cancellation, deadline, abnormal exit, and surviving descendants fail closed and are reaped. No Dial is performed and the hidden control child deliberately exits before READY | Put the real Control Worker and clients inside the contained child, require cluster-exclusive reconnect identity and cgroup/PID-namespace evidence, then complete supervised Outbox/Runner/Gateway assembly and prove separate Temporal credentials/RBAC |
| Web console and Feishu | Planned | Investigation, approval, execution, and audit user journeys |
| Production pilot | Blocked by gates | Non-production drills plus formal Go/No-Go review |

M4 does not enable action claims: the control plane still has no write `StartAuthorizer`, the
WRITE Runner only performs a Linux capability probe in `non-production`, and the Executor rejects
all mutation handlers before READY. Only M6 may wire fixed non-production adapters; no milestone in
the current plan adds a production mode.

## Pilot sequence

```text
historical replay
  -> read-only shadow mode
  -> non-production typed execution
  -> five-service supervised production pilot
  -> Go/No-Go review
  -> 10% / 30% / broader rollout
```

## Mandatory production-write gates

Production mutation feature flags remain off until all of the following are true:

- service mapping completeness is at least 95%;
- real investigation workflow success is at least 95%;
- Top-3 hypotheses cover the confirmed cause in at least 70% of the replay set;
- evidence citation completeness is 100%, key-fact accuracy is at least 95%, and unsupported facts are at most 1%;
- unauthorized and duplicate production mutations are both zero;
- policy, approval, tool, credential, and execution audit coverage is 100%;
- every production mutation performs post-action verification;
- PostgreSQL-backed action claims are atomic across replicas;
- failed dynamic-credential revocation has a durable, alerted retry path;
- timed-out executors are isolated and cannot overlap a reconciled execution;
- READ and WRITE images, identities, queues, Vault roles, and network policies are demonstrably separate;
- each write job is constrained by cgroup v2, reviewed seccomp/LSM policy, a read-only root, and an
  allowlisted egress policy in the target environment;
- 100 negative action tests show zero policy or scope bypass;
- each action type completes at least 20 non-production drills with at least 95% verification success;
- the pilot completes at least 30 supervised production actions without an unauthorized action or AI-caused Sev1/Sev2.

## Explicit non-goals for the first release

- SaaS multi-tenancy and tenant self-service;
- a replacement CMDB;
- arbitrary shell, SSH, or generated Kubernetes manifests;
- autonomous multi-agent meshes;
- vector databases by default;
- VM reboot, database, DNS, network, secret, or cloud-resource mutations;
- direct production changes through GitLab CI, Jenkins, or GitHub Actions.

The detailed 16-week execution plan is maintained in [the SME pilot plan](plans/2026-07-10-sme-internal-aiops-pilot.md).
