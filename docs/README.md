# Documentation

This directory separates current architecture, executable delivery plans, and superseded historical material.

> Current state: `SPEC_APPROVED / DEVELOPMENT_PAUSED / RUNTIME_CLOSED`. The audited remote baseline is `origin/main@90c19b7bbeb17381a72e3cd21dd85b10e01767d4`; start with [current status](status/current.md), [architecture entry](architecture/README.md), and the [rebaseline development program](superpowers/plans/2026-09-19-rebaseline-development-program.md). Historical plans are evidence only.

## Current architecture

- [Architecture overview](architecture/overview.md) — concise English introduction to components and trust boundaries.
- [Architecture documentation entry](architecture/README.md) — current architecture, authority layers, and historical-document boundary.
- [Agent development guide](architecture/agent-development-guide.md) — worktree, Batch, G1–G4, pause, and recovery rules.
- [2026 V3 implementation blueprint](architecture/implementation-blueprint-v3.md) — historical detailed design and safety contract (Chinese), retained for traceability.
- [AI Agent living code map](architecture/agent-code-map.md) — worktree-scoped GitNexus graph, impact-analysis workflow, freshness rules, and its non-authoritative boundary.
- [AWX host identity enrollment v1](contracts/awx-host-identity-enrollment-v1.md)、[AWX governed launch admission v1](contracts/awx-governed-launch-admission-v1.md) 与 [Host identity attestor v1](contracts/host-identity-attestor-v1.md) — Phase 5 已确认后继安全契约；对应业务实现仍以状态源为准。

## Delivery and operations

- [SME internal pilot implementation plan](plans/2026-07-10-sme-internal-aiops-pilot.md) — phased implementation and acceptance plan.
- [Runner Gateway M3](plans/2026-07-11-runner-gateway-m3.md) — mTLS identity, strict protocol, and fail-closed start boundary.
- [Isolated executor M4](plans/2026-07-11-isolated-executor-m4.md) — split trust domains, READY/GO protocol, and termination semantics.
- [Investigation runtime M5](plans/2026-07-11-investigation-runtime-m5.md) — durable investigation facts, READ Runner fencing, immutable connector/plan admission, and remaining Temporal assembly gates.
- [Roadmap and release gates](roadmap.md) — current delivery status and the conditions for enabling production writes.
- [Current status](status/current.md) — the sole completion and capability state source.
- [Runner Gateway security-file staging](operations/runner-gateway-identity-files.md) — secure Kubernetes staging and rotation runbook for mTLS and credential-protection material.
- [Isolated Runner runtime gates](operations/isolated-runner-runtime.md) — split image build, Linux capability checks, and external sandbox gates.
- [READ connector registry](operations/read-connector-registry.md) — immutable typed connector contracts consumed by target/runtime admission.
- [READ target and fixed executor runtime](operations/read-target-runtime.md) — content-addressed target/egress policy, fixed Prometheus/VictoriaLogs transport, and the still-unassembled claim boundary.
- [READ runtime bundle and closed admission](operations/read-runtime-bundle.md) — atomic connector/target/egress/executor digest graph, READ-only client capabilities, and the non-configurable closed claim gate.
- [Investigation plan manifest](operations/investigation-plan-manifest.md) — trusted Signal scope, exact profile matching, four-digest binding, and fail-closed rollout boundary.
- [Temporal investigation preparation](operations/temporal-investigation-preparation.md) — digest-bound Workflow/Activity, History allowlist, replay, and unassembled rollout boundary.
- [Temporal READ orchestration](operations/temporal-read-orchestration.md) — v2 digest queues, recovery-first READ Task state machine, strict converter, server-attested role-isolated Starter/Control Worker, Runner Activity boundary, and closed rollout gate.
- [Investigation runtime binding](operations/investigation-runtime-binding.md) — persistent Plan/Task/Attempt/Receipt runtime fences and migration gates.
- [Investigation result recovery](operations/investigation-result-recovery.md) — DB-only deterministic recovery after completion-response loss.
- [Local PostgreSQL 18.4 development](operations/local-postgresql-development.md) — workstation `colima-aiops` mTLS test instance, external Secret paths and stable verification commands.

## Historical material

- [Archive index](archive/README.md) — superseded documents retained only for decision traceability.

## Documentation rules

1. Current normative architecture belongs in `docs/architecture/`; start from its README.
2. Time-bound execution plans belong in `docs/plans/`.
3. Superseded documents move to `docs/archive/` when practical and must be labeled historical/non-normative. Existing V3 and 2026-07-10/11 documents may remain in place for traceability but are not execution entry points.
4. Security-sensitive behavior must be reflected in code tests and [SECURITY.md](../SECURITY.md), not only in prose.
5. Architectural changes should update the blueprint and include an ADR once the ADR process is introduced.
