# Governed Operations Production Program

This directory is the executable plan set for turning the approved governed-operations design into a complete production closed loop. It is intentionally split into a short program index, phase indexes, and bounded task packs so future workers can load only the context required for the current task.

The current set contains 8 ordered phases, 59 bounded task packs, and 189 checkbox-driven implementation tasks. Planning completion does not change runtime capability state; every new Provider, page, migration, read capability, governed Action, and release gate remains unimplemented until its named evidence passes.

## Authoritative Inputs

- [Current project status](../../../status/current.md)
- [Approved design specification](../../specs/2026-07-13-operational-assets-controlled-access-design.md)
- [Program implementation plan](../2026-07-13-governed-operations-program.md)
- [Fast development and real qualification policy](../2026-07-15-fast-development-validation-program.md)
- [Specification-to-plan coverage matrix](coverage-matrix.md)
- [Verified production planning version baseline](version-baseline.md)
- Phase 5 normative successors: [AWX identity enrollment](../../../contracts/awx-host-identity-enrollment-v1.md), [governed launch admission](../../../contracts/awx-governed-launch-admission-v1.md), and [host identity attestor](../../../contracts/host-identity-attestor-v1.md)

If a task pack conflicts with the approved design, the design wins. If two task packs conflict, stop and resolve the contract in the program plan and the affected phase indexes before changing code.

## Product Dependency Order

1. [Asset Catalog and Discovery Control Plane](01-assets/README.md)
2. [Connection and Runtime Publication](02-connections/README.md)
3. [VictoriaMetrics Ecosystem](03-victoriametrics/README.md)
4. [Investigation Grants and Proactive Policies](04-proactive-grants/README.md)
5. [Host and PostgreSQL Read Diagnostics](05-host-postgresql/README.md)
6. [Production Platform and Read Path](06-production-platform/README.md)
7. [Governed Production Actions](07-governed-actions/README.md)
8. [Production Rollout and Sustained Operations](08-production-rollout/README.md)

Every phase index still defines scope, consumed and produced interfaces, production entry criteria, exit evidence, and migration ownership. During fast construction, the [execution policy overlay](../2026-07-15-fast-development-validation-program.md) owns Batch order, concurrency, commit boundaries, and G1–G4 validation timing. Closed code from a later phase may be built after its stable `Consumes` interfaces have merged; this never records phase acceptance or opens runtime capability.

Task packs must stay below 900 lines and phase/root indexes below 350 lines. Split a growing file by stable interface or production gate. Files, Interfaces, safety contracts and final evidence remain normative; old per-Task TDD and command lists feed the aggregated G2–G4 evidence rather than forcing identical verification after every checkbox.

## Production Closed-loop Boundary

The program is complete only when an asset can be onboarded and an eligible production event can travel through this entire chain:

```text
Versioned Source / Manual Registration
  -> validated Provider adapter + fenced discovery
  -> governed Asset + exact mapping
  -> validated Connection + Opaque Credential Reference
  -> published Target / Capability / Runtime / Runner Realm binding
  -> Alert / Incident / Approved Schedule
  -> governed read-only investigation
  -> bounded Evidence
  -> append-only PROPOSAL_ONLY ActionProposal or Human Review Finding
  -> human-requested, server-sealed immutable ActionPlan
  -> policy + reauthentication + approval
  -> short-lived single-purpose WRITE credential
  -> typed non-interactive execution
  -> independent post-action verification
  -> reconciliation / safe rollback / human escalation when needed
  -> Receipt + complete Audit chain
  -> release SLO / canary / sustained ownership
```

Unknown Source freshness, ambiguous mapping, publication drift, uncertain credential cleanup or failed execution/verification must prove the corresponding stop, revocation, reconciliation, safe rollback and human-escalation paths. A working UI, a successful read-only investigation, or a single mutation demo is not production acceptance.

## Non-negotiable Safety Rules

- The model never becomes an identity or authorization principal.
- The browser, model, workflow payload, and Runner payload never receive raw credentials or secret material.
- Production code uses real durable repositories, identity, policy, credential, Gateway, Runner, workflow, and audit integrations; fakes are test-only.
- No arbitrary shell, interactive SSH/WinRM, PTY, port forwarding, arbitrary SQL, generic endpoint/payload, or observability ingestion capability is introduced.
- Production mutation remains closed until a fixed Action type passes its own policy, approval, credential, execution, verification, recovery, drill, and canary gate.
- Phase 6 immutable READ baseline/handoff and Phase 7 content-addressed Action platform successor are both revalidated at admission boundaries；a registered WRITE increment cannot mutate the READ baseline, while any unregistered WRITE surface closes READ and WRITE admission.
- VM, VictoriaMetrics, VictoriaLogs, VictoriaTraces, databases, remote access paths, and other data sources are governed assets and capabilities, not ad-hoc connection strings.

## Working Method

Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans`. Work in isolated worktrees and group 2–4 related old Tasks into one 1–2 day Batch. Run G1 on every PR, G2 on every Batch, G3 on a vertical Milestone, and the full real-dependency/HA/security/recovery matrix only in G4 after system code is closed-complete. Preserve C0 contract tests and fail-closed behavior, keep production fakes unreachable, update durable status at each gate, and never delete user worktrees or weaken a real safety assertion to manufacture green results.
