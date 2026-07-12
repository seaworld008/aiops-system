# Documentation

This directory separates current architecture, executable delivery plans, and superseded historical material.

## Current architecture

- [Architecture overview](architecture/overview.md) — concise English introduction to components and trust boundaries.
- [2026 V3 implementation blueprint](architecture/implementation-blueprint-v3.md) — authoritative detailed design and safety contract (Chinese).

## Delivery and operations

- [SME internal pilot implementation plan](plans/2026-07-10-sme-internal-aiops-pilot.md) — phased implementation and acceptance plan.
- [Runner Gateway M3](plans/2026-07-11-runner-gateway-m3.md) — mTLS identity, strict protocol, and fail-closed start boundary.
- [Isolated executor M4](plans/2026-07-11-isolated-executor-m4.md) — split trust domains, READY/GO protocol, and termination semantics.
- [Investigation runtime M5](plans/2026-07-11-investigation-runtime-m5.md) — durable investigation facts, READ Runner fencing, immutable connector/plan admission, and remaining Temporal assembly gates.
- [Roadmap and release gates](roadmap.md) — current delivery status and the conditions for enabling production writes.
- [Runner Gateway security-file staging](operations/runner-gateway-identity-files.md) — secure Kubernetes staging and rotation runbook for mTLS and credential-protection material.
- [Isolated Runner runtime gates](operations/isolated-runner-runtime.md) — split image build, Linux capability checks, and external sandbox gates.
- [READ connector registry](operations/read-connector-registry.md) — immutable typed connector contracts and target-manifest prerequisites.
- [Investigation plan manifest](operations/investigation-plan-manifest.md) — trusted Signal scope, exact profile matching, four-digest binding, and fail-closed rollout boundary.

## Historical material

- [Archive index](archive/README.md) — superseded documents retained only for decision traceability.

## Documentation rules

1. Current normative architecture belongs in `docs/architecture/`.
2. Time-bound execution plans belong in `docs/plans/`.
3. Superseded documents move to `docs/archive/` and must be labeled non-normative.
4. Security-sensitive behavior must be reflected in code tests and [SECURITY.md](../SECURITY.md), not only in prose.
5. Architectural changes should update the blueprint and include an ADR once the ADR process is introduced.
