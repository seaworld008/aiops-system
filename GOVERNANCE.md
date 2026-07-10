# Project Governance

AIOps System is currently a maintainer-led, open-source project. Governance is expected to evolve as the contributor base grows.

## Roles

### Contributors

Anyone who improves code, tests, documentation, design, threat models, or community support through the public contribution process.

### Reviewers

Regular contributors trusted to review a defined area. Reviewer status is earned through sustained, high-quality participation and does not grant permission to merge changes.

### Maintainers

Maintainers triage work, merge changes, manage releases and security responses, and protect architectural and safety invariants. The initial maintainer is [@seaworld008](https://github.com/seaworld008).

## Decision process

- Routine, reversible changes are decided through pull-request review.
- Cross-cutting architecture, new production mutation types, compatibility breaks, or trust-boundary changes require a public design proposal before implementation.
- Security embargoes may be handled privately until coordinated disclosure is safe.
- Maintainers seek rough consensus, but may reject changes that weaken safety, operability, or project scope even when technically functional.
- Unresolved major decisions should be recorded as ADRs once the ADR process is established.

## Becoming a reviewer or maintainer

Candidates should demonstrate sustained contributions, sound operational judgment, respectful collaboration, careful security reasoning, and reliable review participation. Existing maintainers nominate and approve role changes publicly, except where privacy or safety requires discretion.

## Conflicts of interest

Reviewers and maintainers should disclose material conflicts and recuse themselves when an employer, vendor relationship, or personal interest could reasonably affect a decision.

## Changes to governance

Governance changes use the same public proposal and review process as major architecture changes. No governance document overrides the [Code of Conduct](CODE_OF_CONDUCT.md) or the private [security reporting process](SECURITY.md).
