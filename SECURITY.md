# Security Policy

Security is a primary product boundary for AIOps System. Please do not disclose suspected vulnerabilities in public issues, discussions, pull requests, or chat rooms.

## Supported versions

The project is pre-alpha. Security fixes are applied to the latest `main` branch only. There is no supported production release yet, and production write automation must remain disabled.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting flow:

<https://github.com/seaworld008/aiops-system/security/advisories/new>

Include, where possible:

- affected commit or component;
- required privileges and deployment assumptions;
- reproducible steps or a minimal proof of concept;
- impact on confidentiality, integrity, availability, workspace isolation, approvals, credentials, or execution fencing;
- any proposed mitigation;
- whether the report contains sensitive operational data.

Do not include real credentials or customer data. If a reproducer requires sensitive material, first send only a description and coordinate a safer transfer path.

## What to expect

Maintainers will aim to acknowledge a report within three business days, validate severity and affected boundaries, coordinate a fix and disclosure plan, and credit reporters who want public recognition. These are response targets, not a service-level agreement.

## High-priority vulnerability classes

We are especially interested in:

- cross-workspace or cross-environment access;
- signature, plan-hash, policy, approval, or idempotency bypass;
- stale Runner leases or duplicate side effects;
- arbitrary command, shell, SSH, generated mutation, or confused-deputy paths;
- credential exposure through logs, prompts, workflow history, storage, or error messages;
- prompt injection that crosses the deterministic trust boundary;
- server-side request forgery in connectors or OIDC discovery;
- audit tampering or missing security-relevant events;
- unsafe reconciliation of an uncertain execution.

Reports that only describe intended pre-alpha limitations, unsupported production deployment, or model-quality variance without a trust-boundary bypass may be handled as normal issues.

## Deployment responsibility

The repository defaults are for development. Operators are responsible for network segmentation, mTLS, Keycloak and Vault hardening, PostgreSQL security and backups, object-store policy, secret rotation, audit retention, and keeping all production mutation flags disabled until the published Go/No-Go gates pass. The fixed READ HTTP executor is currently an unassembled, locally tested contract; READ claims must also remain disabled until M5C2-4 assembly and its identity, digest, network, replay, and end-to-end gates pass.
