# Changelog

All notable project changes will be documented here. The project follows semantic versioning once its first public release is cut.

## [Unreleased]

### Added

- Initial open-source repository structure and community documentation.
- Scoped signal ingestion and bounded read-only connector foundations.
- Evidence-driven investigation and hybrid model-routing foundations.
- Keycloak OIDC, workspace/environment RBAC, signed ActionEnvelope, and CEL policy gates.
- Fenced execution leases, typed action contracts, credential lifecycle controls, and PostgreSQL queue foundations.

### Security

- Added a Linux-only, fixed-root control-worker public-source snapshot that validates trusted directory ancestors, exact owner-only artifacts, content-addressed target CA closure and distinct public client certificates before publishing a read-only fully sealed memfd capability. A killable, reap-confirmed public-only loader child bounds fixed-root I/O; the parent rebuilds the sealed capability without exposing its descriptor and starts the contained control child with only fixed FD3/FD4. The control child rejects extra inherited capabilities and independently revalidates the canonical frame, artifact closure and certificates, while still performing no semantic Snapshot assembly, secret load, Dial, or READY.
- Production write automation remains disabled until all documented Go/No-Go gates pass.
