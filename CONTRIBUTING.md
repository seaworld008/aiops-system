# Contributing to AIOps System

Thank you for helping build a trustworthy, evidence-first operations platform. Contributions are welcome, especially tests, threat models, connector contracts, documentation, reliability work, and narrowly typed automation.

## Before you start

- Search existing issues and discussions before opening a duplicate.
- Open an issue or discussion before a large feature, new mutation type, schema redesign, or trust-boundary change.
- Never include real logs, credentials, tokens, customer data, internal hostnames, or private incident material in issues, fixtures, or commits.
- Read [SECURITY.md](SECURITY.md) before reporting a vulnerability.

## Development setup

```bash
git clone https://github.com/seaworld008/aiops-system.git
cd aiops-system
go version
go mod download
make test
make vet
make build
```

Go 1.26.5 is the repository toolchain baseline. PostgreSQL 16+ is required for real migration and repository integration tests.

## Change workflow

1. Create a focused branch from `main`.
2. Write a failing test for behavioral changes.
3. Implement the smallest safe change.
4. Run formatting, race tests, vet, and builds.
5. Update current architecture or operational documentation when behavior changes.
6. Open a pull request using the repository template.

Recommended checks:

```bash
gofmt -w <changed-go-files>
go test -race -shuffle=on -count=1 ./...
go vet ./...
go build ./cmd/control-plane ./cmd/worker ./cmd/read-runner ./cmd/write-runner ./cmd/executor
git diff --check
```

When Docker/BuildKit is available, also verify that the READ and WRITE trust domains remain
physically separate:

```bash
make runner-images
```

Release builds must override `GO_BUILD_IMAGE` with an approved immutable digest; the Makefile's
full-version tag is for local and CI verification only.

If PostgreSQL is available:

```bash
AIOPS_TEST_POSTGRES_DSN='postgres://aiops:password@127.0.0.1:5432/aiops_test?sslmode=disable' \
  go test -race -count=1 ./internal/store/postgres ./internal/execution/postgres
```

## Safety invariants

Changes must preserve these invariants:

- model output is untrusted input;
- only typed, versioned actions can reach a write runner;
- permissions, risk, approvals, and execution are deterministic decisions;
- workspace and environment scope is checked at every storage and execution boundary;
- credentials never enter model prompts, logs, PostgreSQL domain records, or workflow history;
- production approvals bind the plan hash, exact target, parameters, observed revision, policy version, and expiry;
- stale leases cannot write results or repeat side effects;
- uncertain outcomes retain locks until authorized reconciliation;
- the READ image cannot contain a mutation executor, while the WRITE image can only invoke the
  fixed `/usr/local/libexec/aiops-executor` without payload-selected argv or environment;
- production writes remain disabled unless every documented release gate passes.

An implementation that makes a demo easier but weakens one of these boundaries will not be accepted.

## Code and API expectations

- Keep package APIs narrow and domain-oriented.
- Prefer a modular monolith over premature service decomposition.
- Bound every external query by deadline, concurrency, range, size, and field allowlist.
- Use RFC 9457 problems for HTTP errors, opaque cursors for lists, `Idempotency-Key` for writes, and `If-Match` for updates.
- Avoid arbitrary command execution, generated mutation payloads, and generic tool dispatch.
- Add migrations as ordered up/down pairs; never edit a released migration without an explicit compatibility decision.

## Commit and review style

Use concise, imperative commit subjects such as:

```text
feat: add scoped incident replay
fix: fence expired runner completion
docs: clarify production write gates
```

Pull requests should explain the user impact, trust-boundary impact, tests, migration behavior, and rollback path. Reviewers may ask for adversarial or concurrency tests even when happy-path tests pass.

## Documentation language

English is the default language for the public project entry points. High-value Chinese documentation is welcome and should link to its English counterpart when one exists. The detailed V3 blueprint is currently maintained in Chinese while the public architecture overview is maintained in English.

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
