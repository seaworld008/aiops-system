## Summary

Describe the user or operator outcome and the smallest coherent change that delivers it.

## Why

Explain the problem, relevant evidence, and why this approach was selected.

## Trust-boundary impact

- Identity / workspace / environment scope:
- Policy / approval / plan binding:
- Credentials / secrets:
- Idempotency / leases / uncertain outcomes:
- Audit and data retention:

Write `None` only after checking each boundary.

## Validation

- [ ] New or changed behavior has tests.
- [ ] `go test -race -shuffle=on -count=1 ./...`
- [ ] `go vet ./...`
- [ ] `go build ./cmd/control-plane ./cmd/worker ./cmd/runner`
- [ ] `git diff --check`
- [ ] PostgreSQL migration/integration tests were run, or the reason they could not run is documented.

## Migration and rollback

Describe schema compatibility, rollout order, feature flags, and rollback or reconciliation behavior.

## Documentation

Link updated architecture, runbook, API, or user documentation. If no update is needed, explain why.
