# M2D OIDC credential-revocation administration

## Objective

Expose the existing durable `MANUAL_REQUIRED` recovery transitions through an
OIDC-authenticated, exact-scope management API without bringing protected Vault
reference material into the public control-plane process.

Production write execution remains impossible. This slice administers cleanup
records only; it cannot create or execute actions, issue credentials, or turn on
write claims.

## Public contract

```text
GET  /api/v1/workspaces/{workspaceID}/environments/{environmentID}/credential-revocations
GET  /api/v1/workspaces/{workspaceID}/environments/{environmentID}/credential-revocations/{revocationID}
POST /api/v1/workspaces/{workspaceID}/environments/{environmentID}/credential-revocations/{revocationID}/requeues
POST /api/v1/workspaces/{workspaceID}/environments/{environmentID}/credential-revocations/{revocationID}/external-confirmations
```

- List defaults to `MANUAL_REQUIRED`, uses descending `(created_at,
  revocation_id)` keyset pagination, defaults to 50, and caps at 100.
- Requeue has an empty body. External confirmation accepts exactly one strict
  JSON field: `evidence_hash`, a lowercase SHA-256 digest.
- All responses use `Cache-Control: no-store` and
  `X-Content-Type-Options: nosniff`; errors retain the existing RFC 9457 problem
  shape.
- A cross-scope or unknown revocation returns the same 404 response.
- Response DTOs are explicit safe projections. They never contain accessor
  ciphertext/HMAC/key ID, lease or claim token digests, worker identity, Vault
  bodies, or raw failure text.

## Trust boundary and RBAC

- The OIDC principal supplies the only subject and role source. Audit subjects
  are canonicalized as `oidc:<sub>`; bodies and identity-like headers are
  ignored.
- Read: SRE, Auditor, Platform Admin (`ADMIN`).
- Requeue: Platform Admin only.
- External confirmation: SRE or Platform Admin. The persisted
  `platform_admin` bit is derived only from `RoleAdmin`.
- Requeue and confirmation require recent OIDC authentication (default five
  minutes; configured range one to fifteen minutes).
- Workspace and environment must both occur in the verified Principal and in
  the same SQL predicate used for every read or mutation.

## Persistence and transactions

- `credential/postgres.ManagementRepository` is constructed with a database
  only, not a `ReferenceProtector`, and its SQL projection cannot select
  protected columns.
- Every read and mutation writes immutable audit evidence in the same
  transaction. Mutations also append an outbox event.
- Requeue permits only `MANUAL_REQUIRED` with no evidence or confirmations;
  total attempt/failure counters remain monotonic while the two-hour retry cycle
  restarts.
- The first external confirmation freezes the evidence hash and leaves the row
  `MANUAL_REQUIRED`. The second must be a different subject with the same hash;
  at least one confirmation must be from a Platform Admin. The second insert,
  transition to `REVOKED`, protected-reference clearing, audit, and outbox are
  atomic.
- The existing deferred confirmation trigger remains the final database
  defense. A management scope/status/created-at/revocation-id index supports
  stable keyset reads.
- Visible lifecycle times are finite and ordered (`created_at <=
  manual_required_at <= revoked_at <= updated_at`, omitting absent stages).
  The transition trigger samples one post-lock database clock and advances
  `updated_at`; claim failures first lock the exact claim fence and only then
  sample the clock used for expiry, elapsed-time, backoff, and transition
  decisions. A row-lock wait therefore cannot revive an expired claim or
  create a management record that the safe projection must reject.

## TDD evidence

1. RBAC matrix, exact workspace/environment scope, recent-auth boundaries, and
   future/stale `auth_time`.
2. Strict HTTP media type/body/duplicate-key/unknown-field/trailing-data/size
   validation, BOLA 404 behavior, no-store headers, cursor stability, and secret
   canary scans.
3. Service tests proving subject/admin derivation and fail-closed validation of
   hostile store results.
4. PostgreSQL unit and real PostgreSQL 16 tests for safe projection, keyset
   pagination, concurrent confirmation/requeue, audit/outbox rollback, immutable
   confirmations, direct-SQL non-admin/hash attacks, and guarded down migration.

## Rollback and residual gates

The management index is removed with migration `000008`; destructive down
remains blocked by `MANUAL_REQUIRED`, evidence, confirmations, active cleanup,
or undelivered outbox state. Evidence hashes remain human assertions until an
enterprise evidence-normalization runbook exists. Database superusers remain
outside application-level append-only guarantees; role separation and WORM
audit export are external deployment gates.
