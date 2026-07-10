# Credential Revocations M2A Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add the durable, secret-safe credential revocation lifecycle, migration, reference protector, and memory/PostgreSQL repositories without wiring it into execution yet.

**Architecture:** `internal/credential` owns the redacted domain contract, a mutex-protected reference repository, and an AES-256-GCM/HMAC reference protector. `Prepare` returns `PrepareResult`: only an error-free `Created=true` authorizes one child-credential creation, while replays return the existing canonical revocation ID with `Created=false`. Anchor idempotency authenticates the incoming accessor with its stored-key HMAC; only `ClaimRevocations` decrypts. `internal/credential/postgres` implements the same contract with transactions that validate M1 action fences, use row-level claim fencing, and atomically append redacted audit/outbox records. Migration `000008` keeps an `action_id` foreign key plus workspace/environment/runner scope foreign keys, while a `FOR SHARE` Prepare transaction copies and freezes the currently verified action fence; it deliberately does not reference M1's mutable active-lease columns, which Nack/expiry must clear. Database triggers enforce the fixed lifecycle, initial/version/monotonic invariants, terminal immutability, stable AAD identity, and append-only audit records including `TRUNCATE`.

**Tech Stack:** Go 1.26, PostgreSQL 16 SQL, pgx v5, pgxmock v4, standard-library AES-GCM/HMAC/SHA-256.

---

### Task 1: Domain contract and protected reference

**Files:**
- Create: `internal/credential/revocation.go`
- Create: `internal/credential/protector.go`
- Test: `internal/credential/protector_test.go`

1. Write failing tests for AEAD round trips, AAD substitution, key rotation, keyed HMAC shape, zeroization, and JSON/string redaction.
2. Run `go test ./internal/credential -run 'Test.*Protector|Test.*Reference'` and retain the compile/failure output as RED evidence.
3. Define the eight fixed states, typed requests/fences, redacted `Revocation`, `PrepareResult` creation decision, claim-only `SensitiveReference`, sentinel errors, and the independent `Repository` interface.
4. Implement AES-256-GCM with a copied in-memory key ring. Prefix ciphertext with the nonce, bind revocation/action/epoch/issuer in deterministic AAD, and authenticate the same context plus plaintext with keyed HMAC-SHA256.
5. Run the focused test again for GREEN.

### Task 2: Memory reference repository

**Files:**
- Create: `internal/credential/memory.go`
- Test: `internal/credential/revocation_test.go`

1. Write failing state-machine tests for prepare derivation/fence validation, immutable idempotency conflicts, anchor/activate/no-credential branches, request/claim/reclaim, stale claim fences, retry delay/hash sanitization, manual requeue, and two-person confirmation.
2. Run `go test ./internal/credential -run 'TestMemoryRevocation'` for RED.
3. Implement a mutex-protected record map using an injected action-fence resolver, clock, token source, and protector. Atomically elect one `Created` winner and return the stored canonical ID on semantic replays. Store only protected references; only claim decrypts into a destroyable object.
4. Keep all returned `Revocation` values redacted and compare completion/confirmation fences for idempotency.
5. Run the focused tests under `-race` for GREEN.

### Task 3: PostgreSQL migration

**Files:**
- Create: `migrations/000008_credential_revocations.up.sql`
- Create: `migrations/000008_credential_revocations.down.sql`
- Create: `internal/credential/postgres/migration_test.go`

1. Write static failing tests for fixed states, action-queue scope FK, unique action epoch, ciphertext/HMAC/key constraints, claim/completion shapes, confirmation identities, cutover warning, and SQLSTATE `55000` down guard.
2. Run `go test ./internal/credential/postgres -run TestCredentialRevocationMigration` for RED.
3. Add the schema with immutable ownership/AAD identity, an explicit initial-and-transition state machine, monotonic version/counters/time, terminal immutability, action/scope/runner foreign keys, trusted transactional runner/epoch/digest binding, encrypted-reference and exclusive revoked-proof checks, leased-claim checks, two-person confirmation rows, and audit `TRUNCATE` protection.
4. Make down migration take strong locks and permit only safe `REVOKED`/`NO_CREDENTIAL` rows without confirmation evidence.
5. Run the static tests for GREEN.

### Task 4: PostgreSQL repository

**Files:**
- Create: `internal/credential/postgres/repository.go`
- Create: `internal/credential/postgres/repository_test.go`

1. Write pgxmock failing tests for fence-derived prepare, hashed action/claim tokens, `statement_timestamp()` retry delay, redacted claim projection, first-failure audit/outbox atomicity, completion idempotency, manual transition, and confirmation transactions.
2. Run focused tests for RED.
3. Implement all repository methods with explicit transactions, row locks, generic non-leaking errors, atomic `INSERT ... ON CONFLICT ... RETURNING` Prepare creation decisions/canonical replay, and a shared state-change audit/outbox writer whose payload allowlist is `revocation_id`, `action_id`, `workspace_id`, `issuer`, `attempt`, `failure_code`, and `detail_hash`.
4. Ensure claim obtains candidates with `FOR UPDATE SKIP LOCKED`, increments claim epoch, stores only SHA-256 token digests, and rolls back if reference decryption fails.
5. Run focused tests under `-race` for GREEN.

### Task 5: Real PostgreSQL lifecycle and rollback guards

**Files:**
- Create: `internal/credential/postgres/integration_test.go`
- Modify only if needed: `internal/store/postgres/migrations_integration_test.go`

1. Add an opt-in PostgreSQL 16 harness using `AIOPS_TEST_POSTGRES_DSN`.
2. Exercise canonical one-winner concurrent Prepare, one-winner concurrent claim, whole-batch rollback on AEAD failure, illegal lifecycle/proof SQL, expired reclaim, stale fences, encrypted storage shape, immutable audit, first-failure audit/outbox, manual confirmations, guarded down, and repository reconstruction over the same durable rows.
3. Run the integration package against the available DSN; otherwise record the explicit skip and rely on the repository's standard full-migration harness.

### Task 6: Verification and single M2A commit

**Files:** all M2A files above.

1. Run `gofmt` on all new Go files and `git diff --check`.
2. Run focused `go test -race ./internal/credential/...`.
3. Run full `go test -race ./...`, `go vet ./...`, and `go build ./...`.
4. Run `govulncheck ./...` when installed and report availability/failure exactly.
5. Re-read the M2A boundary to ensure Broker, execution Service, HTTP API, runtime assembly, and production write switches are untouched.
6. Create one commit containing the plan, tests, migration, and implementation; do not push, merge, or open a PR.

### Task 7: Canonical expiry and commit-time Prepare fence

**Files:**
- Modify: `internal/credential/revocation.go`
- Modify: `internal/credential/memory.go`
- Modify: `internal/credential/revocation_test.go`
- Modify: `internal/credential/postgres/repository.go`
- Modify: `internal/credential/postgres/repository_test.go`
- Modify: `migrations/000008_credential_revocations.up.sql`
- Modify: `internal/credential/postgres/migration_test.go`

1. Write one failing memory test showing nanosecond expiry requests within the same PostgreSQL microsecond replay the canonical row and return the exact canonical timestamp.
2. Add `CanonicalCredentialExpiry`, fixed `MaxCredentialTTL = 15 * time.Minute`, and `MinPrepareFenceWindow = time.Second`; canonicalize before every validation, comparison, insert, and return.
3. Run the focused memory test for GREEN.
4. Write a failing pgxmock test requiring a second action-fence query immediately before both new-row and replay commits; make the second query reject a lease/authorization window below one second and roll back without `Created=true`.
5. Add the second database-time validation, including stable action scope, runner, epoch, token digest, active status, maximum credential TTL, and one-second remaining window.
6. Add a durable SQL check and static/real PostgreSQL negative tests enforcing `credential_expires_at <= created_at + interval '15 minutes'`.
7. Run the focused PostgreSQL tests under `-race` for GREEN.

### Task 8: Frozen-fence anchor and invalid-action handoff

**Files:**
- Modify: `internal/credential/revocation.go`
- Modify: `internal/credential/memory.go`
- Modify: `internal/credential/revocation_test.go`
- Modify: `internal/credential/postgres/repository.go`
- Modify: `internal/credential/postgres/repository_test.go`

1. Write a failing memory test whose live bearer resolver rejects after Prepare but whose non-bearer inspection retains matching stable metadata. Inspect before taking the repository mutex; assert RecordAnchor does not call the resolver, persists the accessor, writes ANCHORED semantics, and returns REVOCATION_PENDING when inspection says the frozen fence is no longer current.
2. Extend the action source with `InspectAction(context.Context, actionID) (ActionInspection, error)`. `ActionInspection` contains stable metadata, only the token digest, current epoch/status/lease/auth windows, and no plaintext token.
3. Validate the RecordAnchor request solely against the locked PREPARED record's frozen action ID, runner, epoch, and token digest. Reject inspection scope mismatch; treat expiry/Nack as invalid-current rather than a stale-anchor error.
4. For an invalid current fence, perform ANCHORED then REVOCATION_PENDING transitions atomically and return PENDING. Run the memory test for GREEN.
5. Write the equivalent pgxmock tests. Lock the action row `FOR SHARE` without the bearer first, then lock the revocation, compare frozen fence plus stable scope, and append anchored plus requested audit/outbox pairs in one transaction.
6. Re-read database time immediately before both new and idempotent anchor commits. Require a fixed one-second post-child window; if lease, authorization, or credential TTL is no longer safely current, append the requested transition in the same transaction.
7. Apply the same non-bearer frozen-fence contract to Activate. Only a final-current ANCHORED row may commit ACTIVE; an initially or finally invalid ANCHORED/ACTIVE row atomically becomes REVOCATION_PENDING with its requested audit/outbox pair.
8. Run PostgreSQL focused tests for GREEN, including live, expired, Nack-cleared, new/idempotent anchor, and Activate commit-window shapes.

### Task 9: Auditable expired-PREPARED recovery

**Files:**
- Modify: `internal/credential/revocation.go`
- Modify: `internal/credential/memory.go`
- Modify: `internal/credential/revocation_test.go`
- Modify: `internal/credential/postgres/repository.go`
- Modify: `internal/credential/postgres/repository_test.go`

1. Add a failing public-contract test for `RecoverPrepared(context.Context, RecoverPreparedRequest{Limit})`: before `credential_expires_at + 1m` it returns none; at the boundary it returns one NO_CREDENTIAL; replay returns none. Use a short TTL to prove recovery does not wait for the maximum 15-minute ceiling.
2. Implement bounded batch validation (`1..100`) and deterministic absolute-deadline/ID ordering under the repository mutex.
3. Run the memory recovery test for GREEN.
4. Add a failing pgxmock test requiring database-only eligibility, `FOR UPDATE SKIP LOCKED`, PREPARED/no-accessor filtering, versioned NO_CREDENTIAL transition, and `credential.revocation.prepared_expired` audit plus `.v1` outbox writes.
5. Implement the transactional PostgreSQL recovery. Do not accept a caller timestamp or configurable grace; use the durable `credential_expires_at` plus a fixed one-minute SQL interval, with a matching partial index ordered by deadline and ID.
6. Specify the caller invariant: `CredentialExpiresAt` is the child's absolute deadline; after `Created=true`, M2B permits one immediate, non-retried issuer call, computes TTL from trusted database-time remaining budget, and verifies actual child expiry cannot exceed that deadline. The fixed one-minute grace covers only explicitly bounded clock skew and expiration propagation, never a newly started issuer TTL.
7. Keep the durable maximum-TTL cap, and run the focused PostgreSQL recovery tests for GREEN, including short-TTL boundary, concurrent/at-least-once selection, deterministic limited batches, and outbox rollback.

### Task 10: Real PostgreSQL evidence, documentation, and final amend

**Files:**
- Modify: `internal/store/postgres/migrations_integration_test.go`
- Modify: `docs/plans/2026-07-10-credential-revocations-m2a.md`
- Create: `docs/plans/2026-07-10-credential-revocation-hardening-design.md`

1. Extend the opt-in PostgreSQL 16 harness with nanosecond Prepare/replay, commit-window rejection, live and Nack/expired anchor handoff, and recovery immediately before/at/after the fixed database-time boundary.
2. Document the issuance proof: durable ANCHORED acknowledgement precedes dynamic Secret signing; PREPARED with no accessor has not crossed that anchor barrier. M2B makes one immediate, non-retried Vault call on the exact leased path with `num_uses=2`, derives TTL from a trusted database-time budget, and verifies child expiry is no later than durable `CredentialExpiresAt`; Broker therefore allows at most one leased-secret response. Recovery waits until `credential_expires_at + 1m`. The grace covers only bounded clock/propagation error, not issuer lifetime.
3. Run `gofmt` and `git diff --check`.
4. Run `go test -race -shuffle=on -count=1 ./internal/credential/... ./internal/store/postgres` and then `go test -race -shuffle=on -count=1 ./...`.
5. Run `go vet ./...`, `go build ./...`, and `go run golang.org/x/vuln/cmd/govulncheck@latest ./...`; record an explicit real-PostgreSQL skip when the DSN is unavailable.
6. Stage only M2A files and use `git commit --amend --no-edit`. Confirm `2f554b7..HEAD` still contains exactly one commit; do not push.
