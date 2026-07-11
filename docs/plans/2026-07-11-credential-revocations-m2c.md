# Credential Revocations M2C Recovery, Worker, and Finalization

**Goal:** Make credential cleanup recoverable across process loss and make it
impossible for a WRITE target lock to be released before the credential for the
same action lease epoch is durably `REVOKED` or `NO_CREDENTIAL`.

**Boundary:** M2C connects the durable domain contracts and proves them in
memory, PostgreSQL 16, and Vault 2.0.3. It does not expose a Runner network API,
start a write loop from `cmd/runner`, pass a Secret to an unisolated executor,
or add any production-write mode. Those remain blocked on M3 and M4.

## Fixed safety policy

- Revocation claim lease: 30 seconds.
- Claim heartbeat: every 10 seconds, always extending to 30 seconds.
- Remote revoke timeout: 20 seconds.
- Retry: full jitter with a 5-second floor and 15-minute ceiling.
- Exhaustion: 12 claims or two hours in the current retry cycle, decided with
  repository/database time, enters `MANUAL_REQUIRED`. The first cycle starts
  with `revocation_requested_at`; an audited manual requeue starts a new cycle
  while the total attempt counter remains monotonic.
- ANCHORED issuance-stall grace: two minutes. Current ANCHORED rows younger
  than the grace are not swept; invalid action fences are swept immediately.
- Worker failure details are fixed canonical codes. Upstream errors, response
  bodies, tokens, accessors, lease IDs, and Secrets never become failure detail.
- Issuance and revocation profiles are immutable and keyed by persisted issuer
  ID plus revision. Old revokers remain registered until every matching record
  is terminal.

## C1: Durable recovery and revocation worker

### Task 1: Freeze the durable profile and exhaustion contract

**Files:**

- `internal/credential/revocation.go`
- `internal/credential/memory.go`
- `internal/credential/postgres/repository.go`
- `migrations/000008_credential_revocations.up.sql`
- corresponding unit, migration, and PostgreSQL integration tests

1. Add immutable `issuer_revision` to Prepare, Revocation, protected-reference
   AAD, persistence, audit-safe projections, and Broker result validation.
2. Add the fixed M2C timing/attempt constants. Retry delay outside the fixed
   5-second to 15-minute range is invalid.
3. Make normal failure recording decide retry versus `MANUAL_REQUIRED`
   atomically. PostgreSQL uses database `clock_timestamp()` under the row lock;
   process clocks cannot postpone or accelerate the two-hour boundary.
4. Add bounded exhausted-claim recovery for processes that died without a
   failure ACK. Pending or expired REVOKING work at the attempt/time boundary
   is moved to `MANUAL_REQUIRED` with immutable audit/outbox evidence.
5. Keep immediate manual escalation only for failures that cannot perform a
   remote revoke, such as an undecryptable protected accessor.

### Task 2: Recover stranded ANCHORED and ACTIVE rows

1. Add bounded `RecoverManaged` with deterministic ordering.
2. PostgreSQL performs an unlocked candidate scan, then rechecks each candidate
   under the global lock order:

   ```text
   runner registration -> action row -> exact scope binding -> credential row
   ```

3. Transition only after a second database-time validation proves the frozen
   Runner, scope revision, action epoch/token digest, cancellation, lease,
   authorization, credential deadline, or ANCHORED grace is no longer safe.
4. The memory reference uses the atomic action-inspection callback before its
   repository mutex. A current ACTIVE row and a current, young ANCHORED row are
   unchanged.
5. Every recovery transition atomically appends redacted audit/outbox evidence.

### Task 3: Quarantine protected-reference poison pills

1. Keep batch claim DB atomicity, but do not let one AEAD/key failure roll back
   and starve every valid candidate forever.
2. A failed unprotect is advanced through a fenced claim and immediately placed
   in `MANUAL_REQUIRED` with `INVALID_REFERENCE`, a fixed detail hash, cleared
   claim fields, and claimed/manual audit/outbox records in the same transaction.
3. No raw claim token or accessor for the quarantined row leaves the repository;
   other valid rows in the batch remain claimable.
4. Any SQL, audit, or outbox error still rolls back the entire batch and destroys
   all decrypted in-memory accessors.

### Task 4: Split issuer and revoker capabilities

**Files:**

- `internal/credential/vault/client.go`
- `internal/credential/vault/client_test.go`
- `internal/credential/vault/integration_test.go`

1. The issuer client holds only the manager TokenSource and implements child
   creation/inspection/dynamic issuance.
2. The revoker client holds only the revoker TokenSource and implements only
   revoke-accessor.
3. Both reuse the immutable strict profile and one-shot transport, but neither
   process needs the other's credential.
4. Unit and real tests prove each capability cannot invoke the opposite trust
   domain and that the existing Vault/PostgreSQL closure remains valid.

### Task 5: Implement the at-least-once worker

**Files:**

- `internal/credential/revocationworker/worker.go`
- `internal/credential/revocationworker/worker_test.go`

1. A run performs PREPARED recovery, managed recovery, exhausted-work
   escalation, then claims immediately processable work.
2. Resolve a revoker only from the persisted issuer ID/revision and frozen
   workspace/environment scope. No URL, path, body, wildcard, fallback, or
   request-supplied profile is accepted.
3. Destroy the accessor on every exit. Heartbeat remains active through remote
   revoke and the final repository ACK.
4. Heartbeat loss cancels the remote context and writes no success; the claim
   expires for a new epoch. A remote success with a lost DB ACK is likewise
   retried idempotently after expiry.
5. A revoker that ignores cancellation cannot block the worker past 20 seconds;
   its late completion is a safe duplicate side effect. A fixed one-call remote
   slot prevents repeated runs from accumulating unbounded detached calls.
   Claim batch size remains one until concurrent isolated workers exist, so a
   decrypted accessor never waits behind another 20-second remote operation.
6. Emit only redacted, low-cardinality results. The first failed transaction's
   existing `credential.revocation.failed.v1` event is the alert source; actual
   Pager/Feishu delivery remains an external operations gate.

## C2: Credential-terminal ActionQueue gate

**Files:**

- `internal/execution/action_queue.go`
- `internal/execution/postgres/repository.go`
- `migrations/000008_credential_revocations.up.sql`
- corresponding memory, pgxmock, migration, and PostgreSQL tests

1. Add a PostgreSQL trigger that rejects a WRITE action transition from
   `FINALIZING` or `UNCERTAIN` to `SUCCEEDED`/`FAILED` unless the exact
   `(action_id, lease_epoch)` credential row is `REVOKED` or `NO_CREDENTIAL`.
2. Add the same predicate directly to `Finalize`, `Reconcile`, and background
   FINALIZING recovery so normal callers receive `ErrCredentialCleanupPending`
   instead of a trigger error.
3. `FINALIZING -> UNCERTAIN` remains legal because UNCERTAIN retains the target
   lock. Reconciliation cannot release that lock until cleanup is terminal.
4. Once credential cleanup is terminal, background sweep may finalize a signed
   result receipt without the original plaintext action lease token. This is
   the cross-process recovery path.
5. The memory queue uses an injected atomic credential-finalization gate and
   fails closed for WRITE when the gate is missing or unavailable.
6. Add a stage-only check preventing new `credential_revocations.production`
   rows. Revocation processing itself never filters historical production rows.

## C3: Two-phase Broker and execution ordering

1. Remove caller-selected `ProfileID` from issuer selection. The immutable
   server registry selects a profile from the verified workspace, environment,
   action type, connector, permission, and signed resource tuple.
2. Split DurableBroker into a no-external-side-effect PREPARED phase and a
   single-use issue phase. The opaque prepared handle is shared-state,
   non-serializable, Broker-owned, and cannot be reused or forged.
3. Execution order becomes:

   ```text
   claim -> signature/environment -> final policy -> start safety/kill switch
   -> final environment -> PREPARED -> Start -> heartbeat
   -> authorize/create/anchor/issue/activate -> executor -> result receipt
   -> durable revocation request -> wait or leave FINALIZING for worker recovery
   ```

4. If Start fails, the Broker attempts `NO_CREDENTIAL`; a lost ACK remains a
   PREPARED row and converges through absolute-deadline recovery.
5. Heartbeat covers credential issuance as well as executor execution. A lost
   lease never starts the executor and the credential converges to revocation.
6. Executor success is never rewritten as failure because remote revocation is
   pending. It remains `completion_status=SUCCEEDED` in `FINALIZING` until the
   worker confirms cleanup.
7. Typed executors receive only `DurableCredential`, not the legacy lease-ID
   credential type. Secret transfer to a real process remains blocked on M4.

## Runtime and production-write boundary

- `AIOPS_WRITE_EXECUTION_MODE` has only `disabled` and `non-production`; empty
  means disabled and every production-like spelling is rejected. No production
  enum or hidden switch exists.
- PostgreSQL WRITE claim filters `production=false`, trusted environment state
  must be non-production, and DurableBroker retains its production rejection.
- `cmd/control-plane` receives no manager/revoker credential.
- `cmd/worker` may run the revocation-only role only after secure file/agent
  Secret sources, database protector keyring, and an immutable revoker registry
  validate at startup. Otherwise it exits non-zero.
- The current `cmd/runner --mode=write` is rejected. A real write Runner waits
  for M3 mTLS identity and M4 isolation; M2C does not deliver a Secret to it.
- Disabling writes never disables the revocation worker.

## Verification and exit criteria

1. TDD for each task: focused RED, minimal implementation, focused race, then
   full gates.
2. PostgreSQL 16 covers DB-time thresholds, poison quarantine, lock ordering,
   concurrent recovery, expired-claim reclaim, audit/outbox rollback, and all
   Finalize/Reconcile/Sweep bypass attempts.
3. Vault 2.0.3 plus PostgreSQL proves real child issuance, dynamic credential
   use, process-loss reclaim, accessor revocation, `REVOKED`, failed old DB
   login, and cross-process action finalization.
4. Canary material is absent from database, logs, audit, outbox, and test output.
5. Fixed gates:

   ```text
   gofmt -l .
   git diff --check
   go mod verify
   go test -race -shuffle=on -count=1 ./...
   go vet ./...
   go build ./cmd/control-plane ./cmd/worker ./cmd/runner
   go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
   ```

6. Obtain independent security reviews after C1, C2, and C3. Do not make the
   draft PR ready, merge it, or claim enterprise readiness until all M2C checks
   and external role/PKI/audit gates are complete.
