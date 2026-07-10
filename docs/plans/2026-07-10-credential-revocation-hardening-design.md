# Credential Revocation M2A Hardening Design

## Scope

This amendment hardens only the M2A credential repository and migration contract. It does not wire Broker, Vault, execution Service, HTTP, runtime assembly, or a production write switch.

## Time and issuance invariant

Credential expiry is canonicalized at every repository boundary to PostgreSQL microsecond precision with `time.UnixMicro(value.UnixMicro()).UTC()`. Prepare accepts only an expiry after the repository/database clock and no later than 15 minutes after that clock. Prepare also requires the action lease and authorization window to have at least one second remaining both when the transaction starts and immediately before commit.

The M2B protocol must never sign or issue a dynamic Secret before the durable accessor anchor has reached ANCHORED and that anchor acknowledgement has returned. A PREPARED row with no accessor therefore proves that execution has not crossed the anchor barrier. It can represent a child token, but Broker has not signed or returned a dynamic Secret. With Vault's exact leased-secret path, `num_uses=2`, and one Broker lease call, at most one leased-secret response can succeed.

`CredentialExpiresAt` is a persisted absolute deadline, not a relative TTL that may restart when Vault is called. After an error-free `Created=true`, M2B may make exactly one immediate, non-retried child-creation call. It must derive Vault TTL from a trusted database-time remaining budget, refuse issuance after the bounded create-latency/skew allowance, and configure plus verify that the actual child expiry is no later than the persisted `CredentialExpiresAt`. Delayed creation and issuer retries are forbidden. The deployment must bound combined database/Broker/Vault clock skew and expiration propagation strictly below the fixed one-minute grace; that grace is not additional credential lifetime and cannot absorb an arbitrary Vault default TTL.

Recovery is tied directly to the durable upper bound: a PREPARED row becomes eligible only when database time reaches `credential_expires_at + 1 minute grace`. The migration separately enforces `credential_expires_at <= created_at + 15 minutes` as the maximum requested absolute deadline, while shorter credentials converge sooner. Under the preceding M2B issuance precondition, the child is then guaranteed unable to remain valid and PREPARED can safely become NO_CREDENTIAL. Until M2B implements and contract-tests that precondition, no production caller or write switch may use this M2A repository to authorize child creation.

## Prepare and replay

Prepare retains the atomic `PrepareResult.Created` decision and canonical-ID replay behavior. The PostgreSQL transaction performs a second query for the same action, runner, epoch, token digest, stable scope, active status, and minimum remaining window after insert/audit/outbox work and before every commit path. A failed revalidation rolls back and never returns `Created=true`. To preserve action-to-repository lock order, the memory reference implementation performs both action-source validations before taking its mutex, then atomically elects the in-memory Created winner.

## Anchor after action invalidation

RecordAnchor preserves the global action-to-revocation lock order: PostgreSQL first performs a non-bearer action inspection with `FOR SHARE`, then locks and reads the durable revocation. The memory implementation likewise inspects before taking its repository mutex. After both snapshots are available, the repository authenticates the request fence against the frozen action ID, runner, epoch, and token digest without calling the live bearer resolver. Stable-scope disagreement is rejected; expiry, Nack, or another live-fence invalidation is not.

For a current action, the transaction persists PREPARED to ANCHORED and writes the anchored audit/outbox pair. Immediately before commit it obtains a fresh `statement_timestamp()` and requires the action lease, authorization, and credential TTL to remain beyond a fixed one-second post-child safety window. For an action that was invalid initially or no longer passes that final check, the same transaction first persists the anchor and its event, then transitions ANCHORED to REVOCATION_PENDING and writes the requested audit/outbox pair. The idempotent ANCHORED/ACTIVE anchor path performs the same final database-time check. The returned state is REVOCATION_PENDING, preventing an anchored credential from becoming stranded.

PostgreSQL holds the action-row share lock through the anchor transaction, preventing a lock-order inversion with Prepare, action transitions, or Nack. The memory action source exposes an inspection method with no plaintext bearer material; because it cannot hold an external action-source lock across the repository mutation, it is a reference implementation rather than the durable atomicity boundary.

## Activation after anchoring

Activate is a post-child operation and therefore does not depend on a still-reusable action bearer. It follows the same action-first lock order and non-bearer inspection as RecordAnchor, authenticates the raw request only against the durable frozen action ID, runner, epoch, and token digest, then verifies the stable action scope. PREPARED and NO_CREDENTIAL remain invalid transitions; REVOCATION_PENDING, REVOKING, MANUAL_REQUIRED, and REVOKED are idempotent terminal/recovery observations.

ANCHORED advances to ACTIVE only while the inspected action fence, lease, authorization, and credential TTL are current. After the ACTIVE audit/outbox pair is written, PostgreSQL obtains a fresh `statement_timestamp()` and repeats the one-second safety-window check before commit. If either the initial or final check fails, ANCHORED or ACTIVE is atomically moved to REVOCATION_PENDING with the requested audit/outbox pair. Thus Nack, lease expiry, authorization expiry, or credential expiry cannot commit an unrecoverable ACTIVE/ANCHORED credential.

## PREPARED recovery

`RecoverPrepared(ctx, RecoverPreparedRequest{Limit})` is an at-least-once, bounded repository operation. PostgreSQL selects `credential_expires_at <= statement_timestamp() - interval '1 minute'` with `FOR UPDATE SKIP LOCKED`, ordered and indexed by absolute deadline then revocation ID. Each selected row atomically transitions to NO_CREDENTIAL and appends `credential.revocation.prepared_expired` audit plus `credential.revocation.prepared_expired.v1` outbox records. Concurrent processes cannot recover the same row twice; retries return no already-terminal rows. The memory implementation provides the same selection, boundary, ordering, and idempotent state semantics.

The recovery grace is a fixed one minute across all instances to prevent policy drift. It is valid only with the documented bounded create latency, absolute child deadline, clock-skew, and expiration-propagation preconditions.

## Verification

Tests cover nanosecond expiry canonicalization and replay, live and invalidated/Nacked anchor paths, absence of live bearer resolution during anchor or Activate, initial and final-time invalidation for Anchor/Activate, short-TTL recovery before/at the absolute deadline plus grace, deterministic deadline/ID limited batches, concurrent recovery, audit/outbox atomicity, Prepare end-of-transaction revalidation, dual-unique-key interleaving with local deadlines, pgxmock commit-window proofs, real PostgreSQL blocking-trigger proofs when a DSN is available, and the existing full race/vet/build/vulnerability gates.
