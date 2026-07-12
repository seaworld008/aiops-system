# Temporal investigation preparation runtime

M5C1B1 implements a real, replayable Temporal preparation Workflow and
Activity, but deliberately does not install them in `cmd/worker` or connect the
Signal Outbox dispatcher. READ claims, legacy READ lease progression, WRITE
claims, and every production-write path remain closed.

## Immutable runtime identity

- Workflow type: `aiops.investigation.prepare.v1`.
- Activity type: `aiops.investigation.prepare.activity.v1`.
- Workflow ID: the persistent `signal.ingested.v1` Outbox event ID.
- Task queue:
  `aiops-investigation-prepare-v1-<full-manifest-sha256>-<full-registry-sha256>`.
- Worker registration disables aliases and eager Activities. A compatible
  Worker for an old digest pair must remain available until every Workflow and
  READ Task on that queue is terminal.

The v1 Workflow registration name, Activity registration name, task-queue
prefix, DTO/control flow, canonical input/Memo encoding, and fixed default
converter form one immutable protocol tuple. Any non-replay-compatible change
requires new v2 Workflow/Activity names and a v2 queue prefix. Even a claimed
compatible binary must replay the retained History corpus before rollout;
merely replacing the image and continuing to poll an old digest queue is
forbidden unless that evidence passes.

The start input contains only schema version, Outbox/Tenant/Workspace/Signal
IDs, aggregate version, manifest digest, and registry digest. The result is
`PREPARED` or `NO_ACTIVE_INCIDENT` and contains only persistent IDs, task IDs
and count, plus manifest, registry, profile, and TaskSpec hashes. It contains no
Signal body, labels, Task input, target, request hash, input hash, credential,
or connector error.

The start Memo has exactly one versioned identity key and binds the complete
safe input. A package-owned routing converter deliberately writes that identity
and the matching Workflow and Activity inputs as deterministic JCS
`json/plain`, with exact metadata and a 2 KiB protobuf limit. An ACK-lost retry
can therefore compare both raw payloads exactly. Remaining result DTOs use
Temporal's fixed default converter. The Memo contains only persistent IDs,
schema/aggregate versions, and manifest and registry digests. It never contains
Signal content or labels, Task input or target, connector errors, credentials,
or write material. If
policy requires even these safe IDs and digests to be encrypted, this runtime
must remain unassembled: replacing the deterministic identity with randomized
ciphertext would invalidate its exact duplicate proof.

The routing converter and SDK client are created by one sealed factory. It
rejects every caller-supplied DataConverter, including typed nil values, plus
plugin/interceptor/external-storage/context-propagation options that could add
unreviewed History material. A custom converter can be reconsidered only after
a versioned converter-profile digest is bound to both the task queue and
Workflow identity; otherwise incompatible Workers could poll the same queue.
Neither the Starter nor Worker accepts a raw SDK client. Duplicate and newly
successful starts are ACK-safe only after an initial exact-run Describe, the
immutable first Started event, and a final exact-run Describe all match the
workflow/run/type, an allowed final status, both task-queue projections,
root/parent shape, and bounded canonical Memo and input payloads. This second
Describe narrows, but cannot eliminate, the final status-to-ACK race; dispatcher
quarantine remains mandatory for operator recovery. `TERMINATED`, `CANCELED`,
and `TIMED_OUT` are not ACK-safe; after an emergency stop, redelivery waits
until the authorized Reset run has completed. A same-ID Workflow with different
identity is retried as a conflict and is never treated as an ACK-safe duplicate.

Normal preparation Starter and Worker task identities are fixed to the
low-sensitivity value `aiops-investigation-preparation-v1`; the normal
real-History round-trip gate rejects PID/hostname identities. An authorized
Reset can additionally record the version-pinned server-internal
`history-service` identity, and a future operator client must use its own
versioned fixed low-sensitivity service identity. PID/hostname and personal
operator identities remain forbidden in History. These strings are audit and
shape evidence, not authentication. A later assembly must give the dispatcher,
preparation Worker, and operator client separate Temporal credentials and
namespace permissions, and must restrict `StartWorkflow` for this type to the
dispatcher. Package sealing cannot stop a raw Worker or starter that already
holds namespace poll or start credentials. Until those RBAC and credential
boundaries exist, the runtime remains unassembled and all claims remain closed.

## Durable preparation boundary

The Activity resolves the Signal by its global persistent primary key. Tenant
and Workspace supplied by Workflow History are comparisons, never database
selectors. Memory fixtures snapshot the trusted tenant at first Signal
registration; PostgreSQL reads Signal, Workspace, and Integration composite
scope in one trusted transaction.

Before correlation, the Activity derives a versioned JCS/SHA-256 snapshot fence
from every trusted Signal fact (Tenant and Workspace identity, Signal identity,
provider event, payload hash, fingerprint, status, labels, and observed time).
Memory checks the fence while
holding its repository lock; PostgreSQL re-locks the complete Signal projection
and compares it in the correlation transaction. A concurrent mutation therefore
fails without creating Incident or Investigation facts. The fence is not part
of Workflow input, receipts, Temporal History, audit, or Outbox payloads.

The Activity then attests that persisted scope, resolves the immutable Plan,
correlates the Signal, creates or reuses an Investigation with
`temporal.prepare.v1/<outbox-event-id>`, and re-reads the Incident,
Investigation, and position-ordered Tasks. Immutable parent/scope/spec/hash
drift fails closed. Normal status, timestamp, Evidence, failure, or model
progress made after the create response is allowed, so an Activity result loss
remains recoverable.

Preparation uses a disconnected Workflow context because the Outbox event may
already have been ACKed after a successful start. A normal cancellation request
therefore cannot interrupt the Correlate→Create durable fact boundary. The
Activity has a 30-second per-attempt timeout and indefinitely retryable bounded
backoff for dependency failures. Invalid input, identity/fact conflicts, plan
integrity failures, and invalid receipts are non-retryable. Operational
emergency stop uses Temporal Terminate; it is not modeled as ordinary Cancel.

All dependency panics and diagnostics are folded into fixed low-sensitivity
Temporal ApplicationErrors. Panic values, stack canaries, PostgreSQL messages,
Signal metadata, and Task documents must not enter History.

## Cancel, Terminate, and Reset runbook

These operations are intentionally not interchangeable:

- **Cancel** records an operator request, but does not stop the disconnected
  PREPARE Activity or its retry chain. The exact run remains `RUNNING` while
  the durable Correlate→Create boundary is unfinished. Do not use repeated
  Cancel requests as an emergency-stop mechanism.
- **Terminate** is the emergency stop. It must target both the exact Workflow
  ID and exact run ID and closes that Workflow run as `TERMINATED` immediately.
  It does not synchronously kill an already-running Activity or database call:
  at most the current idempotent attempt can still commit, while no later retry
  is scheduled after it returns. It does not execute Workflow cleanup and does
  not roll back facts already committed to PostgreSQL.
- **Reset** creates a new run for the same Workflow ID from a selected Workflow
  Task boundary. It also does not roll back PostgreSQL; correctness depends on
  the Activity's idempotent create/re-read/revalidate path. Reset is allowed
  only after the failing dependency is healthy and a compatible digest-bound
  Worker is polling.

The pinned Temporal CLI 1.6.1 / Server 1.30.1 contract test fixes the expected
reset lineage. The reset run has `Execution.RunId=<new-run>`,
`RootExecution={WorkflowId:<same-workflow>, RunId:<new-run>}` and
`FirstRunId=<original-terminated-run>`; it has no parent. An ACK-lost Outbox
redelivery after reset must describe this current reset run, verify the exact
Memo/type/queues/lineage, and return `AlreadyExists`.

Emergency procedure:

1. Stop new dispatcher delivery for the affected scope or Outbox event without
   deleting or ACKing pending records. Record only persistent IDs and digests;
   never put Signal data, connector errors, or credentials in the reason.
2. Describe the current run by Workflow ID, retain its exact run ID, and verify
   Workflow type, both task-queue projections, digest-bound Memo, and absence
   of a parent before acting.
3. Use only the controlled operator client with a fixed low-sensitivity service
   identity; never run the default Temporal CLI directly. Send Terminate to the
   exact Workflow/run pair with empty details and a reason containing only a
   fixed reason code plus a low-sensitivity audit reference. Put the personal
   operator identity only in the external immutable audit record. Re-describe
   the same run and require `TERMINATED`; do not accept a later/latest run as
   evidence.
4. Wait the full 30-second Activity StartToClose limit plus shutdown margin,
   then read the durable Incident/Investigation/Task facts twice at least five
   seconds apart and require the same projection in both checks before Reset.
   An official repository respects context cancellation, but this is not a
   transaction rollback or hard-kill guarantee. Repair the external dependency
   and keep the original digest Worker and immutable manifests available.
5. Select the first valid `WORKFLOW_TASK_COMPLETED` event before PREPARE was
   scheduled as the reset point. Reset the exact terminated run with a unique
   request ID. Verify the returned run ID differs from the terminated run and
   the lineage has the shape above.
6. Require the reset run to reach `COMPLETED` with a valid preparation receipt.
   Redeliver the same Outbox start once and require `AlreadyExists` before
   resuming dispatch. If reset cannot complete, leave dispatch quarantined and
   keep the compatible old Worker polling; never create a replacement Workflow
   ID for the same event.

Every Terminate and Reset is a security-relevant external operator action and
must be copied to the platform's immutable audit channel. M5C1B1 supplies the
runtime contract and test evidence only; it does not install an operator API.
Reset has the same controlled-client, fixed-service-identity, low-sensitivity
reason, and external personal-attribution requirements as Terminate.

Worker shutdown is terminal and serialized. `WorkerStopTimeout` is fixed at 35
seconds, longer than the Activity attempt timeout. Assembly must call Worker
`Stop`, then close the sealed Temporal client, and treat a non-nil result from
either operation as fatal before exiting. A nil `Stop` result means only that
the SDK shutdown call did not panic; it is not proof that an Activity which
ignores cancellation has stopped mutating durable state. Final isolation
requires process exit plus the future assembly's queue-drain and durable-fact
stability gates.

## Digest queue retention, drain, and alerts

Deploy a new manifest/registry digest Worker alongside the old Worker. Route
new starts to the new queue only after the new Worker is polling. A Worker for
an old digest pair may be drained only when all of the following hold for two
consecutive checks at least five minutes apart:

- no open preparation Workflow references the old task queue;
- Workflow and Activity backlog counts are zero and oldest-task age is zero;
- no old-queue preparation Activity is retrying; and
- every associated READ Task is terminal.

Stopping a poller is not artifact deletion. Retain the old Worker image,
manifest, registry, and verification record for at least the Temporal
visibility/history retention window so an authorized reset remains possible.
Never let a new digest Worker poll an old digest queue.

Use these conservative initial thresholds until production traffic provides a
measured baseline:

| Condition, per digest-bound queue | Warning | Page / block drain |
| --- | --- | --- |
| Pollers while open Workflows or backlog exist | — | zero for 60 seconds |
| Oldest Workflow/Activity task | 30 seconds for 2 minutes | 2 minutes for 2 minutes |
| Backlog count | 10 for 5 minutes | 100 for 5 minutes |
| Oldest open preparation Workflow | 15 minutes | 2 hours |
| Old digest after cutover | any open item after 24 hours | any item with zero compatible pollers for 60 seconds |
| Terminate or Reset operation | audit immediately | page if not linked to an approved incident/change |

Alert labels and dashboards may contain queue digests, Workflow/run IDs,
counts, ages, and fixed low-cardinality states only. They must not include
Workflow inputs/results, Signal labels, Activity errors, targets, or secrets.
The no-compatible-poller condition is fail-closed and must not be relaxed when
calibrating volume thresholds.

## Verification and rollout

Ordinary `go test ./...` compiles the dev-server test but skips it unless
`AIOPS_TEMPORAL_INTEGRATION=1`. CI has a separate mandatory job that downloads
Temporal CLI `1.6.1`, verifies the published Linux amd64 SHA-256, starts the
headless dev server, and proves start, duplicate-after-ACK-loss, completion,
complete-History canary scanning, four-hash presence, Workflow replay, ordinary
Cancel isolation, exact-run Terminate, one-at-most in-flight durable attempt,
and successful Reset recovery with an ACK-safe duplicate start. It also proves
that a raw valid-Memo/different-input start schedules no Activity, all ordinary
preparation History `identity` fields are empty or the fixed preparation
service value, and the canonical input and sole identity Memo remain exact
`json/plain` under the fixed default converter. Authorized Reset History has
the separately constrained `history-service`/controlled-operator identity
rules described above.

This PR has no migration, public HTTP API, environment configuration, or process
assembly change. Immutable READ target/egress admission, runtime binding, and
the fixed HTTP executor and M5C2-4a runtime Bundle now exist as unassembled contracts. M5C2-4b has
added the unassembled runtime v2 and runner-only Activity; M5C2-4c is the only milestone allowed to
atomically install the dispatcher, Worker, READ Runner and Gateway callbacks. Assembly still may not enable READ claims until all digest,
PKI, network, replay and local E2E gates pass. It may not enable WRITE claims or
add a `production` execution mode.
