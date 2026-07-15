# AWX Host Identity Enrollment v1

Status: confirmed implementation contract for migration `000019_host_postgresql_read_diagnostics` and Phase 5 packages 01, 02, 04, and 08.

This document is the single protocol/schema contract for AWX Host identity enrollment. It is not a public API and does not grant diagnostic execution. The public OpenAPI, browser, model, Investigation Task, and Runner claim surfaces expose only safe status, counts, stable reason codes, and content hashes.

## 1. Purpose and trust boundary

`AWX_INVENTORY` discovery establishes an AWX Host ID and an immutable Catalog Asset/Observation. It does not establish that a later AWX Job actually executed on the same machine. Enrollment closes that gap with a fixed signed module and a TPM-sealed、platform-attested local Ed25519 attestor whose measured process boundary is explicit TCB.

Enrollment is a controlled bootstrap read operation with its own durable authority, fencing, credential cleanup, receipts, and audit. It is not an Investigation, ActionProposal, ActionPlan, generic AWX launch, or source discovery run.

The exact order is:

1. Package 02 publishes an `APPLIED` bootstrap AWX Runtime containing only `AWX_INVENTORY_MAPPING`; no Host or template identity is required for Source creation.
2. AWX discovery produces immutable Assets and Observations.
3. A server-only release/bootstrap authority creates one enrollment Operation in `PENDING` with no Host Attempt yet.
4. The Operation performs one durable, GET-only two-template verification with its own short credential and cleanup, then persists the exact fingerprint bundle.
5. One serializable transaction reloads discovery facts and creates the complete immutable Host Attempt cohort while moving the Operation to `RUNNING`.
6. Each Attempt executes one Host against the fixed enrollment template, persists only a strict safe result, and proves credential cleanup.
7. After every Attempt is terminal, one serializable transaction revalidates the complete cohort and seals both fingerprint/identity artifacts, a `PENDING` Runtime successor, Audit, and Outbox.
8. Distributor and attestor run outside that transaction. A later CAS may move the Runtime to `APPLIED`.
9. Only an exact `APPLIED` identity Runtime may be consumed by the diagnostic contract Publisher. The resulting Host capability remains `PENDING` until package 08 E2E.

No transaction performs remote AWX, distributor, or attestor network I/O.

## 2. Fingerprint bundle

The two template fingerprints remain bundled in the single `AWX_READ_TEMPLATE_FINGERPRINT` artifact kind；no second per-template fingerprint kind is introduced. `AWX_ENROLLMENT_AUTHORITY_KEYRING` is the separate fourth AWX Runtime artifact kind and is never nested in this bundle. The strict RFC 8785 envelope is `awx-read-template-fingerprint-bundle.v1` with exactly these keys:

```text
diagnostic_fingerprint_digest
diagnostic_manifest
diagnostic_manifest_sha256
enrollment_fingerprint_digest
enrollment_manifest
enrollment_manifest_sha256
schema
```

Both nested manifests are strict objects, not encoded JSON strings. Unknown/duplicate keys, noncanonical bytes, a missing branch, digest mismatch, or a manifest larger than 65,536 bytes rejects publication. The verified bundle SHA-256 is bound into the sealed successor Runtime manifest, Bundle, attestation, and provider artifact-set digest; the bootstrap mapping Runtime intentionally has no fingerprint artifact.

Each manifest fixes the full AWX 24.6.1 execution surface: organization/inventory/template/project IDs; project SCM revision; signed playbook/module hashes; execution environment and image digest; exact credential-set and ordered instance-group-set digests; survey bytes/hash; stored `extra_vars={}` and empty stored `limit`; job settings; labels and fallback settings; and all sixteen prompt fields:

```text
ask_scm_branch
ask_diff_mode
ask_variables
ask_limit
ask_tags
ask_skip_tags
ask_job_type
ask_verbosity
ask_inventory
ask_credential
ask_execution_environment
ask_labels
ask_forks
ask_job_slice_count
ask_timeout
ask_instance_groups
```

Only `ask_limit=true`; the other fifteen are false. `survey_enabled=true`, `allow_simultaneous=false`, `become_enabled=false`, `prevent_instance_group_fallback=true`, and all stored defaults are exact. The enrollment and diagnostic templates have distinct IDs, signed modules, surveys, fingerprint domains, credentials/RBAC, and result schemas. A digest from one purpose cannot satisfy the other.

The enrollment survey contains exactly four required non-password/no-default variables:

```text
attestation_nonce                 lowercase 64-hex
enrollment_context_digest        lowercase 64-hex
enrollment_schema_version        constant awx-host-identity-enrollment.v1
expected_host_id                 JCS-safe integer 1..9007199254740991
```

The governed manifest must show only those required variables and the exact fingerprinted defaults. The outer governed POST has the exact nine keys defined by `awx-governed-launch-admission-v1`; within that request, the only AWX prompt overrides are `limit` and `extra_vars`. `limit` is one server-resolved safe token and `extra_vars` has exactly the four keys above；stock preview/launch is not an authorized path. The created Job snapshot and admission receipt must re-equal the locked template/project/SCM/execution-environment/credential/instance-group/inventory/limit/merged-extra-vars closure.

The enrollment execution account has only use/execute on the exact enrollment template, inventory, project artifact, execution environment, and managed-host credential. Its short AWX OAuth token may require scope `write`, but real negative tests deny CRUD, ad-hoc commands, other templates, inventory mutation, project update, credential mutation, and diagnostic-template execution. AWX users are distinct across template verification, enrollment execution, discovery, diagnostic execution, WRITE, and Vault purposes. Within one AWX personal-token profile, issuance and revocation are self-service operations by that same AWX user; the trusted issuer/revoker components and credential sources remain locally distinct, but the contract never misrepresents them as distinct AWX audit actors.

Each normalized nested manifest has exactly these keys; booleans are JSON booleans, IDs are JCS-safe positive integers, digests are lowercase 64-hex, strings are UTF-8 with the stated fixed/bounded values, and arrays are exact ordered sets:

```text
allow_simultaneous
ask_credential
ask_diff_mode
ask_execution_environment
ask_forks
ask_instance_groups
ask_inventory
ask_job_slice_count
ask_job_type
ask_labels
ask_limit
ask_scm_branch
ask_skip_tags
ask_tags
ask_timeout
ask_variables
ask_verbosity
become_enabled
credential_set_digest
custom_virtualenv
diff_mode
execution_environment_id
execution_environment_image_digest
force_handlers
forks
host_config_key_present
instance_group_set_digest
inventory_id
job_slice_count
job_tags
job_template_id
job_type
labels
organization_id
playbook_code
prevent_instance_group_fallback
project_clean
project_delete_on_update
project_id
project_scm_revision_sha256
project_update_on_launch
scm_branch
signed_module_sha256
signed_playbook_artifact_sha256
skip_tags
start_at_task
stored_extra_vars_sha256
stored_limit
survey_enabled
survey_spec
survey_spec_sha256
timeout_seconds
use_fact_cache
verbosity
version
webhook_credential_present
webhook_service
```

`version` is respectively `awx-host-identity-enrollment-template-manifest.v1` or `awx-host-diagnostic-template-manifest.v1`; `stored_extra_vars_sha256` is SHA-256 of exact `{}` bytes and `stored_limit=""`. `job_type="run"`, `scm_branch=""`, `forks=1`, `verbosity=0`, `diff_mode=false`, `force_handlers=false`, `skip_tags=""`, `start_at_task=""`, `timeout_seconds=1..120`, `use_fact_cache=false`, `job_slice_count=1`, `labels=[]`, `custom_virtualenv=""`, `webhook_service=""`, `webhook_credential_present=false`, `host_config_key_present=false`, `project_clean=true`, `project_delete_on_update=false`, `project_update_on_launch=false`, `allow_simultaneous=false`, `become_enabled=false`, `prevent_instance_group_fallback=true`, `survey_enabled=true`; `ask_limit=true` and every other named prompt flag false. `playbook_code` is one of `AWX_HOST_IDENTITY_ENROLLMENT_V1|AWX_HOST_DIAGNOSTIC_V1`. The diagnostic survey makes the eight common variables required and its branch-only variables optional/no-default; the server and signed module independently enforce the selected closed branch. No survey variable outside the 2,446-byte fixture is permitted.

`credential_set_digest` is SHA-256 of RFC 8785 `{"items":[...],"version":"awx-template-credential-set.v1"}`. It has 1..8 items sorted by numeric `credential_id`; each exact object has `credential_id,credential_type_id,credential_type_kind,credential_type_namespace,modified_at_utc,organization_id`. IDs are safe positive integers, organization is the exact template organization, modified time is UTC microsecond, kind/namespace are release-allowlisted, and no secret/input value is fetched or hashed. Enrollment and diagnostic sets are disjoint and each equals the signed release manifest.

`instance_group_set_digest` is SHA-256 of RFC 8785 `{"items":[...],"version":"awx-template-instance-group-set.v1"}`. Items are sorted by numeric `instance_group_id` and have exactly `credential_id,instance_group_id,is_container_group,policy_instance_list_digest,policy_instance_minimum,policy_instance_percentage`; nullable credential uses JSON null, policy instance list digest is over sorted private instance IDs, integers are bounded, and at least one exact release-approved group is required. Any association/object/modified membership drift changes the set digest; fallback remains disabled.

The trusted private `awx-template-release-manifest.v1` is shipped content-addressed in the Control Plane and governed AWX image, signed by the release key used by the authority keyring artifact, and binds AWX `24.6.1`, both normalized manifest hashes, project ID/SCM revision, signed playbook/module hashes and paths, digest-pinned execution-environment image, both credential/instance-group set digests, survey hashes, governed-launch-admission build digest, SBOM digest, and signing provenance. Remote project revision must equal it; playbook/module bytes are trusted only through the independently built signed SCM artifact, never inferred from a mutable AWX name. The verifier loads this exact release manifest by expected hash before network I/O and rejects missing/duplicate/signature/SBOM/provenance drift.

The normalized enrollment survey has exact object keys `description,name,spec` and four `spec` entries in the variable order shown above. Every entry has exactly `choices,default,max,min,new_question,question_description,question_name,required,type,variable`; defaults/choices/descriptions are empty, `new_question|required=true`, nonce/context are `text` with min=max=64, schema version is `text` with min=1/max=64, and Host ID is `integer` with min=1/max=9007199254740991. Its exact 869-byte RFC 8785 fixture is `{"description":"","name":"AWX Host Identity Enrollment v1","spec":[{"choices":"","default":"","max":64,"min":64,"new_question":true,"question_description":"","question_name":"Attestation nonce","required":true,"type":"text","variable":"attestation_nonce"},{"choices":"","default":"","max":64,"min":64,"new_question":true,"question_description":"","question_name":"Enrollment context digest","required":true,"type":"text","variable":"enrollment_context_digest"},{"choices":"","default":"","max":64,"min":1,"new_question":true,"question_description":"","question_name":"Enrollment schema version","required":true,"type":"text","variable":"enrollment_schema_version"},{"choices":"","default":"","max":9007199254740991,"min":1,"new_question":true,"question_description":"","question_name":"Expected Host ID","required":true,"type":"integer","variable":"expected_host_id"}]}` with SHA-256 `b8c42b973a3d296bf9957de76535d3824568af2a3d0ccad5b1b572eb181e49ea`. Tests keep these bytes/length/SHA as one golden in `internal/awxhostidentity`; migration and remote normalized projection byte-compare that golden rather than trusting AWX field omission/defaulting.

For either branch:

```text
manifest_sha256 = SHA256(RFC8785(normalized manifest))
fingerprint_digest = SHA256(FramedTupleV1(
  branch fingerprint domain,
  minimal-decimal inventory_id,
  minimal-decimal job_template_id,
  minimal-decimal project_id,
  raw project_scm_revision_sha256,
  raw signed_playbook_artifact_sha256,
  raw signed_module_sha256,
  minimal-decimal execution_environment_id,
  raw execution_environment_image_digest,
  raw credential_set_digest,
  raw instance_group_set_digest,
  raw survey_spec_sha256,
  raw stored_extra_vars_sha256,
  raw manifest_sha256
))
```

The branch domains are `awx-host-identity-enrollment-template-fingerprint.v1` and `awx-host-diagnostic-template-fingerprint.v1`. The bundle's exact bytes are at most 65,536 bytes and:

```text
bundle_sha256 = SHA256(RFC8785(bundle))
bundle_root_digest = SHA256(FramedTupleV1(
  "awx-read-template-fingerprint-bundle.v1",
  raw enrollment_manifest_sha256,
  raw enrollment_fingerprint_digest,
  raw diagnostic_manifest_sha256,
  raw diagnostic_fingerprint_digest,
  raw bundle_sha256
))
```

## 3. Durable database facts

Migration `000019` owns two additional tables, bringing its exact owned-table set to eight.

### `awx_host_identity_enrollments`

One row is the durable root and immutable request closure. Exact columns are:

```text
tenant_id uuid
workspace_id uuid
environment_id uuid
id uuid
source_id uuid
source_revision bigint
connection_id uuid
connection_revision bigint
integration_id uuid
bootstrap_runtime_publication_id uuid
mapping_artifact_sha256 text
enrollment_template_reference_digest text
diagnostic_template_reference_digest text
expected_enrollment_manifest_sha256 text
expected_diagnostic_manifest_sha256 text
template_verification_request_sha256 text null
template_verification_started_at timestamptz null
template_claim_owner text null
template_claim_epoch bigint
template_claim_token_sha256 text null
template_claim_expires_at timestamptz null
template_heartbeat_sequence bigint
template_credential_attempt_id uuid null
template_credential_attempt_epoch bigint
template_cleanup_state text
template_cleanup_digest text null
template_cleanup_proof bytea null
template_cleanup_proof_key_id text null
template_cleanup_proof_signature_sha256 text null
template_fingerprint_bundle bytea null
template_fingerprint_artifact_sha256 text null
enrollment_fingerprint_digest text null
diagnostic_fingerprint_digest text null
enrollment_module_sha256 text
realm_digest text
network_policy_digest text
trust_closure_digest text
credential_profile_digest text
authority_key_id text
authority_subject text
authority_keyring_runtime_publication_id uuid
authority_keyring_artifact_sha256 text
authority_keyring_manifest_digest text
authority_keyring_revision bigint
authority_key_spki_sha256 text
authority_digest text
authority_statement bytea
authority_signature bytea
authority_signature_sha256 text
authority_nonce_sha256 text
authority_issued_at timestamptz
authority_expires_at timestamptz
capacity_profile_digest text
effective_cohort_limit integer
execution_deadline_at timestamptz
cohort_digest text null
cohort_size integer null
idempotency_key text
request_sha256 text
status text
version bigint
identity_artifact_sha256 text null
identity_artifact_root_digest text null
pending_runtime_publication_id uuid null
enrolled_count integer
unavailable_count integer
failure_code text null
created_at timestamptz
updated_at timestamptz
completed_at timestamptz null
```

After verification `cohort_size` is `1..10000`; before it, both cohort fields are NULL and no Attempt may exist. The authority expiry must be in the future at creation and at most 15 minutes after its signed issuance. IDs, expected template/module release digests, purpose `AWX_HOST_IDENTITY_ENROLLMENT_V1`, signer key, expiry, and one-use 32-byte nonce are verified before insertion; only safe key/digests/times are stored. Unique constraints cover Scope+ID, Scope+idempotency key, Scope+request hash, and `(tenant_id,workspace_id,environment_id,authority_key_id,authority_nonce_sha256)` so one signed nonce cannot create two Operations. A partial unique index permits one nonterminal Operation per Source.

The closed state graph is:

```text
PENDING -> VERIFYING_TEMPLATES -> RUNNING -> FINALIZING -> SEALED
RUNNING|FINALIZING -> ABORTING -> FAILED|MANUAL_REQUIRED
PENDING|VERIFYING_TEMPLATES|RUNNING|FINALIZING -> FAILED
VERIFYING_TEMPLATES|RUNNING|FINALIZING|ABORTING -> MANUAL_REQUIRED
```

`ClaimTemplateVerification` atomically performs `PENDING→VERIFYING_TEMPLATES`, sets a random 256-bit token only as SHA-256, increments `template_claim_epoch`, fixes a 30-second expiry, and starts `template_heartbeat_sequence=1`; only the exact owner/epoch/token may reserve a credential, heartbeat every ≤10 seconds, perform GET, persist bundle, or attach cleanup proof. Before `template_credential_attempt_id` exists, an expired claim may be fenced and reclaimed with a new epoch. Once that opaque ID exists, every new claimant is cleanup-only: it may call `Revoke/GetReceipt`, verify and persist the same signed proof, but may never call `IssueOnce` or any AWX GET/work endpoint. A live claimant may retry a lost GET response at most twice within the same claim, same in-memory single-delivery handle, and a 20-second total network budget. Process loss destroys that handle; after clean revoke the Operation becomes `FAILED/HOST_IDENTITY_TEMPLATE_VERIFY_INTERRUPTED` unless bundle bytes were already durably stored, in which case a cleanup-only recovery may continue from those bytes. Issue/delete ambiguity becomes `MANUAL_REQUIRED`.

Template verification commits its request marker before any GET, stores strict bundle bytes and the prospective fingerprint artifact SHA before cleanup, and may enter `RUNNING` only after a broker proof envelope has been fetched outside the transaction, verified against the pinned receipt key, and persisted in the root as exact bytes/digest/key/signature hash with `REVOKED|NO_CREDENTIAL`. The immutable artifact row itself is created only by the final seal transaction. `RUNNING` clears every template claim field and fixes the clean proof and bundle fields forever. `SEALED|FAILED|MANUAL_REQUIRED` are terminal and immutable. `SEALED` means both artifacts and a `PENDING` Runtime successor were committed atomically; it never means the Runtime is `APPLIED` or the capability is available.

Root shape is exact: `PENDING` has its immutable Operation request but no claim/template-verification request/credential/bundle/proof/cohort; `VERIFYING_TEMPLATES` has a live claim or cleanup-only expired claim and no Attempt cohort; `RUNNING` has the exact bundle, clean persisted proof, cohort `1..effective_cohort_limit<=10000`, no claim, and finalization-only counters still zero even when cohort construction already marked an unsafe-token child terminal; `FINALIZING` materializes counters only after every child is terminal/clean; `ABORTING` forbids new slot/credential/launch and cleanup-converges every child; `SEALED` has non-NULL artifact/root/`PENDING` Runtime IDs and exact final counts; `FAILED|MANUAL_REQUIRED` has one closed failure code, completion time, no live claim, and can never acquire new credential/network authority. Root failure codes are exactly `HOST_IDENTITY_TEMPLATE_CREDENTIAL_UNCERTAIN|HOST_IDENTITY_TEMPLATE_VERIFY_INTERRUPTED|HOST_IDENTITY_TEMPLATE_DRIFT|HOST_IDENTITY_COHORT_EMPTY|HOST_IDENTITY_COHORT_CAPACITY_EXCEEDED|HOST_IDENTITY_EXECUTION_DEADLINE_EXCEEDED|HOST_IDENTITY_ALL_HOSTS_UNAVAILABLE|HOST_IDENTITY_INPUT_DRIFT|HOST_IDENTITY_SEAL_REJECTED|HOST_IDENTITY_CLEANUP_MANUAL_REQUIRED`.

The release verifier accepts an exact Ed25519 key from the production bootstrap keyring and verifies the signature over these framed bytes:

```text
FramedTupleV1(
  "awx-host-identity-enrollment-authority.v1",
  authority_key_id,
  "governed-release-bootstrap",
  authority_keyring_runtime_publication_id,
  raw authority_keyring_artifact_sha256,
  raw authority_keyring_manifest_digest,
  minimal-decimal authority_keyring_revision,
  raw authority_key_spki_sha256,
  T, W, E,
  source_id,
  minimal-decimal source_revision,
  connection_id,
  minimal-decimal connection_revision,
  integration_id,
  bootstrap_runtime_publication_id,
  raw mapping_artifact_sha256,
  raw enrollment_template_reference_digest,
  raw diagnostic_template_reference_digest,
  raw expected_enrollment_manifest_sha256,
  raw expected_diagnostic_manifest_sha256,
  raw enrollment_module_sha256,
  raw realm_digest,
  raw network_policy_digest,
  raw trust_closure_digest,
  raw credential_profile_digest,
  raw capacity_profile_digest,
  minimal-decimal effective_cohort_limit,
  UTC-microsecond execution_deadline_at,
  UTC-microsecond authority_issued_at,
  UTC-microsecond authority_expires_at,
  raw 32-byte authority_nonce
)
```

`authority_subject="governed-release-bootstrap"`; `authority_digest` is SHA-256 of those exact framed bytes, `authority_nonce_sha256=SHA256(raw authority_nonce)`, and `authority_signature_sha256=SHA256(raw 64-byte signature)`. The exact framed statement and signature are safe private control facts and are persisted byte-for-byte in the root; the raw nonce is destroyed after framing. The key registry is not an untracked file: a server-only release process publishes strict `awx-enrollment-authority-keyring.v1` as artifact kind `AWX_ENROLLMENT_AUTHORITY_KEYRING` in an independently attested `AWX_ENROLLMENT_AUTHORITY` Runtime. It contains revision, active/retired key IDs, Ed25519 SPKI bytes/hashes, validity/revocation times, signer/SBOM digests and retention policy. Creation and every claim/finalization lock the exact APPLIED keyring Runtime/artifact in the database, require it remains the active successor, compare all bound fields, and verify the stored authority statement/signature. Publishing a revocation successor atomically closes dependent nonterminal Operations before changing the active pointer; historical artifact/key bytes remain until every referenced Operation/artifact/audit record passes retention. Replay uniqueness is enforced before any remote request.

```text
operation request_sha256 = SHA256(FramedTupleV1(
  "awx-host-identity-enrollment-operation-request.v1",
  T, W, E,
  operation_id,
  raw authority_digest,
  source_id,
  minimal-decimal source_revision,
  connection_id,
  minimal-decimal connection_revision,
  integration_id,
  bootstrap_runtime_publication_id,
  raw mapping_artifact_sha256,
  raw enrollment_template_reference_digest,
  raw diagnostic_template_reference_digest,
  raw expected_enrollment_manifest_sha256,
  raw expected_diagnostic_manifest_sha256,
  raw enrollment_module_sha256,
  raw realm_digest,
  raw network_policy_digest,
  raw trust_closure_digest,
  raw credential_profile_digest,
  raw capacity_profile_digest,
  minimal-decimal effective_cohort_limit,
  UTC-microsecond execution_deadline_at,
  idempotency_key
))
```

`template_verification_request_sha256` uses domain `awx-host-identity-template-verification-request.v1` and frames raw Operation request hash, both template-reference/expected-manifest digests, bootstrap Runtime ID, raw mapping hash, raw credential-profile digest, and the broker-owned template credential-attempt UUID. All fields are write-once. Tests use fixed golden UUID/time/nonce/signature fixtures and compare exact bytes/hashes in Go and PostgreSQL.

### `awx_host_identity_enrollment_attempts`

There is exactly one row per Operation cohort Host and at most one remote Job per Attempt. `SUCCEEDED` requires exactly one; `FAILED|MANUAL_REQUIRED` may have zero or one according to the durable launch boundary. Exact columns are:

```text
tenant_id uuid
workspace_id uuid
environment_id uuid
operation_id uuid
asset_id uuid
source_id uuid
source_revision bigint
latest_observation_content_sha256 text
host_id bigint
limit_token text null
limit_token_source_sha256 text
ordinal integer
enrollment_context_digest text null
request_sha256 text
status text
version bigint
lease_owner text null
lease_epoch bigint
lease_token_sha256 text null
lease_expires_at timestamptz null
heartbeat_sequence bigint
template_slot_digest text
remote_not_before timestamptz null
remote_request_sequence bigint
last_remote_request_at timestamptz null
attempt_deadline_at timestamptz
credential_attempt_id uuid null
credential_attempt_epoch bigint
cleanup_state text
cleanup_digest text null
cleanup_proof bytea null
cleanup_proof_key_id text null
cleanup_proof_signature_sha256 text null
launch_started_at timestamptz null
attestation_nonce text null
launch_request_sha256 text null
launch_admission_receipt_digest text null
job_id bigint null
job_terminal_at timestamptz null
job_snapshot_digest text null
job_host_summary_digest text null
enrollment_output bytea null
enrollment_output_sha256 text null
enrollment_fact bytea null
enrollment_fact_sha256 text null
identity_key_sha256 text null
identity_attestation_digest text null
host_binding_digest text null
outcome text null
failure_code text null
created_at timestamptz
updated_at timestamptz
completed_at timestamptz null
```

The primary key is Scope+Operation+Asset; unique keys additionally enforce Operation+ordinal, Operation+Host ID, and non-NULL Operation+limit token. Ordinals are contiguous `1..cohort_size` in Asset UUID `C` order. `limit_token_source_sha256=SHA256(UTF-8 latest Observation display_name)`。A non-NULL `limit_token` is that byte-exact value and must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`, must not case-fold to `all|ungrouped|localhost`, and contains no whitespace, comma, colon, slash, backslash, quote, shell/Ansible pattern or set/operator character. An unsafe name produces a no-network terminal `FAILED` Attempt with NULL token/context, outcome `UNAVAILABLE`, stable `HOST_IDENTITY_LIMIT_TOKEN_UNSAFE`, cleanup `NO_CREDENTIAL`, no broker proof, and is counted in `unavailable_count`; there is no normalization, fallback alias, group, or pattern expansion.

After `enrollment_context_digest` is computed as specified below:

```text
Attempt request_sha256 = SHA256(FramedTupleV1(
  "awx-host-identity-enrollment-attempt-request.v1",
  T, W, E,
  raw Operation request_sha256,
  operation_id,
  asset_id,
  source_id,
  minimal-decimal source_revision,
  raw latest_observation_content_sha256,
  minimal-decimal host_id,
  raw limit_token_source_sha256,
  limit_token-or-NULL,
  minimal-decimal ordinal,
  raw enrollment_context_digest-or-NULL
))

cohort_digest = SHA256(FramedTupleV1(
  "awx-host-identity-cohort.v1",
  minimal-decimal cohort_size,
  raw Attempt request_sha256 for ordinal 1,
  ...,
  raw Attempt request_sha256 for ordinal cohort_size
))
```

The fingerprint-verification→`RUNNING` transaction inserts all Attempts and the parent cohort fields together. Deferred triggers on both parent and child reject missing, late, duplicate, reordered, cross-Scope, request/context, or digest drift. Once RUNNING, cohort/Attempt identity/input rows are immutable.

Attempt status is:

```text
QUEUED -> LEASED
LEASED -> QUEUED | SLOT_RESERVED | CLEANING_UP | FAILED
SLOT_RESERVED -> LAUNCHING | CLEANING_UP | FAILED
LAUNCHING -> COLLECTING | CLEANING_UP | UNCERTAIN
COLLECTING -> CLEANING_UP | UNCERTAIN
UNCERTAIN -> CLEANING_UP
CLEANING_UP -> SUCCEEDED | FAILED | MANUAL_REQUIRED
```

Only the dedicated enrollment worker and Realm can claim `QUEUED` rows or cleanup-only expired rows. It uses `FOR UPDATE SKIP LOCKED`, a random 256-bit fence token stored only as SHA-256, monotonic lease epoch/heartbeat, and exact request hash. `LEASED` expiry with `credential_attempt_id IS NULL`, no launch marker, and cleanup `NOT_OPENED` increments the epoch and may return to `QUEUED`; once a credential attempt exists, reclaim is cleanup-only and can never call AWX work endpoints. Expired `SLOT_RESERVED|LAUNCHING|COLLECTING|UNCERTAIN|CLEANING_UP` rows are cleanup-only. Partial indexes separately cover new-work claims and cleanup claims; neither includes terminal rows. Discovery, Investigation, Action, and generic Runner workers ignore these rows with zero mutation/network side effects.

`template_slot_digest=SHA256(FramedTupleV1("awx-host-identity-template-slot.v1",awx_origin_digest,minimal-decimal enrollment_template_id))`. A partial unique index over this digest for `SLOT_RESERVED|LAUNCHING|COLLECTING|UNCERTAIN|CLEANING_UP` with `job_terminal_at IS NULL` is the durable cross-Operation semaphore; because `allow_simultaneous=false`, at most one not-yet-terminal enrollment Job exists per origin/template. A worker must win `SLOT_RESERVED` before reserving/issuing a PAT. The slot remains held from pre-issue through trusted Job terminal observation; response loss or unknown/stuck Job keeps the slot closed for reconciliation/manual containment. Cleanup after a proven terminal Job may continue without the slot. Recovery never treats lease expiry as Job termination.

Every remote AWX call first takes a transaction-scoped advisory lock derived from the full slot digest, scans all retained Attempts with that digest, and advances `remote_request_sequence/last_remote_request_at` by CAS. A fixed capacity profile sets minimum request spacing, 429 backoff `1s,5s,30s,2m` and jitter domain; 429 persists `remote_not_before` before releasing the worker, never busy-retries, and the global claim query honors the maximum not-before across that slot. `attempt_deadline_at` is write-once and no later than the Operation deadline; Job template timeout and polling deadline are each ≤120 seconds. The PAT is issued only after slot and rate admission, so queue wait never consumes its ≤5-minute lifetime.

`capacity_profile_digest` identifies a signed immutable profile containing exact `max_cohort_size<=10000`, request spacing, p99 enrollment duration, Attempt timeout, root execution budget, AWX 429 policy and benchmark artifact digest. `effective_cohort_limit=min(10000,profile max,floor(root budget / verified p99 safety bound))`; authority signs the profile and chosen limit, and `execution_deadline_at` is at most 72 hours after creation. A deadline/revocation/supersede sweeper atomically moves the root to `ABORTING`, fails unlaunched rows without credential/network, invokes only the governed cancel/reconcile path for the single known Job, and cleans every credential. It reaches `FAILED` only when every child is terminal clean; unknown Job/cleanup reaches `MANUAL_REQUIRED` and keeps admission/slot contained. Production acceptance of a 10,000 cohort requires a real benchmark proving completion inside the signed budget; otherwise the effective limit is lower even though the schema cap remains 10,000.

Before any credential/session issue, the worker commits a broker-owned opaque `credential_attempt_id`; issuance response loss is cleanup-only and never opens AWX work. The fixed enrollment CleanupBroker profile may issue only a nonrenewed short AWX personal token for the exact enrollment template account. Secret/token values and remote token accessors never enter these tables, Operation payloads, Tasks, logs, or Audit. After cleanup, the worker fetches the recoverable signed proof outside its database transaction, verifies the exact binding/key/signature, then one CAS persists the proof envelope bytes, digest, key ID, and signature hash. Finalization trusts only that database fact and re-verifies it without broker/network I/O. Only `REVOKED|NO_CREDENTIAL` is clean.

Before launch, one CAS writes `LAUNCHING + launch_started_at + fresh attestation_nonce + launch_request_sha256`; all four are write-once and the request digest covers the exact fingerprinted template ID, one-token limit, four-key extra-vars bytes, raw Attempt request hash and fence epoch. Launch never calls stock AWX `JobTemplateLaunch`; it uses only `docs/contracts/awx-governed-launch-admission-v1.md`, whose AWX-side transaction blocks relevant mutation tables, revalidates template/project/EE/credential/instance-group/inventory/Host/limit closure, proves exactly one Host and no same-name group, creates the immutable Job snapshot, commits an admission receipt, and signals only after commit. Any mismatch/race returns no Job. A crash after the local marker but before a trusted admission receipt/Job ID is persisted becomes `UNCERTAIN→CLEANING_UP→MANUAL_REQUIRED`; the worker revokes the credential and never launches again. Receipt digest and safe Job ID are write-once and permit bounded collection. Any safe result or deterministic failure is persisted before `CLEANING_UP`; cleanup uncertainty always ends `MANUAL_REQUIRED`. Governed cancellation or Job deletion is not credential cleanup.

The worker stores only the strict safe enrollment output/fact. It never stores stdout, arbitrary event data, provider error body, Host facts, paths, endpoints, variables, credentials, or raw logs. Attempt `outcome` is exactly `ENROLLED|UNAVAILABLE`; failure codes are exactly `HOST_IDENTITY_LIMIT_TOKEN_UNSAFE|HOST_IDENTITY_INPUT_DRIFT|HOST_IDENTITY_CREDENTIAL_UNCERTAIN|HOST_IDENTITY_LAUNCH_UNCERTAIN|HOST_IDENTITY_TEMPLATE_DRIFT|HOST_IDENTITY_JOB_FAILED|HOST_IDENTITY_JOB_STUCK|HOST_IDENTITY_JOB_RESULT_INVALID|HOST_IDENTITY_ATTESTATION_INVALID|HOST_IDENTITY_OPERATION_ABORTED|HOST_IDENTITY_CLEANUP_UNCERTAIN`.

Terminal shape is exact. `SUCCEEDED` requires outcome `ENROLLED`, NULL failure, one Job ID/snapshot/summary, output/fact/key/attestation/binding digests, broker-backed cleanup `REVOKED`, persisted signed proof, no live lease, and completion time. Clean deterministic `FAILED` requires outcome `UNAVAILABLE`, one failure code, no accepted binding, no live lease, and either (a) no credential/Job plus database-derived `NO_CREDENTIAL` and no broker proof, or (b) a broker attempt with persisted `REVOKED|NO_CREDENTIAL` proof; any partial Job/result field forbidden by its failure stage remains NULL. `MANUAL_REQUIRED` requires outcome `UNAVAILABLE`, one uncertainty code, persisted non-clean proof/state, no live lease, and can never be sealed. No terminal row may retain `ISSUED|CLEANUP_PENDING|UNCERTAIN`, and no nonterminal row may claim a final outcome. Each terminal transition writes one append-only Audit/Outbox receipt.

### Enrollment CleanupBroker durability

Enrollment never uses Investigation `read_credential_leases`. Production injects an HA `EnrollmentCleanupBroker` with the only allowed interface:

```go
type EnrollmentCleanupBroker interface {
    Reserve(context.Context, EnrollmentCredentialBinding) (OpaqueAttemptID, error)
    IssueOnce(context.Context, OpaqueAttemptID, EnrollmentIssueRequest) (NonSerializableSecretHandle, error)
    Revoke(context.Context, OpaqueAttemptID) (SignedCleanupProof, error)
    GetReceipt(context.Context, OpaqueAttemptID) (SignedCleanupProof, error)
}
```

The binding is the exact Scope、Operation/nullable Host Attempt、fence epoch、purpose `AWX_HOST_IDENTITY_TEMPLATE_VERIFY|AWX_HOST_IDENTITY_ENROLLMENT`、template/credential-profile/fingerprint/request digests and expiry. The broker persists its own request marker, issue correlation, encrypted AWX token-ID accessor, issuer/revoker revisions, accessor HMAC, state/version, cleanup attempts and signed receipt before/after each remote boundary. `Reserve` is exact-idempotent; `IssueOnce` can deliver a secret handle only once and any lost response becomes cleanup-only; `Revoke` and `GetReceipt` are exact-idempotent and always recover the same terminal proof bytes. The Control Plane stores the opaque attempt ID plus the complete safe immutable proof envelope/digest/key/signature hash; only Secret/control credential/accessor material remains broker-only.

The exact broker wire protocol is mTLS HTTP/2 with no redirect/proxy/cookie/compression and only these routes: `POST /v1/enrollment-credential-attempts` for Reserve, `POST /v1/enrollment-credential-attempts/{uuid}:issue`, `POST /v1/enrollment-credential-attempts/{uuid}:revoke`, and `GET /v1/enrollment-credential-attempts/{uuid}/receipt`. JSON requests are RFC 8785, `additionalProperties:false`, ≤4 KiB, and use exact keys: Reserve `binding_digest,expires_at,host_attempt_asset_id,idempotency_key,operation_id,purpose,request_sha256,scope,worker_fence_epoch`; issue/revoke `binding_digest,expected_version,request_sha256`; safe responses `attempt_id,state,version` plus the terminal proof where applicable. `host_attempt_asset_id` is JSON null for template verification. Issue success alone uses ≤8 KiB `application/vnd.aiops.single-secret.v1` sealed bytes consumed directly into a non-copyable handle; it is never JSON, retrievable, logged, or retried. Only workload identities `spiffe://aiops/control-plane/enrollment-coordinator` and `spiffe://aiops/control-plane/enrollment-worker` may call their purpose-bound routes. Deadlines are 5 seconds, UUID/path/version/fence/Scope/binding are rechecked server-side, and stable errors are exactly `BINDING_MISMATCH|FENCE_STALE|STATE_CONFLICT|SECRET_ALREADY_DELIVERED|UPSTREAM_UNCERTAIN|CLEANUP_MANUAL_REQUIRED|DEPENDENCY_UNAVAILABLE`. There is no public/internal caller list/search/prefix/general-HTTP route.

The strict RFC 8785 proof envelope has exactly `key_id,payload,payload_sha256,signature,version`; version is `awx-enrollment-cleanup-proof-envelope.v1`. Payload has exactly `attempt_id,binding_digest,cleanup_state,completed_at,credential_attempt_epoch,host_attempt_asset_id,issuer_revision_digest,operation_id,purpose,request_sha256,revoker_revision_digest,scope,token_accessor_hmac,version`, with nullable Host encoded as JSON null and payload version `awx-enrollment-cleanup-proof.v1`. `cleanup_state` is `REVOKED|NO_CREDENTIAL|UNCERTAIN|MANUAL_REQUIRED`. `payload_sha256=SHA256(RFC8785(payload))`; the dedicated Ed25519 receipt key signs `FramedTupleV1("awx-enrollment-cleanup-proof-signature.v1",key_id,raw payload_sha256)`. Envelope SHA-256 is the database `cleanup_digest`; `signature` is lowercase 128-hex and the database stores its decoded-byte SHA-256. Verification keys are purpose-scoped and retained until every referenced row/artifact expires.

Accessor encryption, accessor HMAC, and receipt signing use three distinct Vault Transit keys and key IDs; transport certificates and AWX control credentials are separate again. Old decrypt/HMAC/signing verification versions remain available through audited rotation until all records using them are terminal and past retention. The broker store is a dedicated Vault 2.0.3 TLS Raft cluster/KV v2 mount. Before acknowledging any issue marker it first creates a durable internal recovery-bucket membership, then CAS-writes the attempt marker; two active broker replicas claim by KV version plus random fence. The internal sweeper alone may scan its private recovery index and revokes orphan attempts even when a Control Plane database restore lost the opaque mapping; external callers still have no list API. Terminal proof and queue membership are retained through the cleanup/audit window.

RPO=0 applies to acknowledged markers inside the live quorum: minority-node/leader loss cannot lose them. A point-in-time snapshot or asynchronous regional DR copy is not misrepresented as zero-loss; full-cluster DR uses the documented snapshot RPO, restores broker state before Control Plane claims, and automatically cleans every recovered nonterminal index entry. If a catastrophe loses a post-snapshot broker record, affected enrollment/diagnostic admission remains closed until the ≤5-minute AWX token lifetime and audited manual containment complete.

Each profile authenticates as its own fixed AWX user and calls only `POST /api/v2/users/{same-user-id}/personal_tokens/`; AWX 24.6.1 permits a non-superuser to create only its own personal token. The request has `application=null`; template verification requests OAuth scope `read`, while enrollment execution requests `write`. The response must contain exactly one access token, its numeric accessor, expiry, scope, and `application=null`, with no `refresh_token`. Configured lifetime is ≤5 minutes and the broker never renews. Application tokens, cross-user issuance, and any refresh token are rejected. AWX users and profiles are distinct between GET-only verification and enrollment launch, so one token/account cannot satisfy both purposes.

The trusted revoker component authenticates through a second fixed credential source for the same profile user, because AWX 24.6.1 allows a non-superuser to delete only that user's personal tokens. It uses only the broker's exact encrypted numeric token accessor for `DELETE /api/v2/tokens/{id}/`, followed by exact detail GET/404 confirmation. Issuer and revoker files must differ by inode, realpath, token-source ID and local audit principal, although AWX correctly records the same owning user. These long-lived same-user control credentials are explicit TCB: only the Broker workload can mount them, direct AWX egress is denied, and a purpose-specific mTLS L7 gateway allows the issuer source only the exact self-PAT POST and the revoker source only exact token DELETE/detail GET. Launch, cancel, inventory/template/project/credential mutation, token list/search and every other path are denied at the gateway; real E2E attempts them using each static source and requires zero AWX request/job. If this network control or workload isolation is absent, the affected profile remains `UNAVAILABLE`. Issue response loss with an unknown token ID, ambiguous delete, store/key corruption, or unavailable confirmation yields signed `UNCERTAIN→MANUAL_REQUIRED`, disables new enrollment claims, and triggers audited operator containment. Secret handles are single-delivery, zeroized after use, never renewed, and never serializable/loggable.

## 4. Enrollment context and result

For each remotely eligible Attempt:

```text
enrollment_context_digest = SHA256(FramedTupleV1(
  "awx-host-identity-enrollment-context.v1",
  T, W, E,
  operation_id,
  asset_id,
  source_id,
  minimal-decimal source_revision,
  integration_id,
  minimal-decimal inventory_id,
  minimal-decimal host_id,
  limit_token,
  raw latest_observation_content_sha256,
  raw mapping_artifact_sha256,
  raw enrollment_fingerprint_digest,
  raw enrollment_module_sha256,
  raw realm_digest,
  raw network_policy_digest,
  raw trust_closure_digest
))
```

The module first calls only the fixed local attestor and obtains an exact 32-byte Ed25519 public key. It signs the exact framed bytes, not a textual rendering:

```text
FramedTupleV1(
  "awx-host-identity-enrollment-challenge.v1",
  raw enrollment_context_digest,
  raw attestation_nonce
)
```

The exact launch body is RFC 8785 `{"extra_vars":{"attestation_nonce":"<64hex>","enrollment_context_digest":"<64hex>","enrollment_schema_version":"awx-host-identity-enrollment.v1","expected_host_id":<safe-int>},"limit":"<limit_token>"}` and has no other key. Let `launch_body_sha256=SHA256(exact body bytes)`:

```text
launch_request_sha256 = SHA256(FramedTupleV1(
  "awx-host-identity-enrollment-launch-request.v1",
  raw Attempt request_sha256,
  minimal-decimal enrollment_template_id,
  raw enrollment_fingerprint_digest,
  minimal-decimal lease_epoch,
  raw attestation_nonce,
  raw launch_body_sha256
))
```

The governed admission receipt digest is part of the created Job trust closure and is persisted before polling; the stock `/api/v2/job_templates/{id}/launch/` route is denied by L7 policy for verifier/enrollment/diagnostic users.

The event source is only `event_data.res.host_identity_enrollment_v1`. Its strict canonical object has exactly:

```text
attestation_nonce                  lowercase 64-hex
attestation_profile                closed host-attestor profile code
attestation_statement              canonical private host-attestor envelope
attestation_statement_sha256       lowercase 64-hex
attestor_build_digest              lowercase 64-hex
attestor_key_id                    bounded opaque code
enrollment_context_digest         lowercase 64-hex
host_id                           JCS-safe integer
identity_algorithm                ED25519_HOST_ATTESTATION_V1
identity_key                      lowercase 64-hex raw Ed25519 public key
identity_signature                lowercase 128-hex Ed25519 signature
schema_version                    awx-host-identity-enrollment.v1
```

The canonical private output is at most 65,536 bytes. `identity_key_sha256=SHA256(raw decoded 32-byte key)`. `attestation_statement` and profile obey `docs/contracts/host-identity-attestor-v1.md`; the verifier checks platform chain, nonce/context, workload measurement, TPM-sealed key/SPKI binding, instance identity, validity/revocation and anti-replay before accepting the Ed25519 challenge. Unsupported platform/profile or software-only continuity remains `UNAVAILABLE` and cannot claim platform-bound/anti-clone assurance；the contract never upgrades process-memory seed handling into hardware-native non-exportability. Unknown/duplicate keys, noncanonical JSON/integer, wrong nonce/context/Host, bad chain/key/signature, oversized data, extra Job Host, or more/less than one final result rejects the Attempt.

After the launch response, the executor reloads the created Job and computes:

```text
job_snapshot_digest = SHA256(FramedTupleV1(
  "awx-host-identity-created-job.v1",
  minimal-decimal job_id,
  minimal-decimal enrollment_template_id,
  minimal-decimal inventory_id,
  limit_token,
  raw launch_request_sha256,
  raw launch_admission_receipt_digest,
  raw enrollment_manifest_sha256,
  raw enrollment_fingerprint_digest,
  raw project_scm_revision_sha256,
  raw execution_environment_image_digest,
  raw credential_set_digest,
  raw instance_group_set_digest,
  "SUCCESSFUL"
))
```

The Job's final merged extra-vars SHA must equal the launch body nested object SHA and every other created-Job field must equal the verified manifest/admission receipt; drift prevents result acceptance. Polling accepts `successful` only with `event_processing_finished=true`. It then enumerates every Job event from the same origin using fixed `order_by=counter,id`, page size 200, derived page numbers rather than provider `next`, exact advertised count, contiguous counters/unique IDs, ≤1,000 events and ≤4 MiB total. Missing/duplicate/reordered/truncated/late events fail closed; exactly one final event may contain `event_data.res.host_identity_enrollment_v1`, and stdout/event bodies are never persisted.

The unique Job Host summary digest is:

```text
SHA256(FramedTupleV1(
  "awx-host-identity-job-summary.v1",
  minimal-decimal job_id,
  minimal-decimal enrollment_template_id,
  minimal-decimal inventory_id,
  minimal-decimal host_id,
  limit_token,
  "false",  // constructed_host
  "0",      // changed
  minimal-decimal dark,
  minimal-decimal failures,
  minimal-decimal ignored,
  minimal-decimal ok,
  minimal-decimal processed,
  minimal-decimal rescued,
  minimal-decimal skipped,
  "false",  // failed
  raw launch_request_sha256,
  raw launch_admission_receipt_digest,
  raw enrollment_output_sha256
))
```

The exact AWX 24.6.1 Host summary must have `host_id` equal the expected Host, `host_name` byte-equal the limit token, `constructed_host=false`, `changed=0`, `dark=0`, `failures=0`, `ignored=0`, `ok=1`, `processed=1`, `rescued=0`, `skipped=0`, and `failed=false`. The created Job and complete Host summary set must contain exactly this one row and no fallback/group expansion.

The strict RFC 8785 `awx-host-identity-enrollment-fact.v1` object is at most 2,048 bytes and has exactly these keys:

```text
algorithm
asset_id
attestation_nonce
attestation_profile
attestation_statement_sha256
attestor_build_digest
attestor_key_id
enrollment_context_digest
enrollment_fingerprint_digest
enrollment_module_sha256
enrollment_output_sha256
host_id
identity_key
identity_key_sha256
identity_signature
inventory_id
job_host_summary_digest
job_snapshot_digest
job_id
latest_observation_content_sha256
realm_digest
source_id
source_revision
status
trust_closure_digest
version
```

`status="SUCCEEDED"` and `version="awx-host-identity-enrollment-fact.v1"`. `enrollment_fact_sha256=SHA256(exact canonical fact bytes)`.

```text
identity_attestation_digest = SHA256(FramedTupleV1(
  "awx-host-identity-attestation.v1",
  T, W, E,
  integration_id,
  minimal-decimal inventory_id,
  minimal-decimal host_id,
  asset_id,
  source_id,
  minimal-decimal source_revision,
  raw latest_observation_content_sha256,
  raw identity_key_sha256,
  attestation_profile,
  raw attestation_statement_sha256,
  raw attestor_build_digest,
  attestor_key_id,
  raw enrollment_context_digest,
  raw enrollment_fact_sha256,
  raw job_snapshot_digest,
  raw job_host_summary_digest,
  "SUCCEEDED"
))
```

```text
host_binding_digest = SHA256(FramedTupleV1(
  "awx-host-asset-binding.v1",
  T, W, E,
  minimal-decimal inventory_id,
  minimal-decimal host_id,
  limit_token,
  asset_id,
  source_id,
  minimal-decimal source_revision,
  raw latest_observation_content_sha256,
  raw identity_key_sha256,
  raw identity_attestation_digest,
  raw enrollment_fact_sha256
))
```

## 5. Identity artifact and diagnostic projection

The strict `AWX_HOST_IDENTITY_BINDINGS` artifact schema is `awx-host-identity-bindings.v1`. It has exactly these top-level keys:

```text
connection_binding_digest
connection_revision
enrollment_fingerprint_digest
enrollment_fingerprint_manifest_sha256
enrollment_module_sha256
enrollment_operation_id
enrollment_request_sha256
host_bindings
integration_id
inventory_id
mapping_artifact_sha256
realm_digest
schema
source_id
source_revision
trust_closure_digest
```

`host_bindings` contains `1..10000` Asset UUID `C`-sorted unique entries. Each entry has exactly:

```text
asset_id
attestation_profile
attestation_statement_sha256
attestor_build_digest
attestor_key_id
enrollment_fact
enrollment_fact_sha256
host_binding_digest
host_id
identity_attestation_digest
identity_key
identity_key_sha256
latest_observation_content_sha256
limit_token
```

Every entry is at most 8,192 bytes; the canonical artifact is at most 64 MiB. Host IDs, safe limit tokens, and identity key hashes are independently unique within the cohort. Before accepting any key, completion/finalization acquires sorted transaction advisory locks derived from the full key hash and queries every retained successful enrollment plus current APPLIED identity artifact in Scope; reuse is allowed only for the exact same Integration/inventory/Host/Asset binding during rotation, while any cross-Asset/Host clone/rebind is rejected. Unknown/duplicate/noncanonical/oversized content, a failed/non-clean Attempt, invalid platform/challenge signature, missing current Observation, or any digest mismatch rejects sealing.

The artifact root digest is:

```text
SHA256(FramedTupleV1(
  "awx-host-identity-artifact-root.v1",
  minimal-decimal binding_count,
  raw artifact_sha256,
  raw cohort_digest,
  raw enrollment_request_sha256
))
```

`awx_read_template_revisions` stores only `identity_artifact_sha256`, `identity_artifact_root_digest`, and `identity_binding_count`; it never duplicates a dynamic `limit_map`. The server-side pinned contract resolver loads the exact private artifact by hash and constructs one opaque non-serializable binding handle with six safe comparison fields:

```text
asset_id
host_binding_digest
host_id
identity_attestation_digest
identity_key_sha256
limit_token
```

The handle additionally exposes only package-controlled `VerifyChallenge(messageDigest [32]byte, signature [64]byte) error`; it retains the raw artifact public key in private memory, returns no key bytes, and rejects JSON/String/GoString/copy/export. Thus Package 04 can independently verify a diagnostic challenge without pretending a SHA-256 key hash is a verifier. No artifact bytes, public key, fact, Host ID, limit token, or verifier handle enter public API/Audit/model/Task payloads. A content-addressed in-process index may cache verified bytes; cache keys include Runtime publication and artifact SHA, and drift closes admission.

## 6. Sealing, rollout, rotation, and recovery

Before authority acceptance, the server verifies the signed capacity profile and counts the complete eligible discovery cohort in the same serializable transaction. A count greater than `effective_cohort_limit` (never above 10,000) rejects creation with stable reason `HOST_IDENTITY_COHORT_CAPACITY_EXCEEDED`; no enrollment row, template-verification request, Attempt, credential, network call, artifact, or Runtime is created. Source discovery remains healthy, but AWX diagnostic enrollment/capability stays `UNAVAILABLE` and the existing gate assessment plus Audit/Outbox records only the safe count/limit/reason. There is no truncation, pagination into multiple Operations, or partial binding. Deterministic tests cover the schema boundary at 10,000/10,001; real E2E may admit 10,000 only with the signed throughput proof, otherwise tests its lower production limit.

The final serializable seal transaction locks/reloads the Operation, every Attempt, Source/revision/authority, exact latest Observations, Connection/mapping-only bootstrap Runtime, verified fingerprint bundle/prospective artifact hash, Realm/Network/Trust, module/image/credential profile, and the immutable database-resident cleanup proof facts in the global order. It performs zero Broker/network I/O and independently re-verifies every proof envelope digest/key/signature/binding/state. It excludes every `MANUAL_REQUIRED|UNCERTAIN|non-clean` child, requires `enrolled_count=count(SUCCEEDED)`, `unavailable_count=count(FAILED)`, their sum equals `cohort_size`, identity binding count equals `enrolled_count`, at least one success, and no drift. It then writes the immutable fingerprint and identity artifacts, a `PENDING` Runtime successor, Operation `SEALED`, Audit, and Outbox atomically.

Distributor/attestor observes the `PENDING` Runtime later. It belongs to the exact `AWX_HOST_DIAGNOSTIC` capability family and contains mapping+fingerprint+identity artifacts; the Source resolver accepts only the separate `AWX_INVENTORY_DISCOVERY` family whose artifact set is exactly mapping-only. Exact attestation may CAS the diagnostic Runtime to `APPLIED`; failure/drift leaves the previous diagnostic Runtime pinned and closes only AWX diagnostic admission. Contract publication consumes only that exact `APPLIED` successor and projects the diagnostic fingerprint branch plus identity artifact hashes/count. Diagnostic APPLIED/supersede/rollback never changes the discovery Runtime pointer, Source revision/gate/checkpoint/run success pointer, or its unique resolver cardinality; tests assert those facts before and after CAS.

Rotation always creates a new authority nonce, Operation, complete cohort, complete replacement artifact, Runtime, and contract revision. It never merges a partial cohort with or retains bindings from an old artifact. Old pinned diagnostic work may drain only while its old key/trust closure remains valid. Source/Connection/fingerprint/Observation/attestor drift during enrollment fails the exact Operation without changing Source checkpoint, discovery success pointers, gate, or Asset lifecycle; it closes only the affected diagnostic publication.

Recovery tests kill the coordinator/worker before and after every durable boundary: authority insert, Attempt claim, credential marker, launch marker, Job response, safe output persist, cleanup request/response, Operation finalization, artifact/PENDING Runtime commit, and APPLIED CAS. A post-launch unknown Job is never retried. Cleanup uncertainty becomes `MANUAL_REQUIRED`, suspends new enrollment/diagnostic claims, and requires an audited operator resolution; it cannot be relabeled success.

Migration down refuses while any enrollment Operation/Attempt or AWX mapping/fingerprint/identity artifact/Runtime exists. Empty rollback restores the exact predecessor artifact-kind/size constraints and routine/trigger definitions. Dump/restore and schema admission include both enrollment tables, indexes, constraints, transition/deferred triggers, ACLs, and row/content hashes.

## 7. Required tests

The TDD suite must independently prove:

- no cycle from Source creation/discovery to identity enrollment;
- only signed server bootstrap authority can create an Operation, with exact nonce replay rejection before network I/O;
- exact two-template fingerprint bundle and all sixteen prompt fields;
- exact preview, launch body, `ignored_fields={}`, created Job, unique Host summary, and final event;
- exact output/fact/artifact keys, caps, canonical bytes, signature, and all framed digests;
- 1, 128, 129, and 10,000 Host cohorts with bounded claim concurrency and no truncation, plus 10,001 fail-closed before Operation/network creation;
- per-Host failure affects only that Host while complete cohort accounting remains exact;
- stale fence, wrong worker/Realm, cross-Scope, duplicate/reordered cohort, observation or Runtime drift fail before remote work/seal;
- template-verification claim/issue/GET/cleanup boundary crashes, launch/cleanup response loss, revoker partition, two-active-broker fencing, broker backup/restore/key rotation, and `MANUAL_REQUIRED` containment;
- seal transaction atomicity, external rollout separation, APPLIED-only contract publication, N/N+1 pin/drain/rollback;
- no Secret, stdout, arbitrary event, endpoint, header/body, command/script, Host variable, public key, limit token, or raw provider error crosses its allowed private boundary.
