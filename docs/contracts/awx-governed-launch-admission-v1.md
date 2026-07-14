# AWX Governed Launch Admission v1

Status: confirmed private production contract for AWX `24.6.1`, Phase 5 package 04, and `awx-host-identity-enrollment-v1`.

This contract closes the unsafe GET/preview→stock launch race. It is not a public API, generic AWX proxy, or Action execution path. If this exact admission extension is absent, unverified, drifted, or bypassable, every AWX enrollment/diagnostic capability remains `UNAVAILABLE`.

## 1. Trusted build and routes

Production uses a digest-pinned AWX `24.6.1` image with reviewed patch revision `awx-governed-launch-admission.v1`. The patch source, AWX base commit, Python dependency lock, database migration, normalized-manifest golden, OCI digest, SBOM, vulnerability result and signature are one signed release artifact. Startup and Control Plane Runtime attestation bind all digests; a stock/mixed image fails readiness.

The extension exposes only:

```text
GET  /api/v2/job_templates/{safe-id}/governed_manifest/
POST /api/v2/job_templates/{safe-id}/governed_launch/
POST /api/v2/jobs/{safe-id}/governed_cancel/
GET  /api/v2/governed_launch_receipts/{uuid}/
```

Enrollment, diagnostic and verifier users are denied stock `/launch/`, relaunch, bulk launch, workflow launch, ad-hoc, project update, inventory update and every generic mutation by AWX permission plus the mTLS L7 gateway. Only fixed workload identities and purpose-matched users reach the four routes. No redirect, proxy, cookie, form, GraphQL or arbitrary path/body is supported.

## 2. Manifest read

`governed_manifest` accepts no request body/query other than fixed pagination-free representation. In one read-only transaction it returns the strict normalized template manifest/bundle branch from `awx-host-identity-enrollment-v1`, exact `manifest_sha256`, extension build digest and safe object revision digests. It never returns credential inputs, inventory variables, endpoints, SCM credentials, instance names or secrets. Response is `additionalProperties:false` and ≤65,536 bytes.

This GET supports release verification but grants no launch authority. Only the POST transaction below prevents execution-time drift.

## 3. Atomic governed launch

The strict RFC 8785 POST object has exactly:

```text
expected_host_id
expected_host_name_sha256
expected_manifest_sha256
extra_vars
idempotency_key
launch_request_sha256
limit
purpose
worker_fence_digest
```

`purpose` is `AWX_HOST_IDENTITY_ENROLLMENT_V1|AWX_HOST_DIAGNOSTIC_V1`; ID/digest/token/extra-vars shapes are the exact purpose contract. Unknown/duplicate fields, noncanonical JSON, unsafe limit, caller template/inventory/credential/EE/project/labels/tags or any generic prompt field is rejected before transaction/network.

The AWX view opens one PostgreSQL `SERIALIZABLE` transaction with `lock_timeout=2s`. Before reading mutable truth it executes one generated `LOCK TABLE ... IN SHARE MODE NOWAIT` over the reviewed AWX `24.6.1` model-relation manifest for JobTemplate/UnifiedJobTemplate, Project, Inventory, Host, Group, Credential, CredentialType, ExecutionEnvironment, InstanceGroup and every through relation that binds template credentials/instance groups, inventory hosts/groups and group hosts/children. Build tests derive physical names from Django `_meta.db_table`, byte-compare the exact reviewed model-label/physical-relation golden, and independently hold every relation to require lock failure and zero Job. `SHARE` conflicts with normal AWX DML, so template/project/SCM/credential/EE/inventory/Host/group association updates cannot commit between verification and Job snapshot creation.

Under those locks the view reloads and recomputes the complete signed release/manifest closure. It additionally proves:

- template, project SCM revision/playbook, digest-pinned EE, credential set, instance-group set, survey, all sixteen prompt flags and stored defaults equal `expected_manifest_sha256`;
- inventory ID is fixed by the manifest;
- exactly one enabled Host in that Inventory has byte-exact `name=limit`, its ID equals `expected_host_id`, and `SHA256(UTF-8 name)` equals the request;
- no Group has that name, no constructed/smart/dynamic Host participates, and the safe token contains no Ansible pattern/operator syntax;
- resolving the literal limit against the locked inventory yields exactly that Host and no fallback;
- purpose user/RBAC, extension build, release artifact, request/fence/idempotency and extra-vars closure are exact.

Any mismatch, serialization/lock conflict, non-idempotent or request-digest-conflicting duplicate, drift or resolver ambiguity returns stable rejection and creates zero UnifiedJob/Job/receipt. An exact idempotent replay is handled only by the existing-receipt rule below. The endpoint never attempts best-effort cancel after a failed admission.

On success the same transaction calls the pinned internal job-construction path, creates one immutable Job snapshot plus one `GovernedLaunchReceipt`, and stores their 1:1 IDs/digests before commit. It does not call `signal_start` inside the transaction. One `transaction.on_commit` callback starts only that exact Job after the receipt commit; callback failure marks the Job failed without constructing another. Idempotent replay returns the same receipt/Job only when every request digest matches; drift is conflict.

## 4. Receipt and cancellation

The strict receipt payload has exactly:

```text
created_job_snapshot_digest
expected_host_id
expected_manifest_sha256
extension_build_digest
inventory_id
job_id
launch_request_sha256
limit_sha256
purpose
receipt_id
template_id
version
worker_fence_digest
```

`version=awx-governed-launch-receipt.v1`; `receipt_digest=SHA256(RFC8785(payload))`. The Job stores that digest and the Control Plane persists it before polling. Receipt rows are immutable and private; public/model/Task/Audit surfaces expose at most the digest/status.

Governed cancel accepts exact `job_id,receipt_digest,launch_request_sha256,worker_fence_digest` only for a nonterminal Job created by this extension and the same purpose identity. It is idempotent and creates a signed cancel receipt. Unknown response or inability to prove final Job state is `MANUAL_REQUIRED`; cancel is never credential cleanup and never releases the template slot without a trusted terminal observation.

## 5. Required proof

Real AWX/PostgreSQL E2E must race every mutable manifest field, project SCM revision, credential/EE/instance-group association, Host rename/enable/rebind, same-name Group and inventory membership between manifest GET and launch POST. Every race must produce Job count zero unless the old closure was atomically locked and copied. Tests also prove stock launch/relaunch/workflow/ad-hoc routes are denied, `signal_start` occurs only after receipt commit, two AWX replicas return one idempotent Job, rollback creates none, malicious bodies create none, and image/SBOM/signature/schema drift keeps capability `UNAVAILABLE`.
