# Credential Revocation M2B Durable Broker and Vault Client

**Goal:** Add the non-runtime `DurableBroker`, a database-time child-creation authorization, and a strict Vault 2.0.3 profile client. This slice must prove the absolute-expiry and effective-policy invariants required by M2A, but must not yet wire credentials into `execution.Service` or a write runner.

**Architecture:** Policy and a server-owned issuer profile are resolved before persistence. `PrepareResult.Created=true` elects the only creator. Immediately before Vault, the PostgreSQL repository locks the current Runner registration, action, and revocation in that order; it proves an enabled WRITE Runner, matching scope revision, exact workspace/environment binding, RUNNING state, and no cancellation intent before returning a bounded DB-time authorization. The Broker creates one non-orphan service child, anchors its accessor before any dynamic secret call, inspects the child through the manager identity, issues exactly one leased secret, destroys the child token, and returns the secret only after ACTIVE is durably acknowledged. Any post-anchor failure destroys local material and persists revocation intent.

**Vault compatibility decision:** Vault 2.0.3 cannot return a leased dynamic secret when `num_uses=1`: the final use lazily revokes the token and leases and replaces the response with an error. M2B therefore uses a two-use budget on one exact leased path. The first request may return one lease; a second request becomes the final use, revokes the token and all leases, and cannot return another leased secret. This is valid only with an exact dynamic path, non-empty `lease_id`, and a one-shot client. See [Vault request handling](https://github.com/hashicorp/vault/blob/v2.0.3/vault/request_handling.go#L1271-L1311), [token creation](https://github.com/hashicorp/vault/blob/v2.0.3/vault/token_store.go), and the [Token API](https://developer.hashicorp.com/vault/api-docs/auth/token).

## Non-negotiable boundaries

- No changes to `internal/execution`, command assembly, HTTP APIs, or production-write configuration in M2B.
- M2B remains unreachable from runtime until M2C supplies ANCHORED/ACTIVE recovery and ActionQueue finalization.
- The manager parent is a dedicated service token with no EntityID and exact manager policies. Ordinary Kubernetes/OIDC entity tokens are rejected because non-orphan children inherit the parent EntityID.
- The revoker uses a separate token source. Issuer profiles are immutable and retained by issuer ID until all of their accessors are terminal.
- Child role, policies, namespace, cluster, CA, server name, method, path, fixed body, response fields, and profile revision come only from server configuration.
- The child is `service`, non-orphan, non-renewable, non-periodic, no default policy, exactly two uses, and has no identity or external-namespace policies.
- Vault's PostgreSQL dynamic lease is normally marked renewable. The child policy has no lease-renew capability, the lease ID is never returned, and accessor revocation remains the lifecycle authority.
- Child create and dynamic issue are one-shot. No redirect, retry, proxy, cookie jar, keepalive reuse, HTTP/2, idempotency header, response wrapping, or child-token preflight is allowed.
- Token, accessor, dynamic lease ID, secret, upstream body, and bearer fences never enter JSON, logs, traces, audit/outbox, Temporal history, or plaintext persistence.

### Task 1: DB-time child-create authorization

**Files:**
- Modify: `internal/credential/revocation.go`
- Modify: `internal/credential/memory.go`
- Modify: `internal/credential/revocation_test.go`
- Modify: `internal/credential/postgres/repository.go`
- Modify: `internal/credential/postgres/repository_test.go`
- Modify: `internal/store/postgres/migrations_integration_test.go`

1. Add a random child-create permit to `PrepareResult`. Only an error-free `Created=true` response contains the raw permit; PostgreSQL stores only its SHA-256 digest. Replays, errors, and ambiguous commits never return it.
2. Persist the permit digest plus nullable `child_create_authorized_at` and `child_create_ttl_seconds`. The state remains PREPARED, but the permit may be consumed exactly once with version, audit, and outbox advancement.
3. Add failing public-contract tests for non-idempotent `AuthorizeChildCreate`: only PREPARED/no-accessor/current Runner/action/scope proof plus the Created winner's permit is accepted; a second authorization never returns another TTL. Lock order is registration, action, then revocation; replayed/terminal/cancelled/expired scope fails closed.
4. Add fixed constants for DB commit, Vault ingress, Vault server request, DB/Vault clock lead, TTL quantization, and minimum usable child TTL. Callers cannot supply any of these values. The fixed reserve is their sum.
5. Return a database-derived authorization containing the canonical revocation, DB observation time, exact whole-second TTL, and the fixed monotonic Vault-call budget.
6. Prove the bound:

   ```text
   VaultChildCommitTime + AuthorizedTTL <= CredentialExpiresAt
   ```

   by computing `floor(CredentialExpiresAt - DBNow - FixedReserve)` and rejecting non-positive or sub-minimum budgets.
7. Require action lease and authorization to remain valid beyond the full fixed reserve plus the post-child safety window.
8. PostgreSQL must hold `runner_registrations FOR SHARE`, then `action_queue FOR SHARE`, then `credential_revocations FOR UPDATE`, and read `clock_timestamp()` after the locks. The same transaction proves WRITE/enabled/current revision/exact scope/RUNNING/no-cancel. It never persists a create bearer or caller-selected relative TTL.
9. `RecordNoCredential` is legal only before permit consumption. `RecordAnchor` is legal only after successful authorization. An authorized-but-ambiguous create remains PREPARED until anchor or absolute-expiry recovery.
10. The Broker must create one monotonic timeout before DB authorization and reuse that context for the single Vault create. Deployment configuration must cap Vault listener `max_request_duration` and network budgets within the fixed reserve.
11. Add real PostgreSQL 16 tests for two-Gateway permit races, authorize versus `RecordNoCredential`, authorize versus recovery, DB time versus skewed process clocks, short remaining budgets, lock ordering, Nack, and the exact safe/unsafe boundary.

### Task 2: Sensitive value and durable domain contracts

**Files:**
- Create: `internal/credential/sensitive_value.go`
- Create: `internal/credential/sensitive_value_test.go`
- Create: `internal/credential/durable_broker.go`
- Create: `internal/credential/durable_broker_test.go`

1. Add a shared-state `SensitiveValue` for child tokens and dynamic secrets: clone-on-read, concurrent idempotent `Destroy`, fully redacted formatting/JSON, and a fixed 64 KiB maximum.
2. Add redacted `DurableCredential` metadata containing only revocation ID and absolute expiry. It must not expose child token, accessor, lease ID, fence, issuer body, or policy details.
3. Add typed requests for issuer selection, child creation, manager inspection, and dynamic secret issue. Reject arbitrary URL/path/method/body fields from action payloads.
4. Add `DurableIssuerResolver` and `DurableIssuer` interfaces. Resolver input binds workspace, environment, action type, connector, permission, and signed resource to a server-owned profile.
5. Add an injected UUID source and monotonic timeout source for deterministic crash-boundary tests.

### Task 3: DurableBroker state machine

1. Write RED tests for every boundary: policy, profile, Prepare, DB authorization, child create commit/response, anchor commit/ACK, manager inspection, dynamic issue commit/response, Activate commit/ACK, and caller handoff.
2. Enforce the exact sequence:

   ```text
   policy -> profile -> Prepare(Created=true + permit) -> consume DB-time authorization
   -> Create child once -> RecordAnchor ACK -> manager lookup-accessor
   -> Issue leased secret once -> destroy child token -> Activate ACK
   -> expose DurableCredential
   ```
3. `Created=false` and every Prepare error prohibit child creation, even if the returned row is already ANCHORED or ACTIVE.
4. Anchor any returned accessor before trusting child properties. Unsafe child properties after anchor transition to revocation; malformed/ambiguous create with no accessor remains PREPARED for absolute-deadline recovery.
5. ANCHORED or later failures clear child token and secret before calling durable `RequestRevocation`. Repository failure remains retryable and is reconciled in M2C.
6. `RequestRevocation` on a managed credential clears the local secret before persistence, is concurrent/idempotent across value copies, and performs no synchronous Vault revoke.
7. Secret ownership transfers to the caller only after an exact ACTIVE response. PENDING/REVOKING/MANUAL/REVOKED observations never expose the secret.

### Task 4: Immutable Vault profile and one-shot transport

**Files:**
- Create: `internal/credential/vault/profile.go`
- Create: `internal/credential/vault/profile_test.go`
- Create: `internal/credential/vault/client.go`
- Create: `internal/credential/vault/client_test.go`

1. Validate HTTPS-only base URLs with no userinfo, query, fragment, wildcard, traversal, or mutable path suffix. Require explicit CA roots and TLS 1.3; never set `InsecureSkipVerify`.
2. Require separate manager and revoker `SensitiveValue` token sources. Environment variables are not a token source.
3. Build a fresh one-shot transport per request: `Proxy=nil`, `DisableKeepAlives=true`, HTTP/1 only through `http.Protocols`, `ForceAttemptHTTP2=false`, no HTTP/2 `TLSNextProto`, request `Close=true`, `GetBody=nil`, and no idempotency headers.
4. Disable redirects and cookies. Treat every 3xx as an error without forwarding a token.
5. Cap connect, TLS, response-header, total request, request body, and response body sizes. Discard upstream error bodies and expose only operation, safe class, status, and ambiguity.
6. Add a strict JSON duplicate-key detector before decoding all security-relevant Vault responses.
7. Tests must prove wrong CA, TLS 1.2, proxy environment, redirect target, h2 server, reused-connection disconnect, GET/POST replay, duplicate fields, body overflow, and error bodies all fail closed without a second request.

### Task 5: Vault manager, child, dynamic secret, and revoker APIs

1. Manager `lookup-self` must prove a dedicated service parent with empty EntityID, exact manager policies, sufficient TTL, and no unexpected identity/external policies.
2. Create only `POST /v1/auth/token/create/<fixed-role>` with exact child policies, `type=service`, `renewable=false`, `num_uses=2`, `no_default_policy=true`, bounded `ttl` and `explicit_max_ttl`, fixed metadata, and no orphan flag.
3. After the accessor anchor, use manager `POST /v1/auth/token/lookup-accessor`; never use child `lookup-self` or capabilities.
4. Inspect exact path, role, policies/token policies, empty EntityID/identity/external policies, non-orphan, non-renewable, two remaining uses, zero period, metadata, namespace/profile, bound CIDRs, TTL, explicit max TTL, and absolute expiry.
5. Dynamic issue uses the child token exactly once on the fixed endpoint. Require a non-empty lease ID internally, a lease not beyond the conservative child/database deadline, and an allowlisted secret-field shape. Vault database leases may report `renewable=true`; the exact child policy cannot call renewal paths. Discard and clear the lease ID after validation.
6. Every post-dispatch issue result, including 4xx/5xx/timeout/EOF/malformed JSON, is ambiguous and triggers durable revocation without retry.
7. `revoke-accessor` uses only the separate revoker source. All non-2xx results remain retryable; a 400 must not be treated as already revoked.

### Task 6: Real Vault compatibility evidence and verification

**Files:**
- Create: `internal/credential/vault/integration_test.go`
- Modify: `.github/workflows/ci.yml`
- Modify: this plan with final evidence notes

1. Pin Vault 2.0.3 in CI and use the existing PostgreSQL 16 service to configure a disposable database dynamic-secret role. Fake/contract servers remain unit evidence only.
2. Prove with real Vault:
   - `num_uses=1` cannot return a leased secret;
   - `num_uses=2` returns one lease, then the final use cannot return another and revokes the first;
   - KV/empty-lease responses do not satisfy the profile;
   - an EntityID manager contaminates a non-orphan child and is rejected;
   - a dedicated no-EntityID parent succeeds;
   - parent revocation cascades to child and leases;
   - accessor lookup/revoke is namespace/profile-bound.
3. Unit and integration fixtures must scan formatted errors and captured test output for token/accessor/lease/secret canaries. Database, audit/outbox, application logs, traces, and Vault audit-device scans require the deployed enterprise environment and remain an external gate.
4. Run:

   ```text
   gofmt -l .
   git diff --check
   go mod verify
   go test -race -shuffle=on -count=1 ./...
   go vet ./...
   go build ./cmd/control-plane ./cmd/worker ./cmd/runner
   go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
   ```

5. Obtain an independent security review. Push to draft PR #4 only after focused and full local gates are green; PostgreSQL 16 plus Vault 2.0.3 CI is required before starting M2C.

### Implemented evidence and remaining external gates

- Local unit/contract evidence is green for full `-race -shuffle`, `vet`, build, module verification, formatting, diff checks, and `govulncheck`.
- The real integration fixture is an external `vault_test` package. It uses a TLS 1.3/HTTP/1.1 loopback proxy and the exported production `Profile`/`Client` to run manager validation, child create/inspection, PostgreSQL issuance and `SELECT 1`, independent revoker accessor revocation, and database credential invalidation.
- Vault 2.0.3 emits one fixed warning when both the role and request specify `explicit_max_ttl`. The client accepts only that exact single warning with the lesser-value seconds equal to the database-authorized request TTL; missing, additional, or mismatched warnings fail issuance while preserving any returned accessor for revocation. Lookup-accessor must then report the same exact explicit max TTL.
- Foreground post-dispatch cleanup uses the repository's internal system-recovery transition rather than an expiring action fence, so lease expiry, cancellation, `FINALIZING`, or `UNCERTAIN` cannot strand an already anchored record. M2C must still add an ANCHORED/ACTIVE sweeper for database outages or lost cleanup acknowledgements before runtime wiring.
- `DurableCredential.Secret` uses the conservative Vault expiry and destroys shared material at the deadline; copies cannot reconstruct it afterwards.
- Real tests also cover `num_uses=1/2`, a renewable database lease that the narrow child cannot renew, KV v1 empty-lease rejection, EntityID contamination rejection, and parent/accessor cascade semantics. Missing accessor/lease evidence accepts only Vault 2.0.3's exact HTTP 400 response while root health remains valid; 403/404 never count as revocation.
- This workstation has neither a PostgreSQL service nor a Vault service, so those tests skip locally. GitHub CI with PostgreSQL 16 and `hashicorp/vault:2.0.3` is the required execution evidence; a fake server is not counted as real integration.
- Enterprise Namespace isolation, real Vault PKI and certificate rotation, HA/failover/restart, listener `max_request_duration`, deployed manager/revoker auth roles, NetworkPolicy, and cross-system audit/log/outbox/trace canary scans remain external go/no-go gates.
- M2B remains library-only and unreachable from runtime. No production write configuration or execution path was added.

## M2C boundary

M2C will pass the action lease fence into `DurableBroker`, move issuance after final policy/safety/environment validation, add ANCHORED/ACTIVE recovery and the revocation worker, replace synchronous lease revocation, gate ActionQueue FINALIZING on durable revocation, and only then make this library reachable from a write runner. Production write remains absent.
