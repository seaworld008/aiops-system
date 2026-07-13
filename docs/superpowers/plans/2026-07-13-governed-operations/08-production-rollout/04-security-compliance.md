# Production Security, Identity, Supply Chain, and Compliance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make production release artifacts, identities, credentials, data handling and operator workflows independently verifiable against the approved threat model and fail-closed governance invariants.

**Architecture:** Enforce security in four layers: source/artifact provenance, Kubernetes admission and network identity, runtime authorization/credential boundaries, and append-only compliance evidence. Automated scanners provide inputs rather than self-approval; explicit expiring exceptions and independent sign-off are required where a finding cannot be immediately removed.

**Tech Stack:** Go security tests, OpenAPI contract tests, gitleaks, govulncheck, gosec, Semgrep, Syft, Grype, Cosign, OCI attestations, Kubernetes 1.36 ValidatingAdmissionPolicy, workload identity, Keycloak OIDC, Vault/PKI, mTLS, OWASP ZAP, Playwright/axe, and signed JSON evidence.

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- The model remains outside the trusted computing base and can never convert untrusted Evidence, prompt text or UI content into authorization.
- No scanner suppression, severity downgrade or allowlist entry is accepted without owner, exact finding/artifact, rationale, compensating control, creation time and mandatory expiry.
- Production images and charts must be built from the accepted commit by the protected release workflow, signed, attested and pinned by digest.
- Operator identity, workload identity and short-lived target credential are different credentials with different issuers/audiences and may not be exchanged.
- Browser tokens remain memory-only; production OIDC configuration fails closed and no test identity provider is linked.
- Audit/evidence retention, legal hold and deletion are policy-controlled. Missing an approved signed retention revision blocks the release.
- Security evidence contains digests and bounded summaries, not secrets, exploit payload dumps, raw database rows or model prompts.

## Fixed Security Decision Matrix

| Signal | Required response | Release result |
|---|---|---|
| unsigned or provenance-mismatched image | admission deny and artifact quarantine | `HOLD` |
| secret/credential/DLP canary exposure | revoke、contain、incident and evidence preservation | `HOLD` |
| unauthorized or duplicate mutation | scoped Kill Switch and independent investigation | `ROLL_BACK` or `HOLD` |
| workload identity/Realm/network drift | deny new claim and rotate identity/policy | `HOLD` |
| stale critical/high finding without accepted expiry | block candidate | `HOLD` |
| expired access review or orphan privilege | revoke and rerun review | `HOLD` |
| audit/evidence integrity gap | close affected admission and repair chain | `HOLD` |
| unknown scanner/DAST result | treat as missing evidence | `HOLD` |
| accepted time-bounded nonzero exception | independent sign-off plus compensating control | continue only within expiry |
| all security/compliance gates fresh PASS | add signed evidence observation | no automatic promotion |

Security automation supplies evidence and may stop a release；it cannot self-approve a wave or create `PRODUCTION_CLOSED_LOOP_ACCEPTED`.

### Task 1: Update the production threat model and executable security invariants

**Files:**
- Create: `docs/security/threat-model-v4.md`
- Create: `docs/security/production-readiness.md`
- Create: `docs/security/security-invariants.yaml`
- Create: `tests/security/invariants_test.go`
- Create: `tests/security/secret_surface_test.go`
- Create: `tests/security/authorization_matrix_test.go`
- Create: `tests/security/prompt_data_boundary_test.go`

**Interfaces:**
- Consumes: accepted architecture/ADRs, all public API schemas, Runner protocols, frontend storage behavior, Action/verification paths
- Produces: versioned threat/control matrix and executable negative suite

- [ ] **Step 1: Write failing invariant-schema and coverage tests**

The test loads `security-invariants.yaml` and requires every invariant to name an owner, trust boundary, prevention control, detection, test ID, incident action and release gate. It cross-checks every public privileged operation and Runner RPC has at least one positive authorization and one negative boundary test.

```go
func TestEveryPrivilegedOperationHasNegativeBoundaryProof(t *testing.T) {
    operations := loadPrivilegedOpenAPIOperations(t, "../../api/openapi/control-plane-v1.yaml")
    invariants := loadInvariants(t, "../../docs/security/security-invariants.yaml")
    for _, operation := range operations {
        require.NotEmpty(t, invariants.NegativeProofFor(operation.OperationID), operation.OperationID)
    }
}
```

Run:

```bash
go test ./tests/security -run 'TestEvery|TestInvariantSchema|TestSecretSurface' -count=1
```

Expected: FAIL until the threat model, invariant catalog and test mapping exist.

- [ ] **Step 2: Document assets, actors, boundaries, abuse cases, and controls**

At minimum cover:

- OIDC operator impersonation, stale roles, self-approval and reauthentication replay.
- Cross-scope Asset/Connection/Grant/Action/release references.
- Connection and credential-reference tampering.
- Runner certificate theft, Realm confusion, replay, lease fencing and clock skew.
- Browser/model/prompt attempts to inject endpoint, header/body, shell, SQL, path, Secret, approval or Action parameters.
- Evidence/log/trace prompt injection and data exfiltration.
- Runtime publication rollback/downgrade and digest collision/ambiguity.
- READ credential reuse for WRITE, WRITE credential widening, revocation uncertainty and crash.
- Duplicate or uncertain target mutation, verification spoofing and unsafe rollback.
- Audit deletion/tampering, outbox loss and release-evidence forgery.
- Supply-chain compromise, mutable images, chart/value tampering and test dependency in production.
- Backup theft, restore of active Grants/credentials and DR decision replay.
- Kill Switch bypass, policy dependency outage and operator emergency misuse.

For each abuse case, identify prevention, bounded detection labels, stop/escalation behavior, evidence and test.

- [ ] **Step 3: Implement negative tests at every boundary**

Tests must prove:

- Unknown fields and oversized bodies fail before domain dispatch.
- Scope/tenant IDs come from authenticated context, never request claims alone.
- Secrets never appear in API/OpenAPI examples, generated TypeScript, logs, traces, audit details, browser storage, workflow payloads or Runner payloads.
- Untrusted evidence is rendered as text, not HTML, and cannot create a tool/Action request.
- All privileged commands require exact `effective_actions` plus server authorization.
- mTLS subject/issuer/audience/Realm mismatch, expiry and revocation deny Claim/Start/Heartbeat/Complete.
- Action verification uses an independent read capability and cannot accept executor self-assertion.

Run:

```bash
go test -race -shuffle=on -count=1 ./tests/security/... ./internal/authn/... ./internal/authz/... ./internal/runnergateway/... ./internal/credential/... ./internal/action/... ./internal/actionverification/...
```

Expected: PASS; prohibited inputs produce stable typed denials and no side effect.

- [ ] **Step 4: Commit threat and invariant coverage**

```bash
git add docs/security tests/security
git commit -m "docs(security): make production invariants executable"
```

### Task 2: Build, attest, scan, sign, and admit immutable artifacts

**Files:**
- Create: `scripts/security/verify-release-artifacts.sh`
- Create: `scripts/security/verify-image-policy.sh`
- Create: `deploy/policies/production/validating-admission-policies.yaml`
- Create: `deploy/policies/production/image-signature-policy.yaml`
- Create: `deploy/policies/production/README.md`
- Create: `tests/security/artifact_policy_test.go`
- Modify: `.github/workflows/production-release-candidate.yml`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: protected source commit, dependency lockfiles, Dockerfiles, chart, builder workload identity
- Produces: SBOM, vulnerability/SAST/secret-scan reports, SLSA-style provenance, signatures, admission evidence

- [ ] **Step 1: Add failing artifact-policy tests**

Reject an unsigned image, mutable tag, untrusted issuer/subject, digest mismatch, missing SBOM/provenance, unexpected base image, privileged/host namespace, root user, writable root filesystem, unbounded resources, added Linux capability and an expired vulnerability exception.

Run:

```bash
go test ./tests/security -run TestArtifactPolicy -count=1
```

Expected: FAIL until policies and verifier exist.

- [ ] **Step 2: Implement source and dependency scanning**

`verify-release-artifacts.sh` runs, with pinned tool versions recorded in the workflow:

```bash
gitleaks detect --no-banner --redact --source .
govulncheck ./...
gosec -fmt=json -out="$EVIDENCE_DIR/gosec.json" ./...
semgrep scan --config p/golang --config p/owasp-top-ten --json --output "$EVIDENCE_DIR/semgrep.json" .
syft "dir:." -o cyclonedx-json="$EVIDENCE_DIR/source-sbom.json"
```

Build each image in the protected workflow, then generate image SBOM, scan by digest, and sign/attest with keyless workload identity. Release passes only when there is no unresolved exploitable Critical/High finding. An exception is a signed record bound to CVE/rule, exact digest, owner, compensating control and expiry; expiry or digest change blocks.

- [ ] **Step 3: Implement admission and signature verification**

Kubernetes admission denies mutable/unqualified images, missing digest, unsigned/untrusted provenance, prohibited security contexts, host access, missing resources and service-account-token automount. Signature policy trusts only the protected repository/workflow subject and expected OIDC issuer.

Test in a disposable cluster:

```bash
bash scripts/security/verify-release-artifacts.sh
bash scripts/security/verify-image-policy.sh
kubectl apply --server-side --dry-run=server -f deploy/policies/production/validating-admission-policies.yaml
go test ./tests/security -run TestArtifactPolicy -count=1
```

Expected: accepted release artifacts pass; every malicious fixture is denied with a stable reason.

- [ ] **Step 4: Commit supply-chain enforcement**

```bash
git add scripts/security deploy/policies/production tests/security .github/workflows
git commit -m "feat(security): attest and admit immutable artifacts"
```

### Task 3: Implement identity lifecycle, access reviews, retention, and audit export

**Files:**
- Create: `docs/security/identity-and-access.md`
- Create: `docs/security/retention-policy.schema.json`
- Create: `docs/security/production-retention-policy.json`
- Create: `internal/accessreview/model.go`
- Create: `internal/accessreview/service.go`
- Create: `internal/accessreview/postgres/repository.go`
- Create: `internal/accessreview/service_test.go`
- Create: `internal/accessreview/postgres/repository_integration_test.go`
- Create: `internal/auditexport/export.go`
- Create: `internal/auditexport/export_test.go`
- Modify: `api/openapi/control-plane-v1.yaml`
- Regenerate: `web/src/shared/api/schema.d.ts`

**Interfaces:**
- Consumes: Keycloak groups/roles, service ownership, workload identities, credential issuer roles, audit records, signed retention revision
- Produces: periodic access-review campaigns, revoke actions, immutable audit export manifest and retention gate

- [ ] **Step 1: Write failing identity and retention tests**

Cover departed/disabled operator, stale privileged group, ownerless service, dormant break-glass role, overlapping proposer/approver/decider, unused workload identity, orphaned Vault/PKI role, retention policy missing signer/expiry, audit export gap and legal-hold deletion attempt.

Run:

```bash
go test ./internal/accessreview/... ./internal/auditexport/... -count=1
```

Expected: FAIL because packages do not exist.

- [ ] **Step 2: Implement access-review domain and durable campaign**

A campaign snapshots exact identities, role bindings, scopes, effective actions, service ownership, workload identity subjects/audiences and issuer roles. Review decisions are `KEEP`, `REVOKE` or `ESCALATE`; no response by deadline becomes `REVOKE_OR_HOLD` for privileged access. Applying revocation is idempotent, audited and verified against Keycloak/Vault/PKI.

Break-glass access requires named incident, narrow scope, short expiry, two-person activation, global visibility and post-incident review. It cannot create arbitrary Action types or bypass immutable plans/verification.

- [ ] **Step 3: Implement signed retention and audit export**

The production retention file validates against the schema and contains approved durations for operational records, Evidence, Receipts, security audit, release decisions, backups and legal holds, plus signer identities and policy digest. There is no permissive application default; absence or expiry fails release readiness.

Audit export writes ordered records plus sequence range, previous/export digest, schema revision, object-store URI, encryption/signature metadata and gap status. Tests prove deterministic export, tamper detection, idempotent retry and no credential material.

Run:

```bash
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test -race ./internal/accessreview/... ./internal/auditexport/... -count=1
pnpm --dir web generate:api
pnpm --dir web typecheck
```

Expected: PASS; a missing review or audit gap produces a blocking release gate.

- [ ] **Step 4: Commit identity and compliance controls**

```bash
git add docs/security internal/accessreview internal/auditexport api/openapi/control-plane-v1.yaml web/src/shared/api/schema.d.ts
git commit -m "feat(compliance): govern access review and audit retention"
```

### Task 4: Execute penetration, abuse, incident, and compliance gates

**Files:**
- Create: `tests/security/dast-baseline.yaml`
- Create: `tests/security/runner-abuse_test.go`
- Create: `tests/security/action-abuse_test.go`
- Create: `web/e2e/security/browser-security.spec.ts`
- Create: `docs/operations/production/security-incident-response.md`
- Create: `docs/operations/production/credential-compromise.md`
- Create: `docs/operations/production/audit-gap-response.md`
- Create: `docs/security/production-signoff.schema.json`
- Modify: `internal/releasegovernance/gates.go`
- Modify: `internal/releasegovernance/gates_test.go`

**Interfaces:**
- Consumes: production-equivalent deployment, attack fixtures, signed scan/access/audit/incident-drill summaries
- Produces: `GateSecurity` and `GateCompliance` evidence with independent sign-off

- [ ] **Step 1: Add failing security-gate tests**

Require fresh successful secret, SAST, dependency, image, signature, admission, DAST, access-review, audit-export and incident-drill evidence. Any missing, expired, unsigned, wrong-digest, gap-bearing or unresolved Critical/High result is `UNKNOWN` or `FAIL` and blocks promotion.

Run:

```bash
go test ./internal/releasegovernance -run 'TestSecurityGate|TestComplianceGate' -count=1
```

Expected: FAIL until the gate schema is complete.

- [ ] **Step 2: Implement DAST and protocol abuse suites**

Run ZAP against the public API with an allowlisted test identity and passive plus bounded active rules. Browser tests assert CSP, frame denial, MIME protection, Referrer-Policy, strict CORS, memory-only tokens, logout cleanup, no sensitive URL/query state, safe Evidence rendering and no secret in network response.

Runner/Action abuse tests include replay, invalid certificate chains, wrong Realm/audience, clock skew, oversized frames, malformed protobuf/JSON, slowloris, endpoint/SQL/shell/payload injection, approval hash substitution, target drift, duplicate claim, verifier spoofing and forced crash.

- [ ] **Step 3: Run incident drills and independent sign-off**

Exercise: OIDC privileged-account compromise, Runner certificate compromise, Vault/PKI credential-issuer compromise, suspected duplicate production Action, DLP leak, audit sequence gap and malicious release artifact. Each run proves Kill Switch/revocation, containment, evidence preservation, owner notification, recovery/reissue, reconciliation and post-incident release decision.

Run:

```bash
AIOPS_E2E_BASE_URL="$AIOPS_E2E_BASE_URL" zap-baseline.py -c tests/security/dast-baseline.yaml -t "$AIOPS_E2E_BASE_URL"
go test ./tests/security -run 'TestRunnerAbuse|TestActionAbuse' -count=1
pnpm --dir web exec playwright test e2e/security/browser-security.spec.ts
bash scripts/security/verify-release-artifacts.sh
```

Expected: no blocking finding; signed summaries reference the exact release digest. Security and platform signers differ from the release proposer.

- [ ] **Step 4: Bind evidence and commit**

```bash
go test ./internal/releasegovernance -run 'TestSecurityGate|TestComplianceGate' -count=1
git add tests/security web/e2e/security/browser-security.spec.ts docs/operations/production docs/security internal/releasegovernance
git commit -m "feat(release): gate rollout on security evidence"
```
