# Local PostgreSQL 18.4 Development and Test Instance

This repository runs required database tests against a workstation-managed PostgreSQL 18.4 deployment. Its location is supplied through `AIOPS_LOCAL_POSTGRES_ROOT`; no machine-specific root, password, private key, or complete DSN is committed. This deployment is a development/test dependency and is never a production deployment source.

## Fixed local contract

| Fact | Required value |
|---|---|
| Docker context | `colima-aiops` by default; explicitly overridable |
| Container | `aiops-postgres18` |
| Immutable image | `docker.io/library/postgres:18.4-alpine3.24@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15` |
| Host endpoint | loopback-only, default `localhost:55432` |
| Control database | exactly `aiops_test` |
| Server TLS | enabled, minimum TLS 1.3 |
| Authentication | distinct SCRAM password plus client certificate for each LOGIN identity |
| Test connection budget | `max_connections >= 100`; cross-package integration parallelism remains enabled |

The harness creates 128-bit randomized physical databases under the `aiops_assets_test_<hex>` family and removes only databases whose creation it confirmed. It must never point at an application or production database.

The workstation deployment operator must persist `max_connections = 100` (or a larger reviewed test-only value) in that deployment's external PostgreSQL configuration and restart only its dedicated `aiops-postgres18` test container. Rollback restores the prior external value and restarts that same test container; when the value is below 100, this repository's wrapper intentionally closes the parallel integration gate. This setting is not a production sizing recommendation.

## Identity and DSN boundaries

The first three rows below describe the current wrapper. The two Source Gate rows are the exact target after the sequential capability-identity harness merges；until then their variables/files are absent and must not be reported as available。

| Purpose | Exact login identity | In-memory variable | Allowed use |
|---|---|---|---|
| Test control/admin | `aiops` | `AIOPS_TEST_POSTGRES_DSN` | Local fixture bootstrap plus create/drop of confirmed randomized test databases only; never application runtime |
| Migration | `aiops_migrator` | `AIOPS_TEST_POSTGRES_MIGRATION_DSN` | Migration identity admission, then the reviewed SET-only edge to `aiops_schema_owner`; never runtime queries |
| Application | `aiops_control_plane_workload` | `AIOPS_TEST_POSTGRES_APPLICATION_DSN` | Application admission and runtime integration checks; never migration or role switching |
| Source Gate seal | `aiops_source_gate_sealer` | `AIOPS_TEST_POSTGRES_SOURCE_GATE_SEAL_DSN` | Receipt-seal primitive and exact identity/ACL negatives only |
| Source Gate admit | `aiops_source_gate_admitter` | `AIOPS_TEST_POSTGRES_SOURCE_GATE_ADMIT_DSN` | Gate-admit primitive and exact identity/ACL negatives only |

The two non-login roles are `aiops_schema_owner` and `aiops_control_plane_runtime`. The exact base graph is:

- `aiops_migrator`: `LOGIN NOINHERIT`, with only `SET TRUE / INHERIT FALSE / ADMIN FALSE` membership in `aiops_schema_owner`;
- `aiops_schema_owner`: `NOLOGIN NOINHERIT`, owns each randomized application test database and its trusted schema/object surface; the separate `aiops_test` control database remains test-admin infrastructure;
- `aiops_control_plane_runtime`: `NOLOGIN NOINHERIT`, carries only the reviewed runtime ACL;
- `aiops_control_plane_workload`: `LOGIN INHERIT`, with only `INHERIT TRUE / SET FALSE / ADMIN FALSE` membership in `aiops_control_plane_runtime`.

All four roles are `NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`. The local `aiops` role is an external test-control administrator and is not part of the production four-role ABI.

Source Gate A2a additionally consumes two production capability identities：`aiops_source_gate_sealer` and `aiops_source_gate_admitter` are both `LOGIN NOINHERIT` with the same five dangerous flags disabled、no membership、mutually distinct credentials/DSNs，and no base runtime or extension-owner rights。Their application database/schema ACL is absent at exact-36；only exact-38 postflight/grant gives direct database `CONNECT`、schema `USAGE` and their own single function `EXECUTE`，and down/unknown/partial revokes it。They have no relation/sequence ACL and cannot call one another's routine。

The current exact-36 `DatabaseRoleAdmission.Check` remains the four-base-role application probe and requires `session_user=current_user='aiops_control_plane_workload'`；the capability harness exact8 does not modify it，and instead uses control/admin fixtures to prove the two capability identities、ACL absence、pairwise-distinct credentials/DSNs and application-connection rejection。Formal A2a alone extends the application probe to version-matched six-role/exact-36-or-38 ACL admission and adds fixed exact-38-only capability probes requiring exact sealer/admitter session identity while rejecting role switching、cross-function privilege or any relation ACL。Migration identity and role-switch admission run separately before `BEGIN`；callers must not select an admission mode。

## External Secret and trust layout

With `root=$AIOPS_LOCAL_POSTGRES_ROOT`, the first three identities below are current；the Source Gate rows are the target layout that the capability-identity harness must provision before A2a:

| Identity/material | Root-relative file | Required mode |
|---|---|---:|
| Test-admin password | `secrets/postgres-password` | `0600` |
| Migration password | `secrets/migrator-password` | `0600` |
| Application password | `secrets/workload-password` | `0600` |
| Source Gate sealer password | `secrets/source-gate-sealer-password` | `0600` |
| Source Gate admitter password | `secrets/source-gate-admitter-password` | `0600` |
| Development CA | `certs/ca.crt` | readable |
| Test-admin certificate/key | `certs/client.crt`, `secrets/client.key` | key `0600` |
| Migration certificate/key | `certs/migrator-client.crt`, `secrets/migrator-client.key` | key `0600`; certificate CN `aiops_migrator` |
| Application certificate/key | `certs/workload-client.crt`, `secrets/workload-client.key` | key `0600`; certificate CN `aiops_control_plane_workload` |
| Source Gate sealer certificate/key | `certs/source-gate-sealer-client.crt`, `secrets/source-gate-sealer-client.key` | key `0600`; certificate CN `aiops_source_gate_sealer` |
| Source Gate admitter certificate/key | `certs/source-gate-admitter-client.crt`, `secrets/source-gate-admitter-client.key` | key `0600`; certificate CN `aiops_source_gate_admitter` |

After the capability-identity harness merges, every path is overridden through the safe path variables in `.env.example`. That same change must reserve empty `AIOPS_SOURCE_GATE_ADMIT_DATABASE_URL` and `AIOPS_DISCOVERY_SOURCE_GATE_SEAL_DSN_FILE` production slots without wiring either pool；A2c alone consumes them。Those variables identify files or intentionally empty configuration slots only; Secret values and complete DSNs must never appear in `.env`, shell history, documentation, logs, issue reports, snapshots, or commits.

## Wrapper behavior

The current `scripts/with-local-postgres.sh` continues to prove only control/migration/application identities. The capability-identity harness must extend it so that, after that Batch merges, it fails closed unless it can prove all of the following before running a command:

- an explicit external root and loopback-only endpoint;
- the exact control database and five exact LOGIN role names;
- the expected running/healthy digest-pinned container;
- PostgreSQL `18.4`, SSL enabled, TLS minimum `TLSv1.3`, and `max_connections >= 100`;
- readable CA/certificates, `0600` private keys, and nonempty `0600` passwords of at least 32 characters.

After the harness merges, it reads each password only into process memory, URL-encodes all URI components through standard input, exports the five DSNs above, proves all credentials are pairwise distinct, unsets the plaintext shell variables, and then `exec`s the requested command. It never prints or writes a DSN. Tests must use the identity-specific variable; `AIOPS_TEST_POSTGRES_DSN` is retained solely as the control/admin harness variable while legacy fixtures are migrated. The pre-A2a helper may create roles/credentials and control-database login evidence, but its application-database ACL reconciliation is exact and bidirectional：only exact-38 schema postflight enters the capability `CONNECT|USAGE` grant branch and then requires full role/capability admission；exact-36、successful A2a down、unknown or partial state enters revoke-and-prove-absent，with unknown/partial returning closed after revocation。A2a initial/up/down/up/partial tests must exercise every outcome so predecessor ACL cannot retain a capability grant。

## Stable commands

Select the external workstation deployment without committing its machine path:

```bash
export AIOPS_LOCAL_POSTGRES_ROOT=/path/to/workstation/postgresql
```

Verify the instance and one real migration path:

```bash
make postgres-local-check
```

Run the required PostgreSQL integration gate:

```bash
make test-integration-local
```

Run another command with the same protected environment:

```bash
./scripts/with-local-postgres.sh go test -race ./internal/assetcatalog/postgres -count=1
```

The external deployment's own launcher may set `AIOPS_LOCAL_POSTGRES_ROOT` and `AIOPS_REPOSITORY_ROOT`, then delegate to this repository wrapper. It must not reconstruct a DSN itself.

## Rotation and recovery

If a password or identity file is missing, empty, expired, or suspected of exposure, stop the test gate. Generate a new cryptographically random password (at least 256 bits), update the external Secret file and matching database role as one operator-controlled rotation, issue a replacement client certificate with the exact role CN, keep private files at `0600`, and rerun both identity login checks plus `make postgres-local-check`.

Changing only the file or only the database role intentionally breaks authentication. Never recover by weakening `pg_hba.conf`, client-certificate verification, TLS, role flags, memberships, database/schema ACL, or the separation between control、migration、application、sealer and admitter DSNs.
