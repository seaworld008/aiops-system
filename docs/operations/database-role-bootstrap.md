# PostgreSQL Database Role Bootstrap

This runbook is the sole bootstrap/IaC truth for the base PostgreSQL role ABI and later Source Gate capability identities consumed by Asset Catalog migration `000015`. Before any application migration it provisions all identities but only the base/exact-36 owned-manifest database/schema ACL；Source Gate capability `CONNECT|USAGE` is a conditional postflight reconciliation after both the `000015` owned exact-38 and application-schema global exact-110 ACL manifests pass, and is revoked in every other state. Migration SQL may validate and extend object ACL, but it must never create LOGIN roles, generate passwords, own the database bootstrap, or weaken this boundary.

No password, private key, client certificate, complete DSN, or machine-specific path belongs in Git. Secret management supplies distinct migration and application passwords/certificates at deploy time. Examples below use placeholders or process-memory environment variables only.

## Exact base roles

| Role | Login | Inherit | Required use |
|---|---:|---:|---|
| `aiops_migrator` | yes | no | Migration connection identity only |
| `aiops_schema_owner` | no | no | Database, trusted schema, relation and function owner |
| `aiops_control_plane_runtime` | no | no | Reviewed runtime ACL carrier only |
| `aiops_control_plane_workload` | yes | yes | Control Plane application connection identity only |

All four base roles are `NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`. Their two LOGIN roles require distinct credentials and distinct DSNs. The application DSN must never be accepted by the migration runner, and the migration DSN must never be accepted by application startup.

The only base memberships are:

- `aiops_schema_owner -> aiops_migrator`: `ADMIN FALSE`, `INHERIT FALSE`, `SET TRUE`;
- `aiops_control_plane_runtime -> aiops_control_plane_workload`: `ADMIN FALSE`, `INHERIT TRUE`, `SET FALSE`.

There is no runtime membership in `aiops_migrator` or `aiops_schema_owner`, and no migrator membership in the runtime role.

## Bootstrap order

Run this through an audited database administration channel. Load the two random LOGIN passwords from the secret manager into process memory; do not place them on a command line. A `psql` automation may use `\getenv` and quoted variables so values are never interpolated as SQL syntax:

```sql
\getenv migration_password AIOPS_BOOTSTRAP_MIGRATION_PASSWORD
\getenv application_password AIOPS_BOOTSTRAP_APPLICATION_PASSWORD

BEGIN;
CREATE ROLE aiops_migrator
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  PASSWORD :'migration_password';
CREATE ROLE aiops_schema_owner
  NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE aiops_control_plane_runtime
  NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE aiops_control_plane_workload
  LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  PASSWORD :'application_password';

GRANT aiops_schema_owner TO aiops_migrator
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
GRANT aiops_control_plane_runtime TO aiops_control_plane_workload
  WITH ADMIN FALSE, INHERIT TRUE, SET FALSE;
COMMIT;
```

### Source Gate capability identities

Before applying the A2a form of `000015`, IaC additionally preprovisions exactly two non-owner capability identities. Role/credential creation happens first；the database `CONNECT`、schema `USAGE` and function ACL shown below are an A2a cutover target, not permissions that the pre-A2a capability harness may activate against the exact-36 application schema。

| Role | Login | Inherit | Required use |
|---|---:|---:|---|
| `aiops_source_gate_sealer` | yes | no | Receipt-seal typed executor only |
| `aiops_source_gate_admitter` | yes | no | Gate-admit typed executor only |

Both are `NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`, have no membership edges, and use distinct short-lived credentials/DSNs that are also distinct from migration and ordinary application credentials. They are not base ACL carriers or extension owners. The Worker outcome sink receives only the sealer connector; the Control Plane gate path receives only the admitter connector. Neither connector may be placed in a general Repository pool or shared across binaries.

```sql
\getenv source_gate_seal_password AIOPS_BOOTSTRAP_SOURCE_GATE_SEAL_PASSWORD
\getenv source_gate_admit_password AIOPS_BOOTSTRAP_SOURCE_GATE_ADMIT_PASSWORD

BEGIN;
CREATE ROLE aiops_source_gate_sealer
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  PASSWORD :'source_gate_seal_password';
CREATE ROLE aiops_source_gate_admitter
  LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  PASSWORD :'source_gate_admit_password';
COMMIT;
```

Create the application database outside that transaction because PostgreSQL prohibits `CREATE DATABASE` in a transaction block:

```sql
CREATE DATABASE <application_database> OWNER aiops_schema_owner TEMPLATE template0;
```

From a different administrative database, switch to the database owner and establish only the exact pre-A2a database ACL. Capability roles are explicitly kept disconnected:

```sql
SET ROLE aiops_schema_owner;
REVOKE ALL ON DATABASE <application_database> FROM PUBLIC;
REVOKE ALL ON DATABASE <application_database> FROM aiops_source_gate_sealer;
REVOKE ALL ON DATABASE <application_database> FROM aiops_source_gate_admitter;
GRANT CONNECT ON DATABASE <application_database> TO aiops_migrator;
GRANT CONNECT ON DATABASE <application_database> TO aiops_control_plane_workload;
RESET ROLE;
```

Connect to the new application database, then establish the exact trusted `public` schema ACL, again as its owner:

```sql
ALTER SCHEMA public OWNER TO aiops_schema_owner;
SET ROLE aiops_schema_owner;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM aiops_migrator;
REVOKE ALL ON SCHEMA public FROM aiops_control_plane_workload;
REVOKE ALL ON SCHEMA public FROM aiops_source_gate_sealer;
REVOKE ALL ON SCHEMA public FROM aiops_source_gate_admitter;
GRANT CREATE, USAGE ON SCHEMA public TO aiops_schema_owner;
GRANT USAGE ON SCHEMA public TO aiops_control_plane_runtime;
RESET ROLE;
```

At this point exact-36 owned-manifest admission sees no capability database/schema ACL. Only after `000015` A2a postflight has proved both its owned exact-38 manifest and the content-addressed global exact-110 routine ACL manifest may the helper enter its grant branch, connected through the migration identity and recording `aiops_schema_owner` as semantic grantor:

```sql
BEGIN;
SET LOCAL ROLE aiops_schema_owner;
GRANT CONNECT ON DATABASE <application_database> TO aiops_source_gate_sealer;
GRANT CONNECT ON DATABASE <application_database> TO aiops_source_gate_admitter;
GRANT USAGE ON SCHEMA public TO aiops_source_gate_sealer;
GRANT USAGE ON SCHEMA public TO aiops_source_gate_admitter;
RESET ROLE;
COMMIT;
```

The helper must then run full owned-exact-38/global-exact-110 schema/role/capability admission before exposing either connector. For exact-36、successful A2a down、unknown、partial or ambiguous owned/global state, it instead runs the fail-closed branch and proves both identities absent from database/schema ACL；unknown/partial additionally returns `asset_catalog_unavailable` after revocation:

```sql
BEGIN;
SET LOCAL ROLE aiops_schema_owner;
REVOKE ALL ON SCHEMA public FROM aiops_source_gate_sealer;
REVOKE ALL ON SCHEMA public FROM aiops_source_gate_admitter;
REVOKE ALL ON DATABASE <application_database> FROM aiops_source_gate_sealer;
REVOKE ALL ON DATABASE <application_database> FROM aiops_source_gate_admitter;
RESET ROLE;
COMMIT;
```

After the owned-exact-38/global-exact-110 grant branch, the resulting database ACL is exactly owner `CONNECT+CREATE+TEMPORARY`, migrator/workload/sealer/admitter each direct `CONNECT`, and nothing for PUBLIC/runtime. The direct schema ACL is exactly owner `CREATE+USAGE`, runtime/sealer/admitter `USAGE`, and nothing for PUBLIC/migrator/workload. Workload receives schema `USAGE` only through inherited runtime membership. No LOGIN identity receives database `CREATE` or `TEMP`, and the schema owner remains the sole persistent schema `CREATE` holder. CI/local/recovery must exercise initial predecessor72+owned36、up→global110/owned38、down→restored predecessor72、re-up、partial/unknown、unexpected111 and wrong predecessor ACL reconciliation so no capability grant or PUBLIC hardening drift survives。

## Migration admission

Each migration connection is fresh, dedicated, and non-pooled. Before `BEGIN`, the runner must prove:

```sql
SELECT session_user, current_user;
```

Both values must equal `aiops_migrator`. The runner separately verifies all role flags, both exact memberships, database owner/ACL and trusted schema owner/ACL. It then starts the reviewed transaction, runs `SET LOCAL ROLE aiops_schema_owner`, executes only the owned migration, runs `RESET ROLE`, and commits. Any preflight, role switch, migration, postflight, reset, or commit ambiguity destroys the connection and fails closed.

Migration `000012_outbox_event_routing` is the sole reviewed nontransactional exception. Its exact concurrent index statement runs on its own fresh migrator connection after the same identity check and `SET ROLE aiops_schema_owner`; exact OID/definition/state postflight and connection destruction remain mandatory. This exception cannot be generalized into arbitrary DDL.

## Application and capability admission

The Control Plane ordinary Repository pool uses only the application DSN；the Source Gate admit path separately holds the isolated admitter connector defined above and never exposes it to that pool. `DatabaseRoleAdmission.Check` is fixed to the application probe and requires:

```text
session_user = current_user = aiops_control_plane_workload
```

The existing exact-36 application probe remains unchanged：it validates only the four base roles、two base memberships、exact-36 database/schema and relation/column/function ACL plus semantic grantor/multiplicity in one read-only repeatable-read snapshot。The capability-identity harness does not own or extend this production file；it uses its control/admin fixture path to prove the two new role identities/flags、no membership、pairwise-distinct credentials、application ACL absent and actual connection rejection。Formal A2a owns the version-matched extension：the application probe then validates all six reviewed identities while accepting only owned exact-36 with predecessor exact-72 normalized ACL, or owned exact-38 with global exact-110 hardened ACL. The workload may inherit `aiops_control_plane_runtime`; it cannot `SET ROLE` to runtime, migrator, schema owner, sealer or admitter. The isolated gate connector is unreachable through ordinary Repository construction.

Only formal A2a adds the two fixed capability probes，and they run only after owned exact-38/global exact-110 postflight/grant。They separately require `session_user=current_user=aiops_source_gate_sealer` or `aiops_source_gate_admitter`，reject membership、role switching、relation/sequence privilege、the other routine、inherited runtime ACL、`TEMP|CREATE` or a wrong direct grantor。Bootstrap/config/harness admission separately proves that all four LOGIN credentials and DSNs are pairwise distinct without claiming the future probes。A missing、unknown、duplicate、unexpected 111th、overload、grantable、wrong-grantor or PUBLIC ACL returns only `asset_catalog_unavailable`.

## Object ACL after `000015`

All twelve Asset Catalog relations and all `000015` functions are owned by `aiops_schema_owner`. The owned routine manifest remains exact 38（existing 36 + new 2）；the application-schema global manifest is content-addressed exact 110，formed from the fixed `000001..000014` predecessor exact 72 plus Asset exact 38. Authority inspection finds 78 definitions、6 same-identity replacements、72 final identities（68 trigger + 4 helper）and no predecessor direct grant；normalized pre-up ACL is owner+PUBLIC `EXECUTE` on all72. The predecessor manifest is `C`-sorted by canonical signature、owner、grantor and grantability；it is never an arbitrary runtime snapshot. A2a up must validate that exact identity/ACL set before DDL，then explicitly enumerate PUBLIC EXECUTE revocation for all predecessor 72 and owned 38；`ON ALL FUNCTIONS IN SCHEMA` is forbidden. Unknown 73rd/111th、missing、overload、owner/grantor/grantability or ACL drift rolls back the entire migration and is never repaired opportunistically.

After Source Gate A2a, runtime receives the reviewed relation/column privileges、Asset18 function edges and newly frozen predecessor exact72 direct `EXECUTE` manifest。The only C-order identities and production expected digest are defined by [Pack06 canonical predecessor exact72 runtime EXECUTE manifest](../superpowers/plans/2026-07-13-governed-operations/01-assets/06-source-external-cmdb.md#canonical-predecessor-exact72-runtime-execute-manifest)；this runbook does not copy the list。Migration、application admission and exact-12 test must explicitly match every listed signature and embed that constant rather than derive-and-accept a runtime snapshot。PUBLIC is absent from global110；owner110、runtime direct/effective90、workload direct0/effective90，migrator0 without its separate SET-only owner path。Seal remains sealer-only，admit remains admitter-only；both have predecessor0 and no relation/sequence ACL。Down first revokes added runtime72 edges，then removes owned38 and restores PUBLIC72 so catalog/owner/ACL equals pre-up；schema-wide grant/revoke and unknown-object restoration are forbidden.

The four predecessor read surfaces are exactly `workspaces`, `environments`, `services`, and `service_bindings`; runtime gets `SELECT` there and no direct ACL on `tenants` or `integrations`. It receives no `UPDATE`, grant option, or direct row-lock capability on `services`/`service_bindings`：direct `FOR KEY SHARE|FOR SHARE|FOR UPDATE` must return `42501`。All three entry points are strict、non-overloaded、`VOLATILE PARALLEL UNSAFE SECURITY DEFINER` functions owned by `aiops_schema_owner` with `search_path=pg_catalog, public, pg_temp` and require a `SERIALIZABLE READ WRITE` transaction。The parent-lock function keeps exact Service→legacy binding locking。The Source Gate functions both lock target Run→receipt/UUID-ordered prior Runs→Source→published Revision and append Audit/Outbox last；on a first-write seal，the sealer executor obtains `pg_catalog.transaction_timestamp()` in that same transaction、uses its fixed-six UTC value as the only issued time for signing，and the primitive requires exact equality before enforcing `expires_at <= issued_at + interval '24 hours'`、cleanup-time ordering and prior-HA expiry；an exact already-committed response-loss replay is recognized before this first-write time guard and remains zero-write，while changed replay rejects。Seal then derives receipt/HA、fixed terminal/capacity/fence closure plus `TERMINAL_COMMITTED` Audit after durable `REVOKED` cleanup；admit compares Source version/gate revision and derives pointer/status/epoch/open Audit/Outbox，never caller decision or payload。Each function also rejects a `session_user` other than its exact capability identity.

Runtime gets no relation-level `INSERT|UPDATE` on `asset_sources` or `asset_source_runs` after A2a。Source column grants exclude all three pointer columns。Run INSERT includes legacy initial columns plus exact seven immutable qualification queue-binding columns；the other sixteen protected columns have no INSERT。Run UPDATE includes only legacy lifecycle columns；all twenty-three qualification/HA columns have no UPDATE。Thus Source pointer direct INSERT/UPDATE、Run protected direct UPDATE and non-queue protected direct INSERT return `42501`。Runtime otherwise gets the reviewed existing Asset relation grants，`SELECT,INSERT` on `asset_source_limit_buckets` plus column-only `UPDATE(next_token_at,last_receipt_id,version,updated_at)`，and `SELECT,INSERT` on append-only `asset_source_limit_permits`；it gets no table-wide bucket UPDATE and no permit UPDATE。Audit/Outbox use the reviewed column-level INSERT/UPDATE surfaces。Asset/Audit/Outbox/Limiter `DELETE` and `TRUNCATE`、unlisted columns、database/schema `CREATE` and TEMP remain absent。

## Extension-owner ABI

The base extension-owner manifest is empty. A later owned migration may preprovision one reviewed extension owner only through IaC and must add exactly one migrator SET-only edge for that migration. Such a role is `NOLOGIN NOINHERIT` with all five dangerous flags disabled, no base membership, no committed schema `CREATE`, and only its reviewed typed-table/procedure/pure-helper rights. Task 1 does not name a Phase 3 owner. Trigger, transition and base-mutation execution is always forbidden.

## Verification and drift response

Admission compares semantic ACL from `pg_catalog.aclexplode(COALESCE(acl, pg_catalog.acldefault(...)))`; it does not compare cluster-local OIDs. Operators must verify owner/grantee/grantor labels, privilege, grantability and multiplicity, plus membership `admin_option`, `inherit_option` and `set_option`. Never treat `has_*_privilege` alone as sufficient evidence because inherited or PUBLIC access can hide a direct ACL drift.

After bootstrap, migration, restore, failover or credential rotation, select the branch from the admitted schema manifest and complete every applicable check before serving traffic:

1. migration identity admission on the migration DSN before `BEGIN`;
2. `000001..000015` migration postflight as `aiops_schema_owner` through the SET-only edge，classifying only predecessor72+owned36 or global110+owned38 and treating unknown/partial as unavailable;
3. reconcile before any ordinary admission：initial/down state proves exact predecessor72 normalized ACL and capability connection rejection；up state proves global110 hardening before owner grant and both fixed capability probes；unknown/partial revokes capability ACL，proves absence/rejection and returns unavailable;
4. rerun ordinary application `DatabaseRoleAdmission.Check` only for one reconciled exact state；every grant/revoke invalidates earlier admission evidence;
5. run initial/up/down/up/partial/unexpected111/wrong-predecessor integration、runtime exact72 edge count/hash、application-identity key DML/trigger/four-helper behavior plus required dual-instance dump/restore recovery and negative checks for PUBLIC、TEMP、membership、grantor/grantability、overload、wrong-version/extra/cross-function ACL and role switching;
6. expose a capability connector only for owned exact-38/global exact-110 after all checks pass；the predecessor state exposes only ordinary application traffic and keeps Source Gate capabilities closed.

Every future `000016..000022` migration that adds or replaces a `public` routine must update the content-addressed global manifest、explicit PUBLIC revoke and rollback contract。An unknown routine or a future public routine without explicit PUBLIC revoke closes admission。

Any drift leaves the application unavailable. Do not repair it by granting superuser, broad role membership, PUBLIC privileges, TEMP, database/schema CREATE, `SET ROLE` to workload, or by reusing one DSN for both identities. Correct IaC to the exact manifest, rotate affected credentials if necessary, rerun admission, and preserve the failed evidence for audit.

## Rotation, backup and rollback

Rotate migration、application、sealer and admitter credentials independently. Issue certificates with exact role identities, update the secret manager and database password atomically, and drain only the matching pool。For a capability identity，the predecessor72/owned36 state proves the new credential only through control-database login/role evidence while application-database connection remains rejected；global110/owned38 requires its full fixed probe before revoking the old credential。Never print a password or complete DSN during rotation.

Backups preserve owner and object ACL records. Restore into a clean database preprovisioned with the predecessor72/owned36 state，using non-superuser `pg_restore --single-transaction --role=aiops_schema_owner`; after restore, require the exact global110/owned38 manifest、conditional capability reconciliation and full admission before exposure。The A2a dual-instance dump/restore test is required G2 because this contract changes archived ACL and down restoration semantics。`--no-owner`, `--no-acl`, `--disable-triggers`, ownership rewriting and superuser restore are forbidden；a non-`--create` archive never substitutes for database-level ACL reconciliation.

Rollback of `000015` requires its empty-state guard、explicit revocation of the A2a-added runtime exact72 direct edges and exact predecessor72 normalized PUBLIC EXECUTE restoration；the post-down catalog/owner/ACL must equal pre-up exactly. Role deletion is a separate IaC operation and is allowed only after every application database, membership, owned object, active session and Secret reference has been proven absent. A failed or ambiguous rollback preserves the roles and closes admission; it never falls back to a shared administrator DSN.
