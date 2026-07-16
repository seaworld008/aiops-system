# PostgreSQL Database Role Bootstrap

This runbook is the sole bootstrap/IaC truth for the base PostgreSQL role ABI consumed by Asset Catalog migration `000015`. It provisions identities and database/schema ACL before any application migration. Migration SQL may validate and extend object ACL, but it must never create LOGIN roles, generate passwords, own the database bootstrap, or weaken this boundary.

No password, private key, client certificate, complete DSN, or machine-specific path belongs in Git. Secret management supplies distinct migration and application passwords/certificates at deploy time. Examples below use placeholders or process-memory environment variables only.

## Exact base roles

| Role | Login | Inherit | Required use |
|---|---:|---:|---|
| `aiops_migrator` | yes | no | Migration connection identity only |
| `aiops_schema_owner` | no | no | Database, trusted schema, relation and function owner |
| `aiops_control_plane_runtime` | no | no | Reviewed runtime ACL carrier only |
| `aiops_control_plane_workload` | yes | yes | Control Plane application connection identity only |

All four roles are `NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`. The two LOGIN roles require distinct credentials and distinct DSNs. The application DSN must never be accepted by the migration runner, and the migration DSN must never be accepted by application startup.

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

Create the application database outside that transaction because PostgreSQL prohibits `CREATE DATABASE` in a transaction block:

```sql
CREATE DATABASE <application_database> OWNER aiops_schema_owner TEMPLATE template0;
```

From a different administrative database, switch to the database owner so every semantic ACL row records `aiops_schema_owner` as grantor:

```sql
SET ROLE aiops_schema_owner;
REVOKE ALL ON DATABASE <application_database> FROM PUBLIC;
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
GRANT CREATE, USAGE ON SCHEMA public TO aiops_schema_owner;
GRANT USAGE ON SCHEMA public TO aiops_control_plane_runtime;
RESET ROLE;
```

The resulting database ACL is exactly owner `CONNECT+CREATE+TEMPORARY`, migrator `CONNECT`, workload `CONNECT`, and nothing for PUBLIC/runtime. The direct schema ACL is exactly owner `CREATE+USAGE` and runtime `USAGE`; PUBLIC/migrator/workload have none. Workload receives schema `USAGE` only through inherited runtime membership. Neither LOGIN identity receives database `CREATE` or `TEMP`, and the schema owner remains the sole persistent schema `CREATE` holder.

## Migration admission

Each migration connection is fresh, dedicated, and non-pooled. Before `BEGIN`, the runner must prove:

```sql
SELECT session_user, current_user;
```

Both values must equal `aiops_migrator`. The runner separately verifies all role flags, both exact memberships, database owner/ACL and trusted schema owner/ACL. It then starts the reviewed transaction, runs `SET LOCAL ROLE aiops_schema_owner`, executes only the owned migration, runs `RESET ROLE`, and commits. Any preflight, role switch, migration, postflight, reset, or commit ambiguity destroys the connection and fails closed.

Migration `000012_outbox_event_routing` is the sole reviewed nontransactional exception. Its exact concurrent index statement runs on its own fresh migrator connection after the same identity check and `SET ROLE aiops_schema_owner`; exact OID/definition/state postflight and connection destruction remain mandatory. This exception cannot be generalized into arbitrary DDL.

## Application admission

The Control Plane uses only the application DSN. `DatabaseRoleAdmission.Check` is fixed to the application probe and requires:

```text
session_user = current_user = aiops_control_plane_workload
```

It validates the four roles, two memberships, database/schema ACL, exact relation/column/function ACL and semantic grantor/multiplicity in one read-only repeatable-read snapshot. The workload may inherit `aiops_control_plane_runtime`; it cannot `SET ROLE` to runtime, migrator, or schema owner. A missing, unknown, duplicate, extra, grantable, wrong-grantor, or default PUBLIC ACL returns only `asset_catalog_unavailable`.

## Object ACL after `000015`

All twelve Asset Catalog relations and all ordinary functions are owned by `aiops_schema_owner`. Runtime receives only the reviewed relation/column privileges, the exact 17 pure function signatures, and the one fixed `public.asset_catalog_lock_exact_service_binding(uuid,uuid,uuid,uuid)` entry point. PUBLIC function `EXECUTE` is revoked on all 36 functions. Trigger/transition routines remain owner-only. Workload has no direct object ACL and consumes only inherited runtime rights.

The four predecessor read surfaces are exactly `workspaces`, `environments`, `services`, and `service_bindings`; runtime gets `SELECT` there and no direct ACL on `tenants` or `integrations`. It receives no `UPDATE`, grant option, or direct row-lock capability on `services`/`service_bindings`：direct `FOR KEY SHARE|FOR SHARE|FOR UPDATE` must return `42501`。The sole parent-lock path is the strict、non-overloaded、`VOLATILE PARALLEL UNSAFE SECURITY DEFINER` function above, owned by `aiops_schema_owner` with `search_path=pg_catalog, public, pg_temp`; it requires a `SERIALIZABLE READ WRITE` transaction and locks exact Service `FOR KEY SHARE` before exact legacy binding `FOR SHARE`, requiring `mapping_status='EXACT'`.

Runtime gets `SELECT,INSERT` on `asset_source_limit_buckets` plus column-only `UPDATE(next_token_at,last_receipt_id,version,updated_at)` and `SELECT,INSERT` on append-only `asset_source_limit_permits`; it gets no table-wide bucket UPDATE and no permit UPDATE. Audit/Outbox use the reviewed column-level INSERT/UPDATE surfaces. Asset/Audit/Outbox/Limiter `DELETE` and `TRUNCATE`, unlisted columns, database/schema `CREATE`, and TEMP remain absent.

## Extension-owner ABI

The base extension-owner manifest is empty. A later owned migration may preprovision one reviewed extension owner only through IaC and must add exactly one migrator SET-only edge for that migration. Such a role is `NOLOGIN NOINHERIT` with all five dangerous flags disabled, no base membership, no committed schema `CREATE`, and only its reviewed typed-table/procedure/pure-helper rights. Task 1 does not name a Phase 3 owner. Trigger, transition and base-mutation execution is always forbidden.

## Verification and drift response

Admission compares semantic ACL from `pg_catalog.aclexplode(COALESCE(acl, pg_catalog.acldefault(...)))`; it does not compare cluster-local OIDs. Operators must verify owner/grantee/grantor labels, privilege, grantability and multiplicity, plus membership `admin_option`, `inherit_option` and `set_option`. Never treat `has_*_privilege` alone as sufficient evidence because inherited or PUBLIC access can hide a direct ACL drift.

After bootstrap, migration, restore, failover or credential rotation, run all of the following before serving traffic:

1. migration identity admission on the migration DSN before `BEGIN`;
2. `000001..000015` migration postflight as `aiops_schema_owner` through the SET-only edge;
3. application `DatabaseRoleAdmission.Check` through the workload DSN;
4. schema admission and the PostgreSQL integration/recovery gates;
5. negative checks for PUBLIC schema usage, TEMP, wrong membership options, unknown grantor, extra ACL and workload role switching.

Any drift leaves the application unavailable. Do not repair it by granting superuser, broad role membership, PUBLIC privileges, TEMP, database/schema CREATE, `SET ROLE` to workload, or by reusing one DSN for both identities. Correct IaC to the exact manifest, rotate affected credentials if necessary, rerun admission, and preserve the failed evidence for audit.

## Rotation, backup and rollback

Rotate migration and application credentials independently. Issue certificates with exact role identities, update the secret manager and database password atomically, drain old pools, then prove the new identity before revoking the old credential. Never print a password or complete DSN during rotation.

Backups preserve owner and ACL records. Restore into a clean database already owned and ACL'd by IaC, using non-superuser `pg_restore --single-transaction --role=aiops_schema_owner`; `--no-owner`, `--no-acl`, `--disable-triggers`, ownership rewriting and superuser restore are forbidden.

Rollback of `000015` requires its empty-state guard and exact predecessor ACL restoration. Role deletion is a separate IaC operation and is allowed only after every application database, membership, owned object, active session and Secret reference has been proven absent. A failed or ambiguous rollback preserves the roles and closes admission; it never falls back to a shared administrator DSN.
