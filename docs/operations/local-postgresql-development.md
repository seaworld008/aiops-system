# Local PostgreSQL 18.4 Development and Test Instance

This repository uses the workstation-managed PostgreSQL deployment at `/Volumes/soft/14-db/001-postgresql/` for required real-database tests. It is a development/test dependency, not a production deployment source.

## Fixed local facts

| Fact | Value |
|---|---|
| Docker context | `colima-aiops` |
| Container | `aiops-postgres18` |
| Immutable image baseline | `docker.io/library/postgres:18.4-alpine3.24@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15` |
| Host endpoint | `localhost:55432` |
| Safe test control database | `aiops_test` |
| Test role / client certificate CN | `aiops` |
| Server TLS | enabled, minimum and maximum TLS 1.3 |
| Server certificate identities | `postgres.aiops.internal`, `localhost`, `127.0.0.1` |

The test harness creates 128-bit randomized physical databases beneath the safe `aiops_test(_...)` naming family and only removes databases whose creation it confirmed. Do not point it at an application or production database.

## Secret and trust files

The real password is persisted outside Git at `/Volumes/soft/14-db/001-postgresql/secrets/postgres-password`. The current file is nonempty and mode `0600`. Never copy its value into `.env`, shell history, documentation, logs, issue reports or commits.

The mTLS files are:

- CA: `/Volumes/soft/14-db/001-postgresql/certs/ca.crt`
- client certificate: `/Volumes/soft/14-db/001-postgresql/certs/client.crt`
- client private key: `/Volumes/soft/14-db/001-postgresql/secrets/client.key`

`scripts/with-local-postgres.sh` validates the container image and `18.4|ssl=on|TLSv1.3` server facts, reads the password only into process memory, URL-encodes it through standard input, and exports an in-memory `AIOPS_TEST_POSTGRES_DSN` with `sslmode=verify-full`. It never prints or writes the DSN.

## Stable commands

Verify the instance and one real migration path:

```bash
make postgres-local-check
```

Run the required six-package PostgreSQL integration gate:

```bash
make test-integration-local
```

Run another command with the same protected environment:

```bash
./scripts/with-local-postgres.sh go test -race ./internal/assetcatalog/postgres -count=1
```

Override a local fact only through the documented `AIOPS_LOCAL_POSTGRES_*` variables in `.env.example`. The script deliberately fails closed on a missing/empty Secret, wrong image, stopped/unhealthy container, wrong PostgreSQL version or weaker TLS setting.

If the password file is ever missing or empty, stop first: generate a cryptographically random value, update both the external Secret and the database role atomically through the deployment's administrative recovery procedure, then rerun `make postgres-local-check`. Changing only the file or only the role will break authentication. Password rotation is an operator action and must never be implemented by silently weakening `pg_hba.conf` or TLS.
