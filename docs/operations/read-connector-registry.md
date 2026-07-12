# READ Connector Registry

The READ connector registry is the immutable admission contract shared by
Investigation task creation, Runner Gateway start authorization, typed Evidence
completion, and the fixed but currently unassembled READ HTTP executor. It contains no credentials,
HTTP headers, arbitrary command material, or network client.

This milestone does **not** wire the registry into the live Control Plane.
M5C2-4a now installs a sealed closed Admission while the existing disabled
start/heartbeat/completion callbacks remain installed. The Admission also prevents an old
lease from advancing during a rolling upgrade. Only M5C2-4c may replace those callbacks atomically, after
the READ Runner, Temporal dispatch, target/egress manifests, and component/profile
digest checks are ready together; assembly does not itself authorize claims.

## Manifest contract

Load the registry from a strict JSON file with schema version
`read-connector-registry.v1`. Each connector ID is an exact, versioned instance
ID and is bound to one trusted tenant/workspace/environment tuple. A fixed
service ID may narrow the admission further.

```json
{
  "schema_version": "read-connector-registry.v1",
  "definitions": [
    {
      "scope": {
        "tenant_id": "10000000-0000-4000-8000-000000000001",
        "workspace_id": "20000000-0000-4000-8000-000000000002",
        "environment_id": "30000000-0000-4000-8000-000000000003",
        "service_id": "40000000-0000-4000-8000-000000000004"
      },
      "connector_id": "prometheus-staging-health-v1-ef492f70edbcc1bb7a86e3f2dbdeb90c6f88281831fa66cf724259d154ba4587",
      "target_ref": "prometheus-staging-target-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "prometheus_range_query": {
        "expression": "sum(rate(http_requests_total[5m]))",
        "step_seconds": 30,
        "max_lookback_minutes": 60,
        "max_items": 100,
        "max_samples": 20000
      }
    },
    {
      "scope": {
        "tenant_id": "10000000-0000-4000-8000-000000000001",
        "workspace_id": "20000000-0000-4000-8000-000000000002",
        "environment_id": "30000000-0000-4000-8000-000000000003",
        "service_id": "40000000-0000-4000-8000-000000000004"
      },
      "connector_id": "victorialogs-staging-errors-v1-950d6da545aef76c613b33721e73e83e515ee1704bb165017530621f4ddf1e11",
      "target_ref": "victorialogs-staging-target-v1-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "victorialogs_search": {
        "query": "_stream:{app=\"payments\"} level:error",
        "limit": 100,
        "max_lookback_minutes": 60,
        "fields": [
          {"name": "_time", "type": "string", "required": true, "max_bytes": 64},
          {"name": "_msg", "type": "string", "required": true, "max_bytes": 2048},
          {"name": "status", "type": "number", "required": false}
        ]
      }
    }
  ]
}
```

Exactly one typed operation object is allowed per definition. The operation is
derived by the registry and cannot be selected freely by the manifest:

- `prometheus_range_query` maps to `range_query`;
- `victorialogs_search` maps to `search`.

A Task supplies only `{"lookback_minutes":N}`. PromQL, LogsQL, projected fields,
step, item limits, and sample limits remain server-owned. The same connector ID
cannot be reused for another environment in one tenant/workspace. Connector IDs
are full content addresses in the form `<base>-v1-<sha256>`. Use
`BuildConnectorID` to derive the ID from normalized scope, target reference,
kind/operation, fixed query, projection, budgets, and validator-v2 profile.
Changing any of those values while retaining the old ID fails registry loading.
Validator-v2 additionally rejects case-folded JSON field aliases at Task input
and typed Evidence boundaries. Validator-v1 semantics remain frozen; a semantic
validator change always requires a new profile/content address and retention of
the compatible old binary until its tasks are terminal.

`target_ref` is a low-cardinality opaque content-address-shaped reference. It is
not a URL or a secret. M5C2-3a's `read-target-manifest.v1` loader now recomputes
the suffix from the fixed HTTPS endpoint identity, explicit CA, credential-role
reference and network-policy reference (but not rotating Secret bytes).
M5C2-3b additionally resolves that policy through content-addressed
`read-egress-policy.v1` admission and a fixed one-shot executor. Claims remain
disabled until M5C2-4c assembly and separate Go/No-Go evidence pass. Target/policy
manifests and their secrets must never enter
Task input, claim responses, Evidence, Temporal History, logs, or audit events.

## File and rollout requirements

`LoadFile` accepts only a clean absolute path. It opens without following
symlinks, requires a regular file owned by the process user, rejects group/world
writable permissions, limits the file to 1 MiB, rejects unknown/duplicate JSON
fields and trailing documents, and never echoes path or manifest content in an
error.

The registry digest covers exact scope, connector ID, operation, target
reference, fixed query, output projection, and budgets; it excludes actual
credentials. C2-4c must make Gateway and READ Runner prove the same registry,
target, egress and executor profile digests before any later claim decision.
A mismatch is a startup failure, not a partial registry fallback.

READ heartbeat now revalidates Runner identity/scope and requires a trusted
server-side `HeartbeatAuthorizer` inside the same locked transaction. Every
valid next sequence and same-sequence replay must re-prove the full Bundle and
connector admission. For either legal sequence shape, rejection or panic
atomically cancels a still-current attempt and returns `TERMINATE` without
extending its lease; expired attempts stay stale and malformed jumps remain
conflicts, so neither can be revived. The production assembly must install
`Bundle.AuthorizeHeartbeat` before any future claim Go/No-Go; the current
closed Admission still rejects the request before the authorizer or READ task
mutation transaction is reached. The outer mTLS identity middleware continues
its per-request PostgreSQL registration/certificate/scope revalidation. Mixed
registry versions remain forbidden.

Prometheus v1 accepts matrix samples only; native histograms fail the task.
VictoriaLogs v1 accepts only configured primitive fields and requires canonical
UTC `_time`. A connector result marked truncated must be completed as
`FAILED/result_rejected`; it must never be represented as complete Evidence.

Production writes remain unavailable. This registry is READ-only and does not
alter `AIOPS_WRITE_EXECUTION_MODE`, WRITE Runner policy, or the production write
roadmap gate.
