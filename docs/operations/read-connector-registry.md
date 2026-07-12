# READ Connector Registry

The READ connector registry is the immutable admission contract shared by
Investigation task creation, Runner Gateway start authorization, typed Evidence
completion, and the future READ Runner executor. It contains no credentials,
HTTP headers, arbitrary command material, or network client.

This milestone does **not** wire the registry into the live Control Plane.
`ClaimsEnabled` remains `false`, and the existing disabled start/completion
callbacks remain installed. This also prevents an old lease from advancing
during a rolling upgrade. A later assembly milestone may replace those gates
only after the READ Runner, Temporal dispatch, target manifest, and registry
digest checks are ready together.

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
      "connector_id": "prometheus-staging-health-v1-83004ffac7bfe4e53c40492220072dd08343bbbfddd0d3851de2de1378a6cf11",
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
      "connector_id": "victorialogs-staging-errors-v1-e011d6bc0557c71650569feeee89d1853f9b0027610578e6fd15982b75be0bd2",
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
kind/operation, fixed query, projection, budgets, and validator-v1 profile.
Changing any of those values while retaining the old ID fails registry loading.
Validator-v1 semantics are frozen; a semantic validator change requires a new
profile/version and retention of the old executor until its tasks are terminal.

`target_ref` is a low-cardinality opaque content-address-shaped reference. It is
not a URL or a secret. This milestone validates its canonical form but cannot
yet recompute the suffix because the target contract is intentionally held by
the future READ Runner target manifest. That loader must hash the fixed HTTPS
endpoint identity, explicit CA, credential/role reference, redirect/proxy
policy, and network-policy profile (but not rotating Secret bytes), and require
the suffix to match before readiness can succeed. Until that check exists,
claims remain disabled. The target manifest and its secrets must never enter
Task input, claim responses, Evidence, Temporal History, logs, or audit events.

## File and rollout requirements

`LoadFile` accepts only a clean absolute path. It opens without following
symlinks, requires a regular file owned by the process user, rejects group/world
writable permissions, limits the file to 1 MiB, rejects unknown/duplicate JSON
fields and trailing documents, and never echoes path or manifest content in an
error.

The registry digest covers exact scope, connector ID, operation, target
reference, fixed query, output projection, and budgets; it excludes actual
credentials. Gateway and READ Runner must advertise the same digest before
claims can be enabled. A mismatch is a startup failure, not a partial registry
fallback.

The current READ heartbeat revalidates Runner identity/scope but does not yet
re-run connector admission. Removing a definition while an attempt is already
`RUNNING` can therefore allow reads until that short lease expires, although
typed completion will reject its Evidence. Before claims are enabled, the
assembly path must bind the attempt's contract/target digest into heartbeat
authorization, or atomically cancel and drain all affected attempts; mixed
registry versions remain forbidden.

Prometheus v1 accepts matrix samples only; native histograms fail the task.
VictoriaLogs v1 accepts only configured primitive fields and requires canonical
UTC `_time`. A connector result marked truncated must be completed as
`FAILED/result_rejected`; it must never be represented as complete Evidence.

Production writes remain unavailable. This registry is READ-only and does not
alter `AIOPS_WRITE_EXECUTION_MODE`, WRITE Runner policy, or the production write
roadmap gate.
