import type { components } from "@/shared/api/schema";

export const workspaceID = "33333333-3333-4333-8333-333333333333";
export const environmentID = "44444444-4444-4444-8444-444444444444";
export const primaryAssetID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
export const secondaryAssetID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
export const manualSourceID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
export const serviceID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
export const assetConflictID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
export const discoverySourceID = "16161616-1616-4161-8161-161616161616";
export const sourceRunID = "17171717-1717-4171-8171-171717171717";

export const browserConfigFixture: components["schemas"]["BrowserConfig"] = {
  oidc: {
    url: "https://identity.example.com",
    realm: "aiops",
    client_id: "control-plane-web",
  },
  api_base_path: "/api/v1",
  build: {
    version: "test",
    commit: "test-commit",
    contract_digest: `sha256:${"0".repeat(64)}`,
  },
};

export const sessionFixture: components["schemas"]["Session"] = {
  subject: "test-operator",
  username: "测试操作员",
  roles: ["VIEWER"],
  workspace_ids: [workspaceID],
  environment_ids: [environmentID],
  service_ids: [serviceID],
  authenticated_at: "2026-07-17T00:00:00Z",
  expires_at: "2026-07-17T01:00:00Z",
};

export const assetSummaryFixture: components["schemas"]["AssetSummary"] = {
  id: primaryAssetID,
  environment_id: environmentID,
  display_name: "payments-api-01",
  external_id: "payments-api-01.example",
  kind: "LINUX_VM",
  provider_kind: "MANUAL_V1",
  source: {
    id: manualSourceID,
    name: "生产手工登记源",
    kind: "MANUAL",
  },
  service_summaries: [
    {
      id: serviceID,
      name: "payments",
      role: "PRIMARY_RUNTIME",
    },
  ],
  mapping_status: "EXACT",
  lifecycle: "ACTIVE",
  owner_group: "sre-payments",
  criticality: "HIGH",
  data_classification: "INTERNAL",
  labels: [{ key: "region", value: "cn-east-1" }],
  connection_summary: { status: "NOT_CONFIGURED" },
  capability_summary: { status: "NOT_CONFIGURED", count: 0 },
  last_observed_at: "2026-07-17T00:20:00Z",
  version: 7,
  effective_actions: ["EDIT_GOVERNANCE", "QUARANTINE", "RETIRE"],
};

export const secondaryAssetSummaryFixture: components["schemas"]["AssetSummary"] = {
  ...assetSummaryFixture,
  id: secondaryAssetID,
  display_name: "orders-db-01",
  external_id: "orders-db-01.example",
  kind: "DATABASE_INSTANCE",
  owner_group: "sre-orders",
  criticality: "CRITICAL",
  labels: [{ key: "region", value: "cn-north-1" }],
  version: 3,
};

export const assetPageFixture: components["schemas"]["AssetPage"] = {
  items: [assetSummaryFixture, secondaryAssetSummaryFixture],
  page: { next_cursor: "cursor-next-page" },
  effective_actions: ["CREATE_ASSET"],
};

export const assetDetailFixture: components["schemas"]["AssetDetail"] = {
  ...assetSummaryFixture,
  field_provenance: [
    {
      field_code: "display_name",
      source_id: manualSourceID,
      provider_kind: "MANUAL_V1",
      source_revision: 1,
      observed_at: "2026-07-17T00:20:00Z",
      provider_path_code: "manual.display_name",
      confidence: 100,
      ownership: "SOURCE",
    },
    {
      field_code: "owner_group",
      source_id: manualSourceID,
      provider_kind: "MANUAL_V1",
      source_revision: 1,
      observed_at: "2026-07-17T00:20:00Z",
      provider_path_code: "governance.owner_group",
      confidence: 100,
      ownership: "GOVERNANCE",
    },
  ],
  relation_counts: { incoming: 1, outgoing: 1 },
};

export const secondaryAssetDetailFixture: components["schemas"]["AssetDetail"] = {
  ...assetDetailFixture,
  ...secondaryAssetSummaryFixture,
  field_provenance: assetDetailFixture.field_provenance.map((field) => ({
    ...field,
    field_code:
      field.field_code === "display_name"
        ? "display_name"
        : "owner_group",
  })),
};

const emptyRunCounts: components["schemas"]["SourceRunCounts"] = {
  observed: 0,
  created: 0,
  changed: 0,
  unchanged: 0,
  conflicts: 0,
  missing: 0,
  stale: 0,
  restored: 0,
  tombstoned: 0,
  rejected: 0,
};

export const lastSuccessRunCountsFixture: components["schemas"]["SourceRunCounts"] = {
  ...emptyRunCounts,
  observed: 12,
  created: 2,
  changed: 3,
  unchanged: 7,
  conflicts: 1,
};

export const currentRunCountsFixture: components["schemas"]["SourceRunCounts"] = {
  ...emptyRunCounts,
  observed: 19,
  created: 7,
  changed: 4,
  unchanged: 8,
  conflicts: 2,
  missing: 1,
};

export const manualSourceFixture: components["schemas"]["AssetSourceSummary"] = {
  id: manualSourceID,
  name: "生产手工登记源",
  kind: "MANUAL",
  provider_kind: "MANUAL_V1",
  status: "ACTIVE",
  gate_status: "AVAILABLE",
  gate_reason_code: null,
  gate_revision: 2,
  published_revision: 1,
  published_revision_digest: "1".repeat(64),
  checkpoint_sha256: null,
  checkpoint_version: 0,
  last_success_run_id: null,
  last_success_at: null,
  last_complete_snapshot_run_id: null,
  last_complete_snapshot_at: null,
  current_run_counts: null,
  last_run_counts: emptyRunCounts,
  version: 2,
  created_at: "2026-07-16T00:00:00Z",
  updated_at: "2026-07-17T00:00:00Z",
  effective_actions: ["CREATE_ASSET"],
};

export const discoverySourceFixture: components["schemas"]["AssetSourceSummary"] = {
  id: discoverySourceID,
  name: "生产 CMDB 目录",
  kind: "EXTERNAL_CMDB",
  provider_kind: "CMDB_CATALOG_V1",
  status: "DEGRADED",
  gate_status: "SUSPENDED",
  gate_reason_code: "source_gate_suspended",
  gate_revision: 8,
  published_revision: 4,
  published_revision_digest: "8".repeat(64),
  checkpoint_sha256: "9".repeat(64),
  checkpoint_version: 18,
  last_success_run_id: sourceRunID,
  last_success_at: "2026-07-17T00:20:00Z",
  last_complete_snapshot_run_id: sourceRunID,
  last_complete_snapshot_at: "2026-07-17T00:20:00Z",
  current_run_counts: currentRunCountsFixture,
  last_run_counts: lastSuccessRunCountsFixture,
  version: 9,
  created_at: "2026-07-15T00:00:00Z",
  updated_at: "2026-07-17T00:25:00Z",
  effective_actions: [],
};

export const assetSourcePageFixture: components["schemas"]["AssetSourcePage"] = {
  items: [manualSourceFixture, discoverySourceFixture],
  page: { next_cursor: null },
  effective_actions: [],
};

export const assetSourceDetailFixture: components["schemas"]["AssetSourceDetail"] = {
  summary: discoverySourceFixture,
  latest_revision: {
    revision: 4,
    status: "PUBLISHED",
    profile_code: "CMDB_CATALOG_V1",
    integration_id: "18181818-1818-4181-8181-181818181818",
    sync_mode: "SCHEDULED",
    credential_reference_id:
      "19191919-1919-4191-8191-191919191919",
    trust_reference_id: "20202020-2020-4202-8202-202020202020",
    network_policy_reference_id:
      "21212121-2121-4212-8212-212121212121",
    authority_environment_ids: [environmentID],
    binding_digest: "8".repeat(64),
    source_definition_digest: "a".repeat(64),
    version: 4,
    created_at: "2026-07-16T00:00:00Z",
    updated_at: "2026-07-16T00:30:00Z",
    effective_actions: [],
  },
  published_revision: {
    revision: 4,
    status: "PUBLISHED",
    profile_code: "CMDB_CATALOG_V1",
    integration_id: "18181818-1818-4181-8181-181818181818",
    sync_mode: "SCHEDULED",
    credential_reference_id:
      "19191919-1919-4191-8191-191919191919",
    trust_reference_id: "20202020-2020-4202-8202-202020202020",
    network_policy_reference_id:
      "21212121-2121-4212-8212-212121212121",
    authority_environment_ids: [environmentID],
    binding_digest: "8".repeat(64),
    source_definition_digest: "a".repeat(64),
    version: 4,
    created_at: "2026-07-16T00:00:00Z",
    updated_at: "2026-07-16T00:30:00Z",
    effective_actions: [],
  },
};

export const sourceRunFixture: components["schemas"]["AssetSourceRun"] = {
  id: sourceRunID,
  source_id: discoverySourceID,
  source_revision: 4,
  source_revision_digest: "8".repeat(64),
  kind: "DISCOVERY",
  status: "SUCCEEDED",
  stage: "COMPLETED",
  stage_changed_at: "2026-07-17T00:20:00Z",
  trigger_type: "SCHEDULED",
  gate_revision: 6,
  page_sequence: 3,
  relation_page_sequence: 3,
  cursor_before_sha256: "b".repeat(64),
  cursor_after_sha256: "9".repeat(64),
  checkpoint_version: 18,
  not_before: "2026-07-17T00:10:00Z",
  final_page: true,
  complete_snapshot: true,
  effective_complete_snapshot: true,
  work_result_kind: "DATA_PROJECTION",
  work_result_status: "SUCCEEDED",
  work_result_digest: "c".repeat(64),
  work_result_recorded_at: "2026-07-17T00:19:00Z",
  validation_outcome: null,
  validation_proof_digest: null,
  credential_cleanup_status: "REVOKED",
  counts: lastSuccessRunCountsFixture,
  failure_code: null,
  trace_id: "d".repeat(32),
  version: 11,
  created_at: "2026-07-17T00:10:00Z",
  started_at: "2026-07-17T00:11:00Z",
  heartbeat_at: "2026-07-17T00:18:00Z",
  completed_at: "2026-07-17T00:20:00Z",
  effective_actions: [],
};

export const assetRelationPageFixture: components["schemas"]["AssetRelationPage"] = {
  items: [
    {
      id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
      source_environment_id: environmentID,
      target_environment_id: environmentID,
      source_asset_id: primaryAssetID,
      target_asset_id: secondaryAssetID,
      type: "DEPENDS_ON",
      status: "ACTIVE",
      provenance: "MANUAL",
      source_id: manualSourceID,
      source_revision: 1,
      last_run_id: "ffffffff-ffff-4fff-8fff-ffffffffffff",
      last_page_sequence: 1,
      accepted_checkpoint_version: 0,
      run_fence_epoch: 1,
      provider_version_sha256: "2".repeat(64),
      relation_fact_sha256: "3".repeat(64),
      version: 1,
      updated_at: "2026-07-17T00:20:00Z",
    },
  ],
  page: { next_cursor: null },
};

export const assetMutationResultFixture: components["schemas"]["AssetMutationResult"] = {
  asset: assetDetailFixture,
  mutation_receipt: {
    audit_id: "12121212-1212-4121-8121-121212121212",
    trace_id: "4".repeat(32),
    idempotent_replay: false,
  },
};

export const assetConflictFixture: components["schemas"]["AssetConflictDetail"] = {
  id: assetConflictID,
  environment_id: environmentID,
  asset: {
    id: primaryAssetID,
    display_name: assetSummaryFixture.display_name,
    kind: assetSummaryFixture.kind,
    lifecycle: "DISCOVERED",
  },
  candidate_asset: {
    id: secondaryAssetID,
    display_name: secondaryAssetSummaryFixture.display_name,
    kind: secondaryAssetSummaryFixture.kind,
    lifecycle: "DISCOVERED",
  },
  candidate_service: {
    id: serviceID,
    name: "payments",
  },
  source_id: manualSourceID,
  observation: {
    id: "14141414-1414-4141-8141-141414141414",
    source_id: manualSourceID,
    source_revision: 1,
    observed_at: "2026-07-17T00:20:00Z",
  },
  type: "FIELD_CONFLICT",
  field_name: "display_name",
  existing_value_sha256: "5".repeat(64),
  candidate_value_sha256: "6".repeat(64),
  status: "OPEN",
  resolution: null,
  resolution_reason_code: null,
  resolved_at: null,
  impact_counts: {
    asset_active_bindings: 1,
    asset_active_relationships: 1,
    candidate_asset_active_bindings: 1,
    candidate_asset_active_relationships: 0,
    candidate_service_active_bindings: 1,
  },
  version: 5,
  etag: `"asset-conflict:${assetConflictID}:v5"`,
  created_at: "2026-07-16T00:00:00Z",
  updated_at: "2026-07-17T00:20:00Z",
  effective_actions: ["RESOLVE_CONFLICT"],
};

export const assetConflictPageFixture: components["schemas"]["AssetConflictPage"] = {
  items: [assetConflictFixture],
  page: { next_cursor: null },
};

export const assetConflictMutationResultFixture: components["schemas"]["AssetConflictMutationResult"] = {
  conflict: {
    ...assetConflictFixture,
    status: "RESOLVED",
    resolution: "CONFIRM_EXACT",
    resolution_reason_code: "SERVICE_OWNER_VERIFIED",
    resolved_at: "2026-07-17T00:30:00Z",
    version: 6,
    etag: `"asset-conflict:${assetConflictID}:v6"`,
    effective_actions: [],
  },
  binding: null,
  mutation_receipt: {
    audit_id: "15151515-1515-4151-8151-151515151515",
    trace_id: "7".repeat(32),
    idempotent_replay: false,
  },
};
