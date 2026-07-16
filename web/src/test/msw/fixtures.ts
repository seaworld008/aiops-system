import type { components } from "@/shared/api/schema";

export const workspaceID = "33333333-3333-4333-8333-333333333333";
export const environmentID = "44444444-4444-4444-8444-444444444444";
export const primaryAssetID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
export const secondaryAssetID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
export const manualSourceID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
export const serviceID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";

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

export const assetSourcePageFixture: components["schemas"]["AssetSourcePage"] = {
  items: [manualSourceFixture],
  page: { next_cursor: null },
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
