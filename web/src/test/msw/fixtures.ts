import type { components } from "@/shared/api/schema";

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
  workspace_ids: ["33333333-3333-4333-8333-333333333333"],
  environment_ids: ["44444444-4444-4444-8444-444444444444"],
  service_ids: [],
  authenticated_at: "2026-07-17T00:00:00Z",
  expires_at: "2026-07-17T01:00:00Z",
};
