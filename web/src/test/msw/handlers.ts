import { http, HttpResponse } from "msw";

import {
  assetDetailFixture,
  assetMutationResultFixture,
  assetPageFixture,
  assetRelationPageFixture,
  assetSourcePageFixture,
  browserConfigFixture,
  secondaryAssetDetailFixture,
  secondaryAssetID,
  sessionFixture,
} from "./fixtures";

const noStoreHeaders = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Trace-ID": "1".repeat(32),
};

export const handlers = [
  http.get("/api/v1/browser-config", () =>
    HttpResponse.json(browserConfigFixture, {
      headers: noStoreHeaders,
    }),
  ),
  http.get("/api/v1/session", () =>
    HttpResponse.json(sessionFixture, {
      headers: noStoreHeaders,
    }),
  ),
  http.get(
    "/api/v1/workspaces/:workspaceId/environments/:environmentId/assets",
    () =>
      HttpResponse.json(assetPageFixture, {
        headers: noStoreHeaders,
      }),
  ),
  http.get(
    "/api/v1/workspaces/:workspaceId/environments/:environmentId/assets/:assetId",
    ({ params }) =>
      HttpResponse.json(params.assetId === secondaryAssetID
        ? secondaryAssetDetailFixture
        : assetDetailFixture, {
        headers: { ...noStoreHeaders, ETag: '"asset-7"' },
      }),
  ),
  http.get(
    "/api/v1/workspaces/:workspaceId/environments/:environmentId/asset-relations",
    () =>
      HttpResponse.json(assetRelationPageFixture, {
        headers: noStoreHeaders,
      }),
  ),
  http.get("/api/v1/workspaces/:workspaceId/asset-sources", () =>
    HttpResponse.json(assetSourcePageFixture, {
      headers: noStoreHeaders,
    }),
  ),
  http.post(
    "/api/v1/workspaces/:workspaceId/environments/:environmentId/assets",
    () =>
      HttpResponse.json(assetMutationResultFixture, {
        status: 201,
        headers: {
          ...noStoreHeaders,
          ETag: '"asset-7"',
          "X-Audit-ID": assetMutationResultFixture.mutation_receipt.audit_id,
        },
      }),
  ),
  http.patch(
    "/api/v1/workspaces/:workspaceId/environments/:environmentId/assets/:assetId",
    () =>
      HttpResponse.json(assetMutationResultFixture, {
        headers: { ...noStoreHeaders, ETag: '"asset-8"' },
      }),
  ),
  http.post(
    "/api/v1/workspaces/:workspaceId/environments/:environmentId/assets/:assetId\\:quarantine",
    () =>
      HttpResponse.json(assetMutationResultFixture, {
        headers: { ...noStoreHeaders, ETag: '"asset-8"' },
      }),
  ),
  http.post(
    "/api/v1/workspaces/:workspaceId/environments/:environmentId/assets/:assetId\\:retire",
    () =>
      HttpResponse.json(assetMutationResultFixture, {
        headers: { ...noStoreHeaders, ETag: '"asset-8"' },
      }),
  ),
];
