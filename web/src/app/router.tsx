import {
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
} from "@tanstack/react-router";

import type { components } from "@/shared/api/schema";
import { MappingWorkbenchPage } from "@/features/asset-mappings/MappingWorkbenchPage";
import { parseMappingSearch } from "@/features/asset-mappings/mappingSearch";
import { AssetSourcesPage } from "@/features/asset-sources/AssetSourcesPage";
import { parseSourceSearch } from "@/features/asset-sources/sourceSearch";
import { AssetCatalogPage } from "@/features/assets/AssetCatalogPage";
import { AssetDetailPage } from "@/features/assets/AssetDetailPage";
import {
  assetListHref,
  parseAssetSearch,
  type AssetSearch,
} from "@/features/assets/assetSearch";

import { AppShell } from "./AppShell";

type Session = components["schemas"]["Session"];

export function createAppRouter(session: Session) {
  const fallback = {
    workspace: session.workspace_ids[0] ?? "",
    environment: session.environment_ids[0] ?? "",
  };
  const rootRoute = createRootRoute({
    component: () => (
      <AppShell session={session}>
        <Outlet />
      </AppShell>
    ),
    notFoundComponent: () => (
      <section role="status">
        <h1>页面尚未在当前阶段实现</h1>
        <p>此路由保持关闭，不代表对应能力已经开放。</p>
      </section>
    ),
  });
  const indexRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: "/",
    component: () => (
      <section>
        <p>应用基础、身份和作用域已安全加载。</p>
        <p>资产与映射页面已接入；发现页面将在后续任务中接入。</p>
      </section>
    ),
  });
  const assetsRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: "/assets",
    validateSearch: (search) => parseAssetSearch(search, fallback),
    component: AssetsRoute,
  });
  const assetDetailRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: "/assets/$assetId",
    validateSearch: (search) => parseAssetSearch(search, fallback),
    component: AssetDetailRoute,
  });
  const assetMappingsRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: "/asset-mappings",
    validateSearch: (search) => parseMappingSearch(search, fallback),
    component: AssetMappingsRoute,
  });
  const assetSourcesRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: "/asset-sources",
    validateSearch: (search) =>
      parseSourceSearch(search, { workspace: fallback.workspace }),
    component: AssetSourcesRoute,
  });

  function AssetsRoute() {
    const search = parseAssetSearch(
      assetsRoute.useSearch() as unknown,
      fallback,
    );
    const navigate = assetsRoute.useNavigate();
    return (
      <AssetCatalogPage
        search={search}
        onSearchChange={(next, options) => {
          void navigate({
            search: next,
            replace: options?.replace ?? false,
          });
        }}
        onOpenAsset={(assetId) => {
          const next: AssetSearch = { ...search };
          delete next.assetId;
          void navigate({
            to: "/assets/$assetId",
            params: { assetId },
            search: next,
          });
        }}
      />
    );
  }

  function AssetDetailRoute() {
    const search = parseAssetSearch(
      assetDetailRoute.useSearch() as unknown,
      fallback,
    );
    const params = assetDetailRoute.useParams() as unknown as {
      assetId: string;
    };
    const assetId = params.assetId;
    const navigate = assetDetailRoute.useNavigate();
    const listSearch: AssetSearch = { ...search };
    delete listSearch.assetId;
    return (
      <AssetDetailPage
        assetId={assetId}
        search={search}
        backHref={assetListHref(listSearch)}
        onBack={() => {
          void navigate({
            to: "/assets",
            search: listSearch,
          });
        }}
        onSearchChange={(next, options) => {
          void navigate({
            search: next,
            replace: options?.replace ?? false,
          });
        }}
      />
    );
  }

  function AssetMappingsRoute() {
    const search = parseMappingSearch(
      assetMappingsRoute.useSearch() as unknown,
      fallback,
    );
    const navigate = assetMappingsRoute.useNavigate();
    return (
      <MappingWorkbenchPage
        search={search}
        onSearchChange={(next, options) => {
          void navigate({
            search: next,
            replace: options?.replace ?? false,
          });
        }}
      />
    );
  }

  function AssetSourcesRoute() {
    const search = parseSourceSearch(
      assetSourcesRoute.useSearch() as unknown,
      { workspace: fallback.workspace },
    );
    const navigate = assetSourcesRoute.useNavigate();
    return (
      <AssetSourcesPage
        search={search}
        onSearchChange={(next, options) => {
          void navigate({
            search: next,
            replace: options?.replace ?? false,
          });
        }}
      />
    );
  }

  const routeTree = rootRoute.addChildren([
    indexRoute,
    assetsRoute,
    assetDetailRoute,
    assetMappingsRoute,
    assetSourcesRoute,
  ]);
  return createRouter({
    routeTree,
    defaultPreload: "intent",
    search: { strict: true },
  });
}
