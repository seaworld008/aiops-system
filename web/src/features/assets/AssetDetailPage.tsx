import { useEffect } from "react";

import { useScope } from "@/shared/api/queryKeys";
import { ProblemPanel } from "@/shared/ui/ProblemPanel";

import { AssetDetailPanel } from "./AssetDetailDrawer";
import {
  isAssetUUID,
  type AssetSearch,
} from "./assetSearch";
import type { AssetSearchChangeOptions } from "./AssetCatalogPage";
import styles from "./AssetCatalogPage.module.css";

export type AssetDetailPageProps = {
  assetId: string;
  search: AssetSearch;
  backHref: string;
  onBack: () => void;
  onSearchChange: (
    search: AssetSearch,
    options?: AssetSearchChangeOptions,
  ) => void;
};

export function AssetDetailPage({
  assetId,
  search,
  backHref,
  onBack,
  onSearchChange,
}: AssetDetailPageProps) {
  const { scope } = useScope();
  useEffect(() => {
    if (search.assetId === undefined) {
      return;
    }
    const canonicalSearch: AssetSearch = { ...search };
    delete canonicalSearch.assetId;
    onSearchChange(canonicalSearch, { replace: true });
  }, [onSearchChange, search]);

  if (!isAssetUUID(assetId)) {
    return (
      <ProblemPanel
        problem={{
          type: "about:blank",
          title: "资产标识无效",
          status: 404,
          code: "asset_not_found",
          detail: "当前链接没有可用的安全资产投影。",
        }}
      />
    );
  }
  return (
    <section className={styles.detailPage}>
      <a
        href={backHref}
        onClick={(event) => {
          event.preventDefault();
          onBack();
        }}
      >
        返回资产列表
      </a>
      <h1>资产详情</h1>
      <AssetDetailPanel
        scope={scope}
        assetId={assetId}
        tab={search.tab}
        onTabChange={(tab) => {
          const canonicalSearch: AssetSearch = {
            ...search,
            tab,
          };
          delete canonicalSearch.assetId;
          onSearchChange(canonicalSearch);
        }}
      />
    </section>
  );
}
