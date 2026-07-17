import type { ReactNode } from "react";

import { AbsoluteTime } from "@/shared/ui/AbsoluteTime";
import { StatusBadge } from "@/shared/ui/StatusBadge";

import type { AssetConflict } from "./api";
import styles from "./MappingWorkbenchPage.module.css";

export type ProvenanceComparisonProps = {
  conflict: AssetConflict;
};

export function ProvenanceComparison({
  conflict,
}: ProvenanceComparisonProps) {
  const candidateAsset = conflict.candidate_asset;
  const candidateService = conflict.candidate_service;
  return (
    <section
      className={styles.comparison}
      aria-label={`${conflict.asset.display_name} 安全比较`}
    >
      <header className={styles.comparisonHeader}>
        <div>
          <span className={styles.eyebrow}>比较键</span>
          <h2>
            {conflict.type} / {conflict.field_name}
          </h2>
        </div>
        <StatusBadge tone={conflict.status === "OPEN" ? "warning" : "neutral"}>
          {conflict.status}
        </StatusBadge>
      </header>
      <p className={styles.suggestion}>
        候选建议，不会自动生效
      </p>
      <div className={styles.comparisonGrid}>
        <ComparisonSection title="权威来源事实">
          <DefinitionList
            rows={[
              ["来源 ID", conflict.source_id],
              [
                "来源修订",
                String(conflict.observation.source_revision),
              ],
              ["观测 ID", conflict.observation.id],
            ]}
          />
          <p>
            接纳时间：{" "}
            <AbsoluteTime value={conflict.observation.observed_at} />
          </p>
        </ComparisonSection>

        <ComparisonSection title="现有资产">
          <DefinitionList
            rows={[
              ["资产名称", conflict.asset.display_name],
              ["资产类型", conflict.asset.kind],
              ["生命周期", conflict.asset.lifecycle],
              ["稳定 Asset ID", conflict.asset.id],
            ]}
          />
        </ComparisonSection>

        <ComparisonSection title="候选关系">
          <DefinitionList
            rows={[
              [
                "候选资产",
                candidateAsset === null
                  ? "无候选资产"
                  : `${candidateAsset.display_name} · ${candidateAsset.kind}`,
              ],
              [
                "候选 Service",
                candidateService === null
                  ? "无候选 Service"
                  : `${candidateService.name} · ${candidateService.id}`,
              ],
              [
                "受影响的连接与策略",
                impactSummary(conflict),
              ],
            ]}
          />
        </ComparisonSection>

        <ComparisonSection title="字段级 Provenance">
          <DefinitionList
            rows={[
              ["字段代码", conflict.field_name],
              ["来源", conflict.observation.source_id],
              [
                "来源修订",
                String(conflict.observation.source_revision),
              ],
              ["置信度", "服务端未提供，不推断"],
            ]}
          />
          <p>
            观测时间：{" "}
            <AbsoluteTime value={conflict.observation.observed_at} />
          </p>
          <p className={styles.safeNote}>
            比较 fingerprint 仅用于服务端并发与相等性判断，浏览器不展示其值。
          </p>
        </ComparisonSection>
      </div>
    </section>
  );
}

function ComparisonSection({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <section className={styles.comparisonSection}>
      <h3>{title}</h3>
      {children}
    </section>
  );
}

function DefinitionList({
  rows,
}: {
  rows: ReadonlyArray<readonly [string, string]>;
}) {
  return (
    <dl className={styles.definitionList}>
      {rows.map(([term, description]) => (
        <div key={term}>
          <dt>{term}</dt>
          <dd data-monospace={term.includes("ID") ? "true" : undefined}>
            {description}
          </dd>
        </div>
      ))}
    </dl>
  );
}

function impactSummary(conflict: AssetConflict): string {
  const counts = conflict.impact_counts;
  return [
    `资产 Binding ${counts.asset_active_bindings}`,
    `资产关系 ${counts.asset_active_relationships}`,
    `候选资产 Binding ${counts.candidate_asset_active_bindings}`,
    `候选资产关系 ${counts.candidate_asset_active_relationships}`,
    `候选 Service Binding ${counts.candidate_service_active_bindings}`,
  ].join("；");
}
