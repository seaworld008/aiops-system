export type NavigationItem = {
  label: string;
  path: string;
  phase: string;
  enabled: boolean;
};

export type NavigationGroup = {
  label: string;
  items: readonly NavigationItem[];
};

export const navigationGroups: readonly NavigationGroup[] = [
  {
    label: "运行",
    items: [
      { label: "总览", path: "/overview", phase: "后续阶段", enabled: false },
      { label: "事件处置", path: "/incidents", phase: "后续阶段", enabled: false },
      { label: "调查记录", path: "/investigations", phase: "后续阶段", enabled: false },
      { label: "主动调查", path: "/proactive-policies", phase: "后续阶段", enabled: false },
      { label: "受治理动作", path: "/action-plans", phase: "后续阶段", enabled: false },
    ],
  },
  {
    label: "资产与连接",
    items: [
      { label: "资产目录", path: "/assets", phase: "后续阶段", enabled: false },
      { label: "映射工作台", path: "/asset-mappings", phase: "后续阶段", enabled: false },
      { label: "连接与数据源", path: "/connections", phase: "后续阶段", enabled: false },
      { label: "发现与同步", path: "/asset-sources", phase: "后续阶段", enabled: false },
      {
        label: "凭据引用",
        path: "/credential-references",
        phase: "后续阶段",
        enabled: false,
      },
      {
        label: "Runner 与能力",
        path: "/runner-realms",
        phase: "后续阶段",
        enabled: false,
      },
    ],
  },
  {
    label: "治理",
    items: [
      {
        label: "授权与策略",
        path: "/governance/policies",
        phase: "后续阶段",
        enabled: false,
      },
      { label: "审计日志", path: "/audit", phase: "后续阶段", enabled: false },
      {
        label: "生产发布",
        path: "/production/releases",
        phase: "后续阶段",
        enabled: false,
      },
    ],
  },
];
