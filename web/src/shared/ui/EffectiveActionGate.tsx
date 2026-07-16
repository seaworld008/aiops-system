import type { ReactNode } from "react";

import type { components } from "@/shared/api/schema";

type EffectiveAction = components["schemas"]["EffectiveAction"];

type EffectiveActionGateProps = {
  effectiveActions: readonly EffectiveAction[];
  action: EffectiveAction;
  children: ReactNode;
  fallback?: ReactNode;
};

export function EffectiveActionGate({
  effectiveActions,
  action,
  children,
  fallback = null,
}: EffectiveActionGateProps) {
  return effectiveActions.includes(action) ? children : fallback;
}
