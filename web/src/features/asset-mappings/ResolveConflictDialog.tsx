import {
  useMutation,
  useQueryClient,
} from "@tanstack/react-query";
import { AlertDialog } from "radix-ui";
import {
  type RefObject,
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  useForm,
  useWatch,
} from "react-hook-form";
import { z } from "zod";

import { useControlPlaneClient } from "@/shared/api/controlPlaneClient";
import type { ClientProblem } from "@/shared/api/problem";
import {
  type Scope,
  useDraftGuard,
} from "@/shared/api/queryKeys";
import type { components } from "@/shared/api/schema";
import { ETagConflictReview } from "@/shared/ui/ETagConflictReview";
import { ProblemPanel } from "@/shared/ui/ProblemPanel";

import {
  type AssetConflict,
  type ConflictBatchResult,
  invalidateMappingScope,
  isConflictProblem,
  isForbiddenProblem,
  type ResolveAssetConflictRequest,
  resolveConflictBatch,
} from "./api";
import styles from "./MappingWorkbenchPage.module.css";

export type ConflictDecision =
  ResolveAssetConflictRequest["resolution"];

type ResolveConflictDialogProps = {
  open: boolean;
  scope: Scope;
  conflicts: readonly AssetConflict[];
  decision: ConflictDecision;
  reviewIdentity: string;
  onOpenChange: (open: boolean) => void;
  onResults: (results: readonly ConflictBatchResult[]) => void;
  onPermissionDenied: (conflictIds: readonly string[]) => void;
  onNavigationGuardChange: (blocked: boolean) => void;
};

type FormValues = {
  service_id: string;
  binding_role: "" | components["schemas"]["BindingRole"];
  reason_code: string;
  impact_acknowledged: boolean;
};

const bindingRoles = [
  "PRIMARY_RUNTIME",
  "DEPENDENCY",
  "OBSERVABILITY_SOURCE",
  "DELIVERY_TARGET",
  "MANAGED_TARGET",
] as const satisfies readonly components["schemas"]["BindingRole"][];

const baseSchema = z
  .object({
    service_id: z.string(),
    binding_role: z.union([z.literal(""), z.enum(bindingRoles)]),
    reason_code: z
      .string()
      .regex(/^[A-Z][A-Z0-9_]{0,127}$/u),
    impact_acknowledged: z.boolean(),
  })
  .strict();

const uuidSchema = z.string().uuid();

export function ResolveConflictDialog({
  open,
  scope,
  conflicts,
  decision,
  reviewIdentity,
  onOpenChange,
  onResults,
  onPermissionDenied,
  onNavigationGuardChange,
}: ResolveConflictDialogProps) {
  const client = useControlPlaneClient();
  const queryClient = useQueryClient();
  const [problem, setProblem] = useState<ClientProblem | null>(null);
  const [conflictLock, setConflictLock] = useState<{
    conflict: AssetConflict;
    request: ResolveAssetConflictRequest;
  } | null>(null);
  const [permissionClosed, setPermissionClosed] = useState(false);
  const identity = `${reviewIdentity}:${scope.workspaceId}:${
    scope.environmentId
  }:${conflicts
    .map((item) => `${item.id}:${item.etag}`)
    .join(",")}:${decision}`;
  const lifecycleRef = useRef({
    active: true,
    identity,
  });
  const {
    register,
    handleSubmit,
    control,
    reset,
    formState: { isDirty, isSubmitting },
  } = useForm<FormValues>({
    defaultValues: defaultValues(conflicts),
  });

  const mutation = useMutation({
    retry: false,
    mutationFn: async ({
      request,
      submittedIdentity,
    }: {
      request: ResolveAssetConflictRequest;
      submittedIdentity: string;
    }) =>
      resolveConflictBatch(
        client,
        scope,
        conflicts,
        request,
        (results) => {
          if (isCurrentIdentity(lifecycleRef, submittedIdentity)) {
            onResults(results);
          }
        },
        () => isCurrentIdentity(lifecycleRef, submittedIdentity),
      ),
  });
  const pending = mutation.isPending || isSubmitting;
  const navigationBlocked = open && (isDirty || pending);

  useLayoutEffect(() => {
    const lifecycle = {
      active: true,
      identity,
    };
    lifecycleRef.current = lifecycle;
    return () => {
      lifecycle.active = false;
    };
  }, [identity]);

  useEffect(() => {
    onNavigationGuardChange(navigationBlocked);
    return () => {
      onNavigationGuardChange(false);
    };
  }, [navigationBlocked, onNavigationGuardChange]);

  const discard = useCallback(() => {
    if (!pending && conflictLock === null) {
      reset(defaultValues(conflicts));
      setProblem(null);
      setConflictLock(null);
      setPermissionClosed(false);
      onOpenChange(false);
    }
  }, [
    conflicts,
    onOpenChange,
    pending,
    reset,
    conflictLock,
  ]);
  const draftRegistration = useMemo(
    () => ({
      isDirty: () => navigationBlocked,
      discard,
    }),
    [discard, navigationBlocked],
  );
  useDraftGuard(draftRegistration);

  const values: FormValues = {
    service_id: useWatch({
      control,
      name: "service_id",
    }),
    binding_role: useWatch({
      control,
      name: "binding_role",
    }),
    reason_code: useWatch({
      control,
      name: "reason_code",
    }),
    impact_acknowledged: useWatch({
      control,
      name: "impact_acknowledged",
    }),
  };
  const impactAcknowledgementRequired =
    decision === "CONFIRM_EXACT" || conflicts.length > 1;
  const formReady = decisionReady(
    decision,
    values,
    impactAcknowledgementRequired,
  );
  const submit = async (rawValues: FormValues) => {
    setProblem(null);
    setConflictLock(null);
    if (
      conflicts.length === 0 ||
      conflicts.some(
        (item) =>
          !item.effective_actions.includes("RESOLVE_CONFLICT"),
      )
    ) {
      setPermissionClosed(true);
      setProblem({
        type: "about:blank",
        title: "只读比较",
        status: 403,
        code: "asset_scope_forbidden",
        detail: "服务端未授予冲突解析动作，映射决定保持关闭。",
      });
      return;
    }
    const parsed = baseSchema.safeParse(rawValues);
    if (!parsed.success) {
      setProblem({
        type: "about:blank",
        title: "决定信息不完整",
        status: 400,
        code: "invalid_request",
        detail: "请检查原因代码、目标 Service 和影响确认。",
      });
      return;
    }
    const request = decisionRequest(
      decision,
      parsed.data,
      impactAcknowledgementRequired,
    );
    if (request === undefined) {
      setProblem({
        type: "about:blank",
        title: "决定信息不完整",
        status: 400,
        code: "invalid_request",
        detail: "确认精确映射需要有效 Service、Binding Role 和影响确认。",
      });
      return;
    }
    const submittedIdentity = identity;
    const results = await mutation.mutateAsync({
      request,
      submittedIdentity,
    });
    if (!isCurrentIdentity(lifecycleRef, submittedIdentity)) {
      return;
    }
    onResults(results);
    await invalidateMappingScope(queryClient, scope);
    if (!isCurrentIdentity(lifecycleRef, submittedIdentity)) {
      return;
    }
    const failed = results.find(
      (
        result,
      ): result is Extract<
        ConflictBatchResult,
        { status: "failure" }
      > => result.status === "failure",
    );
    if (failed !== undefined) {
      setProblem(failed.problem);
      if (isForbiddenProblem(failed.problem)) {
        setPermissionClosed(true);
        onPermissionDenied([failed.conflict.id]);
      }
      if (isConflictProblem(failed.problem)) {
        setConflictLock({
          conflict: failed.conflict,
          request,
        });
      }
      return;
    }
    reset(defaultValues(conflicts));
    onOpenChange(false);
  };

  const first = conflicts[0];
  return (
    <AlertDialog.Root
      open={open}
      onOpenChange={(nextOpen) => {
        if (!nextOpen) {
          discard();
        }
      }}
    >
      <AlertDialog.Portal>
        <AlertDialog.Overlay className="dialog-overlay" />
        <AlertDialog.Content
          className={`dialog-content ${styles.mappingDecisionDialog} ${
            decision === "QUARANTINE_ASSET"
              ? styles.destructiveDialog
              : ""
          }`}
        >
          <AlertDialog.Title>
            {decisionTitle(decision, conflicts.length)}
          </AlertDialog.Title>
          <AlertDialog.Description>
            每个冲突使用自己的当前 ETag 和新的 Idempotency-Key
            提交；batch 逐项执行并在首个失败时停止。
          </AlertDialog.Description>
          {first === undefined ? null : (
            <section className={styles.impactReview}>
              <h3>比较键</h3>
              <p data-monospace="true">
                {first.type} / {first.field_name}
              </p>
              <h3>受影响的连接与策略</h3>
              <ul className={styles.impactList}>
                {conflicts.map((conflict) => (
                  <li key={conflict.id}>
                    <strong>{conflict.asset.display_name}</strong>
                    <span data-monospace="true">{conflict.id}</span>
                    <span>{impactText(conflict)}</span>
                  </li>
                ))}
              </ul>
            </section>
          )}
          {decision === "KEEP_UNRESOLVED" ? (
            <p className={styles.warningNotice}>
              <strong>调查仍保持不可用</strong>
              <span>；后续必须重新进行显式治理。</span>
            </p>
          ) : null}
          {decision === "QUARANTINE_ASSET" ? (
            <p className={styles.dangerNotice}>
              <strong>隔离会阻止新的调查与 Claim</strong>
              <span>，并保留完整审计。</span>
            </p>
          ) : null}
          {problem === null ? null : <ProblemPanel problem={problem} />}
          {conflictLock === null ? null : (
            <ETagConflictReview
              clientVersion={conflictLock.conflict.etag}
              serverVersion="请求发生冲突，必须重新加载并审阅"
              diffRows={[
                {
                  field: "resolution",
                  submittedValue: conflictLock.request.resolution,
                  serverValue: "必须重新加载并审阅",
                },
              ]}
              onReload={() => {
                void invalidateMappingScope(queryClient, scope).then(() => {
                  if (isCurrentIdentity(lifecycleRef, identity)) {
                    setConflictLock(null);
                    setProblem(null);
                    onOpenChange(false);
                  }
                });
              }}
            />
          )}
          <form
            className={styles.decisionForm}
            onSubmit={(event) => {
              void handleSubmit(submit)(event);
            }}
          >
            {decision === "CONFIRM_EXACT" ? (
              <>
                <label>
                  <span>目标 Service</span>
                  <input
                    {...register("service_id")}
                    maxLength={36}
                    autoComplete="off"
                    readOnly
                  />
                </label>
                <label>
                  <span>Binding Role</span>
                  <select
                    aria-label="Binding Role"
                    {...register("binding_role")}
                  >
                    <option value="">请选择</option>
                    {bindingRoles.map((role) => (
                      <option key={role} value={role}>
                        {role}
                      </option>
                    ))}
                  </select>
                </label>
              </>
            ) : null}
            <label>
              <span>审计原因代码</span>
              <input
                aria-label="审计原因代码"
                {...register("reason_code")}
                maxLength={128}
                autoComplete="off"
                placeholder="SERVICE_OWNER_VERIFIED"
              />
            </label>
            {impactAcknowledgementRequired ? (
              <label className={styles.impactAcknowledgement}>
                <input
                  type="checkbox"
                  {...register("impact_acknowledged")}
                />
                <span>
                  {conflicts.length > 1
                    ? `我已逐项审阅全部 ${conflicts.length} 项冲突及其受影响的连接与策略`
                    : "我已审阅受影响的连接与策略"}
                </span>
              </label>
            ) : null}
            <div className="dialog-actions">
              <AlertDialog.Cancel asChild>
                <button
                  type="button"
                  disabled={pending || conflictLock !== null}
                >
                  取消
                </button>
              </AlertDialog.Cancel>
              <button
                type="submit"
                disabled={
                  !formReady ||
                  pending ||
                  permissionClosed ||
                  conflictLock !== null
                }
              >
                {pending ? "正在逐项提交…" : "确认并记录决定"}
              </button>
            </div>
          </form>
        </AlertDialog.Content>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  );
}

function defaultValues(
  conflicts: readonly AssetConflict[],
): FormValues {
  return {
    service_id: conflicts[0]?.candidate_service?.id ?? "",
    binding_role: "",
    reason_code: "",
    impact_acknowledged: false,
  };
}

function decisionReady(
  decision: ConflictDecision,
  values: FormValues,
  impactAcknowledgementRequired: boolean,
): boolean {
  const reasonReady = /^[A-Z][A-Z0-9_]{0,127}$/u.test(
    values.reason_code,
  );
  if (
    !reasonReady ||
    (impactAcknowledgementRequired &&
      !values.impact_acknowledged)
  ) {
    return false;
  }
  if (decision !== "CONFIRM_EXACT") {
    return true;
  }
  return (
    uuidSchema.safeParse(values.service_id).success &&
    values.binding_role !== "" &&
    values.impact_acknowledged
  );
}

function decisionRequest(
  decision: ConflictDecision,
  values: FormValues,
  impactAcknowledgementRequired: boolean,
): ResolveAssetConflictRequest | undefined {
  if (
    impactAcknowledgementRequired &&
    !values.impact_acknowledged
  ) {
    return undefined;
  }
  if (decision === "CONFIRM_EXACT") {
    const service = uuidSchema.safeParse(values.service_id);
    if (
      !service.success ||
      values.binding_role === "" ||
      !values.impact_acknowledged
    ) {
      return undefined;
    }
    return {
      resolution: "CONFIRM_EXACT",
      service_id: service.data,
      binding_role: values.binding_role,
      reason_code: values.reason_code,
    };
  }
  return {
    resolution: decision,
    reason_code: values.reason_code,
  };
}

function decisionTitle(
  decision: ConflictDecision,
  count: number,
): string {
  const prefix = count > 1 ? `批量处理 ${count} 项：` : "";
  switch (decision) {
    case "CONFIRM_EXACT":
      return `${prefix}确认精确映射`;
    case "REJECT_CANDIDATE":
      return `${prefix}拒绝候选`;
    case "KEEP_UNRESOLVED":
      return `${prefix}保持未解析`;
    case "QUARANTINE_ASSET":
      return `${prefix}隔离资产`;
  }
}

function impactText(conflict: AssetConflict): string {
  const counts = conflict.impact_counts;
  return [
    `现有 Binding ${counts.asset_active_bindings}`,
    `现有关系 ${counts.asset_active_relationships}`,
    `候选 Binding ${counts.candidate_asset_active_bindings}`,
    `候选关系 ${counts.candidate_asset_active_relationships}`,
    `Service Binding ${counts.candidate_service_active_bindings}`,
  ].join("；");
}

function isCurrentIdentity(
  lifecycleRef: RefObject<{
    active: boolean;
    identity: string;
  }>,
  identity: string,
): boolean {
  return (
    lifecycleRef.current.active &&
    lifecycleRef.current.identity === identity
  );
}
