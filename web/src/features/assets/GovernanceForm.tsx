import {
  useMutation,
  useQueryClient,
} from "@tanstack/react-query";
import {
  AlertDialog,
  Dialog,
} from "radix-ui";
import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { useControlPlaneClient } from "@/shared/api/controlPlaneClient";
import {
  type Scope,
  useDraftGuard,
} from "@/shared/api/queryKeys";
import { ETagConflictReview } from "@/shared/ui/ETagConflictReview";
import { ProblemPanel } from "@/shared/ui/ProblemPanel";

import {
  assetQueryKeys,
  getAsset,
  invalidateAssetScope,
  isSensitiveAssetLabelKey,
  isVersionConflict,
  patchAsset,
  problemFromError,
  transitionAsset,
  type AssetDetailResult,
  type AssetMutationResponse,
  type PatchAssetRequest,
  type TransitionAssetRequest,
} from "./api";
import styles from "./AssetCatalogPage.module.css";

type GovernanceFormProps = {
  scope: Scope;
  detail: AssetDetailResult;
};

type EditValues = {
  display_name: string;
  owner_group: string;
  criticality: PatchAssetRequest["criticality"];
  data_classification: PatchAssetRequest["data_classification"];
  labels_text: string;
};

type TransitionValues = {
  reason_code: string;
};

type TransitionKind = "quarantine" | "retire";

type ConflictState = {
  clientVersion: string;
  server: AssetDetailResult;
  diffRows: Array<{
    field: string;
    submittedValue: string;
    serverValue: string;
  }>;
};

const editSchema = z
  .object({
    display_name: z.string().trim().min(1).max(256),
    owner_group: z.string().trim().max(256),
    criticality: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    data_classification: z.enum([
      "PUBLIC",
      "INTERNAL",
      "CONFIDENTIAL",
      "RESTRICTED",
    ]),
    labels_text: z.string().max(4096),
  })
  .strict();

const transitionSchema = z
  .object({
    reason_code: z
      .string()
      .regex(/^[A-Z][A-Z0-9_]{0,127}$/u),
  })
  .strict();

export function GovernanceForm({
  scope,
  detail,
}: GovernanceFormProps) {
  const client = useControlPlaneClient();
  const queryClient = useQueryClient();
  const desktopGovernance = useMediaQuery("(min-width: 768px)");
  const identity =
    `${scope.workspaceId}:${scope.environmentId}:${detail.asset.id}`;
  const detailKey = assetQueryKeys.detail(scope, detail.asset.id);
  const lifecycleRef = useRef({
    active: true,
    identity,
  });
  const [editOpen, setEditOpen] = useState(false);
  const [transition, setTransition] =
    useState<TransitionKind | null>(null);
  const [problem, setProblem] = useState<ReturnType<
    typeof problemFromError
  > | null>(null);
  const [formMessage, setFormMessage] = useState<string | null>(null);
  const [conflict, setConflict] = useState<ConflictState | null>(null);
  const [result, setResult] = useState<
    AssetMutationResponse | undefined
  >();
  const editForm = useForm<EditValues>({
    defaultValues: editValues(detail),
  });
  const transitionForm = useForm<TransitionValues>({
    defaultValues: { reason_code: "" },
  });
  const patchMutation = useMutation({
    mutationFn: ({
      etag,
      request,
    }: {
      etag: string;
      request: PatchAssetRequest;
    }) => patchAsset(client, scope, detail.asset.id, etag, request),
    retry: false,
  });
  const transitionMutation = useMutation({
    mutationFn: ({
      kind,
      etag,
      request,
    }: {
      kind: TransitionKind;
      etag: string;
      request: TransitionAssetRequest;
    }) =>
      transitionAsset(
        client,
        kind === "quarantine" ? "quarantineAsset" : "retireAsset",
        scope,
        detail.asset.id,
        etag,
        request,
      ),
    retry: false,
  });
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
  const isCurrentIdentity = useCallback(
    () =>
      lifecycleRef.current.active &&
      lifecycleRef.current.identity === identity,
    [identity],
  );
  const isCurrentDetailLive = () =>
    isCurrentIdentity() &&
    queryClient.getQueryState(detailKey) !== undefined;

  const clearLocalState = useCallback(() => {
    editForm.reset(editValues(detail));
    transitionForm.reset({ reason_code: "" });
    setEditOpen(false);
    setTransition(null);
    setProblem(null);
    setFormMessage(null);
    setConflict(null);
  }, [detail, editForm, transitionForm]);
  const draftRegistration = useMemo(
    () => ({
      isDirty: () =>
        (editOpen && editForm.formState.isDirty) ||
        (transition !== null && transitionForm.formState.isDirty),
      discard: clearLocalState,
    }),
    [
      clearLocalState,
      editForm.formState.isDirty,
      editOpen,
      transition,
      transitionForm.formState.isDirty,
    ],
  );
  useDraftGuard(draftRegistration);

  const mutationResponseMissingETag =
    result !== undefined && result.etag === undefined;
  const canEdit =
    detail.asset.effective_actions.includes("EDIT_GOVERNANCE");
  const canQuarantine =
    detail.asset.effective_actions.includes("QUARANTINE");
  const canRetire = detail.asset.effective_actions.includes("RETIRE");
  const transitionAllowed =
    transition === "quarantine"
      ? canQuarantine
      : transition === "retire"
        ? canRetire
        : false;
  const etagAvailable =
    detail.etag !== undefined && !mutationResponseMissingETag;
  const completeMutation = async (response: AssetMutationResponse) => {
    if (!isCurrentDetailLive()) {
      return;
    }
    const nextDetail: AssetDetailResult = {
      asset: response.result.asset,
      ...(response.etag === undefined ? {} : { etag: response.etag }),
      ...(response.traceId === undefined
        ? {}
        : { traceId: response.traceId }),
    };
    queryClient.setQueryData(detailKey, nextDetail);
    setResult(response);
    setProblem(null);
    setConflict(null);
    setFormMessage(null);
    setEditOpen(false);
    setTransition(null);
    editForm.reset(editValues(nextDetail));
    transitionForm.reset({ reason_code: "" });
    await invalidateAssetScope(queryClient, scope);
    if (!isCurrentDetailLive()) {
      return;
    }
    if (response.etag === undefined) {
      const refreshed =
        queryClient.getQueryData<AssetDetailResult>(detailKey);
      if (refreshed !== undefined) {
        queryClient.setQueryData<AssetDetailResult>(detailKey, {
          asset: refreshed.asset,
          ...(refreshed.traceId === undefined
            ? nextDetail.traceId === undefined
              ? {}
              : { traceId: nextDetail.traceId }
            : { traceId: refreshed.traceId }),
        });
      }
    }
  };

  const loadConflict = async (
    error: unknown,
    submitted: Readonly<Record<string, string>>,
  ) => {
    if (!isCurrentDetailLive()) {
      return;
    }
    if (!isVersionConflict(error)) {
      setProblem(problemFromError(error));
      return;
    }
    try {
      const server = await getAsset(client, scope, detail.asset.id);
      if (!isCurrentDetailLive()) {
        return;
      }
      const serverValues = stringValues(server);
      const fields = new Set([
        ...Object.keys(submitted),
        ...Object.keys(serverValues),
      ]);
      setConflict({
        clientVersion: detail.etag ?? "ETag unavailable",
        server,
        diffRows: [...fields].sort().map((field) => ({
          field,
          submittedValue: submitted[field] ?? "—",
          serverValue: serverValues[field] ?? "—",
        })),
      });
      setProblem(null);
    } catch (reloadError) {
      if (isCurrentDetailLive()) {
        setProblem(problemFromError(reloadError));
      }
    }
  };

  const submitEdit = async (values: EditValues) => {
    if (!desktopGovernance || !isCurrentDetailLive()) {
      return;
    }
    if (conflict !== null) {
      return;
    }
    if (!canEdit) {
      setFormMessage(
        "服务端最新 effective_actions 已撤销编辑权限，提交保持关闭。",
      );
      return;
    }
    setProblem(null);
    setConflict(null);
    setFormMessage(null);
    if (!etagAvailable || detail.etag === undefined) {
      setFormMessage("服务端未返回最新 ETag，治理写入保持关闭。");
      return;
    }
    const parsed = editSchema.safeParse(values);
    if (!parsed.success) {
      setFormMessage("治理字段不符合闭合长度或枚举约束。");
      return;
    }
    const labels = parseGovernanceLabels(parsed.data.labels_text);
    if (!labels.success) {
      setFormMessage(labels.message);
      return;
    }
    const request: PatchAssetRequest = {
      display_name: parsed.data.display_name,
      owner_group:
        parsed.data.owner_group === ""
          ? null
          : parsed.data.owner_group,
      criticality: parsed.data.criticality,
      data_classification: parsed.data.data_classification,
      labels: labels.items,
    };
    try {
      const response = await patchMutation.mutateAsync({
        etag: detail.etag,
        request,
      });
      await completeMutation(response);
    } catch (error) {
      await loadConflict(error, {
        display_name: request.display_name,
        owner_group: request.owner_group ?? "null",
        criticality: request.criticality,
        data_classification: request.data_classification,
        labels: serializeLabels(request.labels),
      });
    }
  };

  const submitTransition = async (values: TransitionValues) => {
    if (!desktopGovernance || !isCurrentDetailLive()) {
      return;
    }
    if (conflict !== null) {
      return;
    }
    if (!transitionAllowed) {
      setFormMessage(
        "服务端最新 effective_actions 已撤销该治理动作，提交保持关闭。",
      );
      return;
    }
    setProblem(null);
    setConflict(null);
    setFormMessage(null);
    if (
      !etagAvailable ||
      detail.etag === undefined ||
      transition === null
    ) {
      setFormMessage("服务端未返回最新 ETag，治理写入保持关闭。");
      return;
    }
    const parsed = transitionSchema.safeParse(values);
    if (!parsed.success) {
      setFormMessage(
        "原因代码必须是 1–128 位大写字母、数字或下划线，并以字母开头。",
      );
      return;
    }
    const request: TransitionAssetRequest = {
      reason_code: parsed.data.reason_code,
    };
    const currentTransition = transition;
    try {
      const response = await transitionMutation.mutateAsync({
        kind: currentTransition,
        etag: detail.etag,
        request,
      });
      await completeMutation(response);
    } catch (error) {
      await loadConflict(error, {
        transition: currentTransition.toUpperCase(),
        reason_code: request.reason_code,
        display_name: detail.asset.display_name,
        version: String(detail.asset.version),
      });
    }
  };

  const reloadConflict = () => {
    if (conflict === null || !isCurrentDetailLive()) {
      return;
    }
    queryClient.setQueryData(detailKey, conflict.server);
    editForm.reset(editValues(conflict.server));
    transitionForm.reset({ reason_code: "" });
    setConflict(null);
    setProblem(null);
    const serverAllowsCurrentAction =
      (editOpen &&
        conflict.server.asset.effective_actions.includes(
          "EDIT_GOVERNANCE",
        )) ||
      (transition !== null &&
        isTransitionAllowed(conflict.server, transition));
    setFormMessage(
      serverAllowsCurrentAction
        ? null
        : "服务端最新 effective_actions 已撤销该治理动作，提交保持关闭。",
    );
  };

  if (!desktopGovernance) {
    return (
      <section className={styles.governance}>
        <p role="status" className={styles.inlineNotice}>
          请在桌面完成治理操作。当前窄屏仅支持查看安全状态与升级人工。
        </p>
      </section>
    );
  }

  return (
    <section className={styles.governance}>
      <div className={styles.governanceActions}>
        {canEdit ? (
          <button
            type="button"
            disabled={!etagAvailable}
            onClick={() => {
              editForm.reset(editValues(detail));
              setProblem(null);
              setConflict(null);
              setFormMessage(null);
              setEditOpen(true);
            }}
          >
            编辑治理信息
          </button>
        ) : null}
        {canQuarantine ? (
          <button
            type="button"
            disabled={!etagAvailable}
            onClick={() => {
              transitionForm.reset({ reason_code: "" });
              setProblem(null);
              setConflict(null);
              setFormMessage(null);
              setTransition("quarantine");
            }}
          >
            隔离资产
          </button>
        ) : null}
        {canRetire ? (
          <button
            type="button"
            disabled={!etagAvailable}
            onClick={() => {
              transitionForm.reset({ reason_code: "" });
              setProblem(null);
              setConflict(null);
              setFormMessage(null);
              setTransition("retire");
            }}
          >
            退役资产
          </button>
        ) : null}
      </div>
      {mutationResponseMissingETag ? (
        <p role="status" className={styles.inlineNotice}>
          治理变更响应缺少 ETag，无法证明后续写入基于最新版本；
          治理写入保持关闭。
        </p>
      ) : !etagAvailable &&
      detail.asset.effective_actions.some((action) =>
        ["EDIT_GOVERNANCE", "QUARANTINE", "RETIRE"].includes(action),
      ) ? (
        <p role="status" className={styles.inlineNotice}>
          服务端未返回最新 ETag，所有治理写入保持关闭。
        </p>
      ) : null}
      {result === undefined ? null : (
        <section role="status" className={styles.inlineResult}>
          <strong>治理变更已由服务端确认</strong>
          <span>
            Audit ID：{" "}
            <span data-monospace="true">
              {result.result.mutation_receipt.audit_id}
            </span>
          </span>
          <span>
            Trace ID：{" "}
            <span data-monospace="true">
              {result.result.mutation_receipt.trace_id}
            </span>
          </span>
        </section>
      )}
      <Dialog.Root
        open={editOpen}
        onOpenChange={(open) => {
          if (!open) {
            editForm.reset(editValues(detail));
            setConflict(null);
            setProblem(null);
            setFormMessage(null);
          }
          setEditOpen(open);
        }}
      >
        <Dialog.Portal>
          <Dialog.Overlay className="dialog-overlay" />
          <Dialog.Content className="dialog-content">
            <Dialog.Title>编辑治理信息</Dialog.Title>
            <Dialog.Description>
              只更新资产治理字段，并使用当前服务端 ETag。
            </Dialog.Description>
            <form
              className={styles.formGrid}
              onSubmit={(event) => {
                void editForm.handleSubmit(submitEdit)(event);
              }}
            >
              {conflict === null ? (
                <>
                  <label>
                    <span>显示名称</span>
                    <input
                      {...editForm.register("display_name")}
                      maxLength={256}
                    />
                  </label>
                  <label>
                    <span>Owner 组</span>
                    <input
                      {...editForm.register("owner_group")}
                      maxLength={256}
                    />
                  </label>
                  <label>
                    <span>关键度</span>
                    <select {...editForm.register("criticality")}>
                      <option value="LOW">LOW</option>
                      <option value="MEDIUM">MEDIUM</option>
                      <option value="HIGH">HIGH</option>
                      <option value="CRITICAL">CRITICAL</option>
                    </select>
                  </label>
                  <label>
                    <span>数据分类</span>
                    <select
                      {...editForm.register("data_classification")}
                    >
                      <option value="PUBLIC">PUBLIC</option>
                      <option value="INTERNAL">INTERNAL</option>
                      <option value="CONFIDENTIAL">CONFIDENTIAL</option>
                      <option value="RESTRICTED">RESTRICTED</option>
                    </select>
                  </label>
                  <label className={styles.formWide}>
                    <span>安全标签（每行 key=value）</span>
                    <textarea
                      {...editForm.register("labels_text")}
                      rows={3}
                      maxLength={4096}
                    />
                  </label>
                </>
              ) : null}
              <GovernanceFeedback
                problem={problem}
                formMessage={formMessage}
                conflict={conflict}
                onReload={reloadConflict}
              />
              <div className={`dialog-actions ${styles.formWide}`}>
                <Dialog.Close asChild>
                  <button type="button">取消</button>
                </Dialog.Close>
                <button
                  type="submit"
                  disabled={
                    patchMutation.isPending ||
                    !etagAvailable ||
                    !canEdit ||
                    conflict !== null
                  }
                >
                  {patchMutation.isPending ? "正在保存…" : "保存治理信息"}
                </button>
              </div>
            </form>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
      <AlertDialog.Root
        open={transition !== null}
        onOpenChange={(open) => {
          if (!open) {
            transitionForm.reset({ reason_code: "" });
            setTransition(null);
            setConflict(null);
            setProblem(null);
            setFormMessage(null);
          }
        }}
      >
        <AlertDialog.Portal>
          <AlertDialog.Overlay className="dialog-overlay" />
          <AlertDialog.Content className="dialog-content">
            <AlertDialog.Title>
              {transition === "quarantine" ? "隔离资产" : "退役资产"}
            </AlertDialog.Title>
            <AlertDialog.Description>
              资产：{detail.asset.display_name}（
              <span data-monospace="true">{detail.asset.id}</span>）。
              {transition === "quarantine"
                ? "隔离会立即阻止新 Claim，并要求运行边界重新验证。"
                : "退役会终止后续运行资格，但保留历史关系与审计。"}
            </AlertDialog.Description>
            <form
              className={styles.formGrid}
              onSubmit={(event) => {
                void transitionForm.handleSubmit(submitTransition)(event);
              }}
            >
              {conflict === null ? (
                <label className={styles.formWide}>
                  <span>原因代码</span>
                  <input
                    {...transitionForm.register("reason_code")}
                    maxLength={128}
                    autoComplete="off"
                  />
                </label>
              ) : null}
              <GovernanceFeedback
                problem={problem}
                formMessage={formMessage}
                conflict={conflict}
                onReload={reloadConflict}
              />
              <div className={`dialog-actions ${styles.formWide}`}>
                <AlertDialog.Cancel asChild>
                  <button type="button">取消</button>
                </AlertDialog.Cancel>
                <button
                  type="submit"
                  disabled={
                    transitionMutation.isPending ||
                    !etagAvailable ||
                    !transitionAllowed ||
                    conflict !== null
                  }
                >
                  {transitionMutation.isPending
                    ? "正在提交…"
                    : transition === "quarantine"
                      ? "确认隔离"
                      : "确认退役"}
                </button>
              </div>
            </form>
          </AlertDialog.Content>
        </AlertDialog.Portal>
      </AlertDialog.Root>
    </section>
  );
}

function GovernanceFeedback({
  problem,
  formMessage,
  conflict,
  onReload,
}: {
  problem: ReturnType<typeof problemFromError> | null;
  formMessage: string | null;
  conflict: ConflictState | null;
  onReload: () => void;
}) {
  return (
    <>
      {problem === null ? null : (
        <div className={styles.formWide}>
          <ProblemPanel problem={problem} />
        </div>
      )}
      {formMessage === null ? null : (
        <p role="alert" className={styles.formWide}>
          {formMessage}
        </p>
      )}
      {conflict === null ? null : (
        <div className={styles.formWide}>
          <ETagConflictReview
            clientVersion={conflict.clientVersion}
            serverVersion={conflict.server.etag ?? "ETag unavailable"}
            diffRows={conflict.diffRows}
            onReload={onReload}
          />
        </div>
      )}
    </>
  );
}

function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() =>
    window.matchMedia(query).matches,
  );
  useEffect(() => {
    const media = window.matchMedia(query);
    const handleChange = () => {
      setMatches(media.matches);
    };
    handleChange();
    media.addEventListener("change", handleChange);
    return () => {
      media.removeEventListener("change", handleChange);
    };
  }, [query]);
  return matches;
}

function editValues(detail: AssetDetailResult): EditValues {
  return {
    display_name: detail.asset.display_name,
    owner_group: detail.asset.owner_group ?? "",
    criticality: detail.asset.criticality,
    data_classification: detail.asset.data_classification,
    labels_text: serializeLabels(detail.asset.labels),
  };
}

function stringValues(
  detail: AssetDetailResult,
): Record<string, string> {
  return {
    display_name: detail.asset.display_name,
    owner_group: detail.asset.owner_group ?? "null",
    criticality: detail.asset.criticality,
    data_classification: detail.asset.data_classification,
    labels: serializeLabels(detail.asset.labels),
    lifecycle: detail.asset.lifecycle,
    mapping_status: detail.asset.mapping_status,
    version: String(detail.asset.version),
  };
}

function serializeLabels(
  labels: PatchAssetRequest["labels"],
): string {
  return labels.map((label) => `${label.key}=${label.value}`).join("\n");
}

function isTransitionAllowed(
  detail: AssetDetailResult,
  transition: TransitionKind,
): boolean {
  return detail.asset.effective_actions.includes(
    transition === "quarantine" ? "QUARANTINE" : "RETIRE",
  );
}

function parseGovernanceLabels(
  value: string,
):
  | { success: true; items: PatchAssetRequest["labels"] }
  | { success: false; message: string } {
  const lines = value
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line !== "");
  if (lines.length > 64) {
    return { success: false, message: "安全标签最多 64 项。" };
  }
  const items: PatchAssetRequest["labels"] = [];
  const keys = new Set<string>();
  for (const line of lines) {
    const separator = line.indexOf("=");
    if (separator <= 0) {
      return {
        success: false,
        message: "安全标签必须使用每行 key=value 格式。",
      };
    }
    const key = line.slice(0, separator).trim();
    const valuePart = line.slice(separator + 1).trim();
    if (
      !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/u.test(key) ||
      valuePart.length === 0 ||
      valuePart.length > 256 ||
      keys.has(key) ||
      isSensitiveAssetLabelKey(key)
    ) {
      return {
        success: false,
        message: "安全标签键、值、敏感语义或重复项不符合闭合约束。",
      };
    }
    keys.add(key);
    items.push({ key, value: valuePart });
  }
  return { success: true, items };
}
