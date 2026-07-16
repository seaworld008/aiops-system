import {
  useCallback,
  useMemo,
  useState,
} from "react";
import {
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { Dialog } from "radix-ui";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { useControlPlaneClient } from "@/shared/api/controlPlaneClient";
import {
  type Scope,
  useDraftGuard,
} from "@/shared/api/queryKeys";
import { ProblemPanel } from "@/shared/ui/ProblemPanel";

import {
  assetQueryKeys,
  createAsset,
  invalidateAssetScope,
  isSensitiveAssetLabelKey,
  listManualAssetSources,
  problemFromError,
  type AssetMutationResponse,
  type CreateAssetRequest,
} from "./api";
import {
  assetKinds,
  assetKindLabels,
} from "./assetSearch";
import styles from "./AssetCatalogPage.module.css";

type CreateAssetDialogProps = {
  open: boolean;
  scope: Scope;
  onOpenChange: (open: boolean) => void;
  onCreated: (result: AssetMutationResponse) => void;
};

type FormValues = {
  source_id: string;
  kind: CreateAssetRequest["kind"];
  external_id: string;
  display_name: string;
  owner_group: string;
  criticality: CreateAssetRequest["criticality"];
  data_classification: CreateAssetRequest["data_classification"];
  labels_text: string;
};

const formSchema = z
  .object({
    source_id: z.string().uuid(),
    kind: z.enum(assetKinds),
    external_id: z.string().trim().min(1).max(512),
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

const defaultValues: FormValues = {
  source_id: "",
  kind: "LINUX_VM",
  external_id: "",
  display_name: "",
  owner_group: "",
  criticality: "MEDIUM",
  data_classification: "INTERNAL",
  labels_text: "",
};

export function CreateAssetDialog({
  open,
  scope,
  onOpenChange,
  onCreated,
}: CreateAssetDialogProps) {
  const client = useControlPlaneClient();
  const queryClient = useQueryClient();
  const [problem, setProblem] = useState<ReturnType<
    typeof problemFromError
  > | null>(null);
  const [formMessage, setFormMessage] = useState<string | null>(null);
  const {
    register,
    handleSubmit,
    reset,
    formState: { isDirty, isSubmitting },
  } = useForm<FormValues>({ defaultValues });
  const sourcesQuery = useQuery({
    queryKey: assetQueryKeys.sourceEligibility(scope),
    queryFn: ({ signal }) =>
      listManualAssetSources(client, scope, signal),
    enabled: open,
  });
  const sourceEligibilityFresh =
    !sourcesQuery.isFetching &&
    sourcesQuery.error === null &&
    sourcesQuery.data !== undefined;
  const eligibleSources =
    sourceEligibilityFresh
      ? sourcesQuery.data.items.filter((source) =>
          source.effective_actions.includes("CREATE_ASSET"),
        )
      : [];

  const discardLocalDraft = useCallback(() => {
    reset(defaultValues);
    setProblem(null);
    setFormMessage(null);
    onOpenChange(false);
  }, [onOpenChange, reset]);
  const draftRegistration = useMemo(
    () => ({
      isDirty: () => open && isDirty,
      discard: discardLocalDraft,
    }),
    [discardLocalDraft, isDirty, open],
  );
  useDraftGuard(draftRegistration);

  const handleDialogOpenChange = (nextOpen: boolean) => {
    if (!nextOpen) {
      discardLocalDraft();
      return;
    }
    onOpenChange(nextOpen);
  };

  const submit = async (values: FormValues) => {
    setProblem(null);
    setFormMessage(null);
    if (
      !sourceEligibilityFresh ||
      !eligibleSources.some((source) => source.id === values.source_id)
    ) {
      setFormMessage(
        "手工登记来源资格尚未完成新鲜验证，资产登记保持关闭。",
      );
      return;
    }
    const parsed = formSchema.safeParse(values);
    if (!parsed.success) {
      setFormMessage("请检查必填字段、长度和格式后重试。");
      return;
    }
    const labels = parseLabels(parsed.data.labels_text);
    if (!labels.success) {
      setFormMessage(labels.message);
      return;
    }
    const request: CreateAssetRequest = {
      source_id: parsed.data.source_id,
      kind: parsed.data.kind,
      external_id: parsed.data.external_id,
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
      const response = await createAsset(client, scope, request);
      await invalidateAssetScope(queryClient, scope);
      onCreated(response);
      handleDialogOpenChange(false);
    } catch (error) {
      setProblem(problemFromError(error));
    }
  };

  return (
    <Dialog.Root open={open} onOpenChange={handleDialogOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <Dialog.Content className="dialog-content">
          <Dialog.Title>添加资产</Dialog.Title>
          <Dialog.Description>
            仅登记可运维引用；不会创建、接管或连接外部资源。
          </Dialog.Description>
          {sourcesQuery.error !== null ? (
            <ProblemPanel problem={problemFromError(sourcesQuery.error)} />
          ) : null}
          {problem === null ? null : <ProblemPanel problem={problem} />}
          {sourcesQuery.isFetching ? (
            <p role="status">正在加载可用手工登记来源…</p>
          ) : null}
          {sourceEligibilityFresh && eligibleSources.length === 0 ? (
            <p role="status" className={styles.inlineNotice}>
              当前没有可用的手工登记来源。只有完成完整 Source
              revision/profile flow，并由服务端授予 CREATE_ASSET 后才可用。
            </p>
          ) : null}
          <form
            className={styles.formGrid}
            onSubmit={(event) => {
              void handleSubmit(submit)(event);
            }}
          >
            <label>
              <span>登记来源</span>
              <select
                {...register("source_id")}
                disabled={
                  !sourceEligibilityFresh ||
                  eligibleSources.length === 0
                }
              >
                <option value="">请选择 opaque Source ID</option>
                {eligibleSources.map((source) => (
                  <option key={source.id} value={source.id}>
                    {source.name} · {source.id}
                  </option>
                ))}
              </select>
            </label>
            <label>
              <span>资产类型</span>
              <select {...register("kind")}>
                {assetKinds.map((kind) => (
                  <option key={kind} value={kind}>
                    {assetKindLabels[kind]}
                  </option>
                ))}
              </select>
            </label>
            <label>
              <span>外部 ID</span>
              <input
                {...register("external_id")}
                maxLength={512}
                autoComplete="off"
              />
            </label>
            <label>
              <span>显示名称</span>
              <input
                {...register("display_name")}
                maxLength={256}
                autoComplete="off"
              />
            </label>
            <label>
              <span>Owner 组</span>
              <input
                {...register("owner_group")}
                maxLength={256}
                autoComplete="off"
              />
            </label>
            <label>
              <span>关键度</span>
              <select {...register("criticality")}>
                <option value="LOW">LOW</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="HIGH">HIGH</option>
                <option value="CRITICAL">CRITICAL</option>
              </select>
            </label>
            <label>
              <span>数据分类</span>
              <select {...register("data_classification")}>
                <option value="PUBLIC">PUBLIC</option>
                <option value="INTERNAL">INTERNAL</option>
                <option value="CONFIDENTIAL">CONFIDENTIAL</option>
                <option value="RESTRICTED">RESTRICTED</option>
              </select>
            </label>
            <label className={styles.formWide}>
              <span>安全标签（每行 key=value）</span>
              <textarea
                {...register("labels_text")}
                rows={3}
                maxLength={4096}
              />
            </label>
            {formMessage === null ? null : (
              <p role="alert" className={styles.formWide}>
                {formMessage}
              </p>
            )}
            <div className={`dialog-actions ${styles.formWide}`}>
              <Dialog.Close asChild>
                <button type="button">取消</button>
              </Dialog.Close>
              <button
                type="submit"
                disabled={
                  isSubmitting ||
                  !sourceEligibilityFresh ||
                  eligibleSources.length === 0
                }
              >
                {isSubmitting ? "正在登记…" : "登记资产"}
              </button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function parseLabels(
  value: string,
):
  | { success: true; items: CreateAssetRequest["labels"] }
  | { success: false; message: string } {
  const lines = value
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line !== "");
  if (lines.length > 64) {
    return { success: false, message: "安全标签最多 64 项。" };
  }
  const items: CreateAssetRequest["labels"] = [];
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
    const labelValue = line.slice(separator + 1).trim();
    if (
      !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/u.test(key) ||
      labelValue.length === 0 ||
      labelValue.length > 256 ||
      keys.has(key) ||
      isSensitiveAssetLabelKey(key)
    ) {
      return {
        success: false,
        message:
          "安全标签包含禁止的敏感键语义，或键、值、重复项不符合闭合约束。",
      };
    }
    keys.add(key);
    items.push({ key, value: labelValue });
  }
  return { success: true, items };
}
