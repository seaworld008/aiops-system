import { useQueryClient } from "@tanstack/react-query";
import { AlertDialog } from "radix-ui";
import {
  type PropsWithChildren,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import {
  type DraftGuardRegistration,
  type Scope,
  ScopeRuntimeProvider,
} from "@/shared/api/queryKeys";
import type { components } from "@/shared/api/schema";

type Session = components["schemas"]["Session"];

type ScopeProviderProps = PropsWithChildren<{
  session: Session;
  isDirty?: boolean;
  onDiscardDraft?: () => void;
}>;

type ScopeTransition = {
  next: Scope;
  history: "push" | "preserve";
  targetURL?: string;
};

const scopeSpecificSearchKeys = [
  "cursor",
  "trail",
  "assetId",
  "sourceId",
  "runId",
  "conflictId",
  "operationId",
  "selectedId",
];

export function ScopeProvider({
  session,
  isDirty = false,
  onDiscardDraft,
  children,
}: ScopeProviderProps) {
  const queryClient = useQueryClient();
  const [scope, setScope] = useState<Scope | undefined>(() =>
    initialScope(session),
  );
  const [pending, setPending] = useState<ScopeTransition | undefined>();
  const draftGuards = useRef(new Set<DraftGuardRegistration>());
  const currentURL = useRef(window.location.href);
  const registerDraftGuard = useCallback(
    (registration: DraftGuardRegistration) => {
      draftGuards.current.add(registration);
      return () => {
        draftGuards.current.delete(registration);
      };
    },
    [],
  );
  const hasDirtyDraft = useCallback(
    () =>
      isDirty ||
      Array.from(draftGuards.current).some((registration) =>
        draftIsDirty(registration),
      ),
    [isDirty],
  );

  useEffect(() => {
    if (scope !== undefined) {
      const synchronized = scopeURL(
        new URL(window.location.href),
        scope,
        false,
      );
      replaceHistoryURL(synchronized.href);
      currentURL.current = synchronized.href;
    }
  }, [scope]);

  const applyScope = useCallback(async (transition: ScopeTransition) => {
    const previous = scope;
    if (previous === undefined) {
      return;
    }
    const destination =
      transition.targetURL === undefined
        ? scopeURL(new URL(currentURL.current), transition.next, true)
        : validatedTransitionURL(
            session,
            transition.next,
            transition.targetURL,
          );
    if (destination === undefined) {
      replaceHistoryURL(currentURL.current);
      setPending(undefined);
      return;
    }
    if (
      transition.history === "preserve" &&
      new URL(window.location.href).href !== destination.href
    ) {
      replaceHistoryURL(currentURL.current);
      setPending(undefined);
      return;
    }
    await queryClient.cancelQueries({
      predicate: (query) =>
        query.queryKey[1] === previous.workspaceId &&
        query.queryKey[2] === previous.environmentId,
    });
    queryClient.removeQueries({
      predicate: (query) =>
        query.queryKey[1] === previous.workspaceId &&
        query.queryKey[2] === previous.environmentId,
    });
    try {
      onDiscardDraft?.();
      for (const registration of draftGuards.current) {
        if (draftIsDirty(registration)) {
          registration.discard();
        }
      }
    } catch {
      setPending(undefined);
      return;
    }
    if (transition.history === "push") {
      window.history.pushState(window.history.state, "", destination.href);
    }
    currentURL.current = destination.href;
    setScope(transition.next);
    setPending(undefined);
  }, [onDiscardDraft, queryClient, scope, session]);

  const requestScopeChange = (next: Scope) => {
    if (scope === undefined) {
      return;
    }
    if (
      next.workspaceId === scope.workspaceId &&
      next.environmentId === scope.environmentId
    ) {
      return;
    }
    if (
      !session.workspace_ids.includes(next.workspaceId) ||
      !session.environment_ids.includes(next.environmentId)
    ) {
      return;
    }
    const transition: ScopeTransition = {
      next,
      history: "push",
    };
    if (hasDirtyDraft()) {
      setPending(transition);
      return;
    }
    void applyScope(transition);
  };

  useEffect(() => {
    if (scope === undefined) {
      return;
    }
    const handlePopState = () => {
      const targetURL = new URL(window.location.href);
      const next = scopeFromURL(session, targetURL);
      if (next === undefined) {
        replaceHistoryURL(currentURL.current);
        return;
      }
      if (sameScope(scope, next)) {
        currentURL.current = targetURL.href;
        return;
      }
      if (hasDirtyDraft()) {
        replaceHistoryURL(currentURL.current);
        setPending({
          next,
          history: "push",
          targetURL: targetURL.href,
        });
        return;
      }
      void applyScope({
        next,
        history: "preserve",
        targetURL: targetURL.href,
      });
    };
    window.addEventListener("popstate", handlePopState);
    return () => {
      window.removeEventListener("popstate", handlePopState);
    };
  }, [applyScope, hasDirtyDraft, scope, session]);

  if (scope === undefined) {
    return (
      <section role="alert" aria-labelledby="scope-unavailable-title">
        <h1 id="scope-unavailable-title">当前作用域不可用</h1>
        <p>请从已授权入口重新进入；不会显示其他作用域中的对象是否存在。</p>
      </section>
    );
  }

  return (
    <ScopeRuntimeProvider
      scope={scope}
      requestScopeChange={requestScopeChange}
      registerDraftGuard={registerDraftGuard}
    >
      {children}
      <AlertDialog.Root
        open={pending !== undefined}
        onOpenChange={(open) => {
          if (!open) {
            setPending(undefined);
          }
        }}
      >
        <AlertDialog.Portal>
          <AlertDialog.Overlay className="dialog-overlay" />
          <AlertDialog.Content
            className="dialog-content"
            aria-describedby="scope-switch-description"
          >
            <AlertDialog.Title>切换作用域</AlertDialog.Title>
            <AlertDialog.Description id="scope-switch-description">
              当前存在未保存草稿。切换会只放弃本地草稿，并清理旧作用域查询。
            </AlertDialog.Description>
            <div className="dialog-actions">
              <AlertDialog.Cancel asChild>
                <button type="button">取消</button>
              </AlertDialog.Cancel>
              <AlertDialog.Action asChild>
                <button
                  type="button"
                  onClick={() => {
                    if (pending !== undefined) {
                      void applyScope(pending);
                    }
                  }}
                >
                  放弃并切换
                </button>
              </AlertDialog.Action>
            </div>
          </AlertDialog.Content>
        </AlertDialog.Portal>
      </AlertDialog.Root>
    </ScopeRuntimeProvider>
  );
}

function initialScope(session: Session): Scope | undefined {
  const search = new URL(window.location.href).searchParams;
  const requestedWorkspace = search.get("workspace");
  const requestedEnvironment = search.get("environment");
  const workspaceId = requestedWorkspace ?? session.workspace_ids[0];
  const environmentId = requestedEnvironment ?? session.environment_ids[0];
  if (
    workspaceId === undefined ||
    environmentId === undefined ||
    !session.workspace_ids.includes(workspaceId) ||
    !session.environment_ids.includes(environmentId)
  ) {
    return undefined;
  }
  return { workspaceId, environmentId };
}

function scopeURL(
  url: URL,
  scope: Scope,
  clearScopeSpecific: boolean,
): URL {
  url.searchParams.set("workspace", scope.workspaceId);
  url.searchParams.set("environment", scope.environmentId);
  if (clearScopeSpecific) {
    for (const key of scopeSpecificSearchKeys) {
      url.searchParams.delete(key);
    }
  }
  return url;
}

function scopeFromURL(session: Session, url: URL): Scope | undefined {
  const workspaceId = url.searchParams.get("workspace");
  const environmentId = url.searchParams.get("environment");
  if (
    workspaceId === null ||
    environmentId === null ||
    !session.workspace_ids.includes(workspaceId) ||
    !session.environment_ids.includes(environmentId)
  ) {
    return undefined;
  }
  return { workspaceId, environmentId };
}

function validatedTransitionURL(
  session: Session,
  scope: Scope,
  value: string,
): URL | undefined {
  const url = new URL(value, window.location.origin);
  const parsed = scopeFromURL(session, url);
  if (
    url.origin !== window.location.origin ||
    parsed === undefined ||
    !sameScope(scope, parsed)
  ) {
    return undefined;
  }
  return url;
}

function sameScope(left: Scope, right: Scope): boolean {
  return (
    left.workspaceId === right.workspaceId &&
    left.environmentId === right.environmentId
  );
}

function replaceHistoryURL(value: string): void {
  window.history.replaceState(window.history.state, "", value);
}

function draftIsDirty(registration: DraftGuardRegistration): boolean {
  try {
    return registration.isDirty();
  } catch {
    return true;
  }
}
