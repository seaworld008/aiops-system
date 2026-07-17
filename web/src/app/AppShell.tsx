import type { PropsWithChildren } from "react";
import { useRef } from "react";

import type { components } from "@/shared/api/schema";
import { useScope } from "@/shared/api/queryKeys";

import styles from "./AppShell.module.css";
import { navigationGroups } from "./navigation";

type Session = components["schemas"]["Session"];

type AppShellProps = PropsWithChildren<{
  session: Session;
}>;

export function AppShell({ session, children }: AppShellProps) {
  const mainRef = useRef<HTMLElement>(null);
  const { scope, requestScopeChange, requestNavigation } = useScope();
  const username = session.username === "" ? session.subject : session.username;

  return (
    <div className={styles.shell}>
      <a
        className={styles.skipLink}
        href="#main-content"
        onClick={(event) => {
          event.preventDefault();
          mainRef.current?.focus();
        }}
      >
        跳到主内容
      </a>
      <aside className={styles.sidebar}>
        <div className={styles.product}>
          <span className={styles.productName}>AIOps 控制平面</span>
          <span className={styles.productState}>受治理 · 关闭态构建</span>
        </div>
        <nav aria-label="领域导航" className={styles.navigation}>
          {navigationGroups.map((group) => (
            <section key={group.label} className={styles.navigationGroup}>
              <h2>{group.label}</h2>
              <ul>
                {group.items.map((item) => (
                  <li key={item.path}>
                    {item.enabled ? (
                      <a
                        className={styles.disabledNavigationItem}
                        href={scopedNavigationHref(item.path, scope)}
                        onClick={(event) => {
                          if (
                            event.defaultPrevented ||
                            event.button !== 0 ||
                            event.metaKey ||
                            event.ctrlKey ||
                            event.shiftKey ||
                            event.altKey
                          ) {
                            return;
                          }
                          event.preventDefault();
                          requestNavigation(event.currentTarget.href);
                        }}
                      >
                        <span>{item.label}</span>
                        <small>{item.phase}</small>
                      </a>
                    ) : (
                      <span
                        aria-disabled="true"
                        className={styles.disabledNavigationItem}
                      >
                        <span>{item.label}</span>
                        <small>{item.phase}</small>
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </nav>
      </aside>
      <header className={styles.contextBar}>
        <div className={styles.scopeControls}>
          <label>
            <span>工作空间</span>
            <select
              value={scope.workspaceId}
              onChange={(event) => {
                requestScopeChange({
                  workspaceId: event.currentTarget.value,
                  environmentId: scope.environmentId,
                });
              }}
            >
              {session.workspace_ids.map((workspaceId) => (
                <option key={workspaceId} value={workspaceId}>
                  {workspaceId}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span>环境</span>
            <select
              value={scope.environmentId}
              onChange={(event) => {
                requestScopeChange({
                  workspaceId: scope.workspaceId,
                  environmentId: event.currentTarget.value,
                });
              }}
            >
              {session.environment_ids.map((environmentId) => (
                <option key={environmentId} value={environmentId}>
                  {environmentId}
                </option>
              ))}
            </select>
          </label>
        </div>
        <span className={styles.user}>{username}</span>
      </header>
      <main
        id="main-content"
        ref={mainRef}
        className={styles.main}
        tabIndex={-1}
      >
        {children}
      </main>
    </div>
  );
}

function scopedNavigationHref(
  path: string,
  scope: {
    workspaceId: string;
    environmentId: string;
  },
): string {
  const search = new URLSearchParams({
    workspace: scope.workspaceId,
    environment: scope.environmentId,
  });
  return `${path}?${search.toString()}`;
}
