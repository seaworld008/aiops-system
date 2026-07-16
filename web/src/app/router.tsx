import {
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
} from "@tanstack/react-router";

import type { components } from "@/shared/api/schema";

import { AppShell } from "./AppShell";

type Session = components["schemas"]["Session"];

export function createAppRouter(session: Session) {
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
        <p>资产、映射与发现页面将在后续任务中接入。</p>
      </section>
    ),
  });
  const routeTree = rootRoute.addChildren([indexRoute]);
  return createRouter({
    routeTree,
    defaultPreload: "intent",
  });
}
