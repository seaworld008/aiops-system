import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import type { PropsWithChildren } from "react";

import type { components } from "@/shared/api/schema";
import type { BrowserConfig } from "@/shared/api/browserConfig";
import {
  type ControlPlaneAuthActions,
  type ControlPlaneClient,
  ControlPlaneRuntimeProvider,
  type createControlPlaneClient,
} from "@/shared/api/controlPlaneClient";

import type { AccessTokenProvider } from "./auth/keycloak";
import { ScopeProvider } from "./scope/ScopeProvider";

type Session = components["schemas"]["Session"];

export type BootstrapDependencies = {
  loadBrowserConfig: () => Promise<BrowserConfig>;
  initializeOIDC: (
    config: BrowserConfig["oidc"],
  ) => Promise<AccessTokenProvider>;
  createClient: typeof createControlPlaneClient;
  render: (result: {
    browserConfig: BrowserConfig;
    tokenProvider: AccessTokenProvider;
    client: ControlPlaneClient;
    session: Session;
  }) => void;
};

type AppProvidersProps = PropsWithChildren<{
  queryClient: QueryClient;
  session: Session;
  client: ControlPlaneClient;
  authActions: ControlPlaneAuthActions;
}>;

export function createAppQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        refetchOnWindowFocus: true,
        staleTime: 0,
        gcTime: 5 * 60_000,
      },
      mutations: {
        retry: false,
      },
    },
  });
}

export async function bootstrapApplication(
  dependencies: BootstrapDependencies,
): Promise<void> {
  const browserConfig = await dependencies.loadBrowserConfig();
  const tokenProvider = await dependencies.initializeOIDC(browserConfig.oidc);
  const client = dependencies.createClient({
    apiBasePath: browserConfig.apiBasePath,
    getAccessToken: tokenProvider.getAccessToken,
  });
  const sessionResult = await client.execute("getSession", { parameters: {} });
  dependencies.render({
    browserConfig,
    tokenProvider,
    client,
    session: sessionResult.data,
  });
}

export function AppProviders({
  queryClient,
  session,
  client,
  authActions,
  children,
}: AppProvidersProps) {
  return (
    <QueryClientProvider client={queryClient}>
      <ControlPlaneRuntimeProvider
        client={client}
        authActions={authActions}
      >
        <ScopeProvider session={session}>{children}</ScopeProvider>
      </ControlPlaneRuntimeProvider>
    </QueryClientProvider>
  );
}
