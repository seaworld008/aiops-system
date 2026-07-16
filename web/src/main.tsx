import { RouterProvider } from "@tanstack/react-router";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { AuthBoundary } from "@/app/auth/AuthBoundary";
import { createKeycloakAccessTokenProvider } from "@/app/auth/keycloak";
import {
  AppProviders,
  bootstrapApplication,
  createAppQueryClient,
} from "@/app/providers";
import { createAppRouter } from "@/app/router";
import "@/app/styles/global.css";
import { loadBrowserConfig } from "@/shared/api/browserConfig";
import { createControlPlaneClient } from "@/shared/api/controlPlaneClient";

async function bootstrap(): Promise<void> {
  await bootstrapApplication({
    loadBrowserConfig,
    initializeOIDC: createKeycloakAccessTokenProvider,
    createClient: createControlPlaneClient,
    render: ({ client, session, tokenProvider }) => {
      const queryClient = createAppQueryClient();
      queryClient.setQueryData(["session"], session);
      const router = createAppRouter(session);
      const root = document.getElementById("root");
      if (root === null) {
        throw new Error("Application root unavailable");
      }
      createRoot(root).render(
        <StrictMode>
          <AuthBoundary>
            <AppProviders
              queryClient={queryClient}
              session={session}
              client={client}
              authActions={{
                login: () => tokenProvider.login(),
                reauthenticate: (returnURL) =>
                  tokenProvider.reauthenticate(returnURL),
                logout: () => tokenProvider.logout(),
              }}
            >
              <RouterProvider router={router} />
            </AppProviders>
          </AuthBoundary>
        </StrictMode>,
      );
    },
  });
}

function renderFailure(error: unknown): void {
  const root = document.getElementById("root");
  if (root === null) {
    return;
  }
  createRoot(root).render(
    <AuthBoundary
      error={error}
      onRetry={() => {
        window.location.reload();
      }}
    />,
  );
}

void bootstrap().catch(renderFailure);
