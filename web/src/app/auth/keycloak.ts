import Keycloak, {
  type KeycloakInitOptions,
  type KeycloakLoginOptions,
  type KeycloakLogoutOptions,
} from "keycloak-js";

import type { OIDCConfig } from "@/shared/api/browserConfig";

export type KeycloakClient = {
  token?: string | undefined;
  init: (options: KeycloakInitOptions) => Promise<boolean>;
  updateToken: (minimumValidity: number) => Promise<boolean>;
  login: (options?: KeycloakLoginOptions) => Promise<void>;
  logout: (options?: KeycloakLogoutOptions) => Promise<void>;
};

export type AccessTokenProvider = {
  getAccessToken: () => Promise<string>;
  login: () => Promise<void>;
  reauthenticate: (returnURL: string) => Promise<void>;
  logout: () => Promise<void>;
};

export async function createKeycloakAccessTokenProvider(
  config: OIDCConfig,
  injected?: KeycloakClient,
): Promise<AccessTokenProvider> {
  const keycloak: KeycloakClient =
    injected ??
    new Keycloak({
      url: config.url,
      realm: config.realm,
      clientId: config.clientId,
    });
  const authenticated = await keycloak.init({
    onLoad: "login-required",
    pkceMethod: "S256",
    checkLoginIframe: false,
    enableLogging: false,
  });
  if (!authenticated || keycloak.token === undefined || keycloak.token === "") {
    throw new Error("OIDC authentication failed");
  }
  return {
    async getAccessToken() {
      await keycloak.updateToken(30);
      if (keycloak.token === undefined || keycloak.token === "") {
        await keycloak.login();
        throw new Error("OIDC token unavailable");
      }
      return keycloak.token;
    },
    async login() {
      await keycloak.login();
    },
    async reauthenticate(returnURL: string) {
      const redirectURL = new URL(returnURL, window.location.origin);
      if (redirectURL.origin !== window.location.origin) {
        throw new Error("OIDC return URL must be same-origin");
      }
      await keycloak.login({
        prompt: "login",
        maxAge: 0,
        redirectUri: redirectURL.href,
      });
    },
    async logout() {
      await keycloak.logout({ redirectUri: window.location.origin });
    },
  };
}
