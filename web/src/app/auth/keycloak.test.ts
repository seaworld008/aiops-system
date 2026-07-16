import { describe, expect, it, vi } from "vitest";

import type { OIDCConfig } from "@/shared/api/browserConfig";

import {
  createKeycloakAccessTokenProvider,
  type KeycloakClient,
} from "./keycloak";

const validOIDCConfig: OIDCConfig = {
  url: "https://identity.example.com",
  realm: "aiops",
  clientId: "control-plane-web",
};

function fakeKeycloak(overrides: Partial<KeycloakClient> = {}): KeycloakClient {
  return {
    token: "ephemeral-token",
    init: vi.fn().mockResolvedValue(true),
    updateToken: vi.fn().mockResolvedValue(false),
    login: vi.fn().mockResolvedValue(undefined),
    logout: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

describe("createKeycloakAccessTokenProvider", () => {
  it("initializes login-required PKCE and refreshes the memory token before every request", async () => {
    const keycloak = fakeKeycloak();
    const provider = await createKeycloakAccessTokenProvider(validOIDCConfig, keycloak);

    expect(keycloak.init).toHaveBeenCalledWith({
      onLoad: "login-required",
      pkceMethod: "S256",
      checkLoginIframe: false,
      enableLogging: false,
    });
    await expect(provider.getAccessToken()).resolves.toBe("ephemeral-token");
    await expect(provider.getAccessToken()).resolves.toBe("ephemeral-token");
    expect(keycloak.updateToken).toHaveBeenNthCalledWith(1, 30);
    expect(keycloak.updateToken).toHaveBeenNthCalledWith(2, 30);
  });

  it("never reads or writes browser persistence or application cookies", async () => {
    const storageSpies = [
      vi.spyOn(Storage.prototype, "setItem"),
      vi.spyOn(Storage.prototype, "getItem"),
      vi.spyOn(Storage.prototype, "removeItem"),
      vi.spyOn(Storage.prototype, "clear"),
    ];
    const provider = await createKeycloakAccessTokenProvider(
      validOIDCConfig,
      fakeKeycloak(),
    );

    await provider.getAccessToken();

    for (const spy of storageSpies) {
      expect(spy).not.toHaveBeenCalled();
    }
    expect(document.cookie).toBe("");
  });

  it("forces a fresh login and accepts only a same-origin return URL", async () => {
    const keycloak = fakeKeycloak();
    const provider = await createKeycloakAccessTokenProvider(validOIDCConfig, keycloak);

    await provider.reauthenticate("/connections/c-1?step=review");

    expect(keycloak.login).toHaveBeenCalledWith({
      prompt: "login",
      maxAge: 0,
      redirectUri: `${window.location.origin}/connections/c-1?step=review`,
    });
    await expect(
      provider.reauthenticate("https://evil.invalid/steal"),
    ).rejects.toThrow("OIDC return URL must be same-origin");
    await expect(provider.reauthenticate("//evil.invalid/steal")).rejects.toThrow(
      "OIDC return URL must be same-origin",
    );
  });

  it("fails closed when authentication or the refreshed token is unavailable", async () => {
    await expect(
      createKeycloakAccessTokenProvider(
        validOIDCConfig,
        fakeKeycloak({ token: undefined, init: vi.fn().mockResolvedValue(false) }),
      ),
    ).rejects.toThrow("OIDC authentication failed");

    const keycloak = fakeKeycloak({ token: "initial-token" });
    const provider = await createKeycloakAccessTokenProvider(
      validOIDCConfig,
      keycloak,
    );
    keycloak.token = undefined;
    await expect(provider.getAccessToken()).rejects.toThrow("OIDC token unavailable");
    expect(keycloak.login).toHaveBeenCalled();
  });
});
