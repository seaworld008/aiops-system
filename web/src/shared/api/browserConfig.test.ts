import { describe, expect, it, vi } from "vitest";

import { loadBrowserConfig } from "./browserConfig";

const validConfig = {
  oidc: {
    url: "https://identity.example.com",
    realm: "aiops",
    client_id: "control-plane-web",
  },
  api_base_path: "/api/v1",
  build: {
    version: "1.0.0",
    commit: "abc123",
    contract_digest: `sha256:${"0".repeat(64)}`,
  },
};

function configResponse(value: unknown, init?: ResponseInit) {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "Content-Type": "application/json" },
    ...init,
  });
}

describe("loadBrowserConfig", () => {
  it("loads the same-origin closed config with no-store anonymous semantics", async () => {
    const fetcher = vi.fn().mockResolvedValue(configResponse(validConfig));

    await expect(loadBrowserConfig(fetcher)).resolves.toMatchObject({
      apiBasePath: "/api/v1",
      oidc: {
        url: "https://identity.example.com",
        realm: "aiops",
        clientId: "control-plane-web",
      },
    });
    expect(fetcher).toHaveBeenCalledWith(
      "/api/v1/browser-config",
      expect.objectContaining({
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
      }),
    );
    const request = fetcher.mock.calls[0]?.[1] as RequestInit | undefined;
    expect(new Headers(request?.headers).has("Authorization")).toBe(false);
  });

  it.each([
    ["extra field", { ...validConfig, client_secret: "forbidden" }],
    [
      "nested secret-like field",
      { ...validConfig, oidc: { ...validConfig.oidc, token: "forbidden" } },
    ],
    [
      "external insecure OIDC",
      { ...validConfig, oidc: { ...validConfig.oidc, url: "http://identity.example.com" } },
    ],
    [
      "localhost OIDC",
      { ...validConfig, oidc: { ...validConfig.oidc, url: "https://localhost" } },
    ],
    [
      "private OIDC",
      { ...validConfig, oidc: { ...validConfig.oidc, url: "https://10.0.0.1" } },
    ],
    [
      "internal OIDC",
      { ...validConfig, oidc: { ...validConfig.oidc, url: "https://identity.internal" } },
    ],
    [
      "IPv4-mapped loopback OIDC",
      {
        ...validConfig,
        oidc: { ...validConfig.oidc, url: "https://[::ffff:127.0.0.1]" },
      },
    ],
    ["cross-origin API base", { ...validConfig, api_base_path: "https://evil.invalid/api" }],
    ["query-bearing API base", { ...validConfig, api_base_path: "/api/v1?token=value" }],
    [
      "invalid build digest",
      { ...validConfig, build: { ...validConfig.build, contract_digest: "sha256:bad" } },
    ],
  ])("fails closed for %s", async (_name, value) => {
    const fetcher = vi.fn().mockResolvedValue(configResponse(value));
    await expect(loadBrowserConfig(fetcher)).rejects.toThrow(
      "Browser configuration unavailable",
    );
  });

  it("fails closed for redirects, non-JSON, oversized and unsuccessful responses", async () => {
    const redirect = vi.fn().mockResolvedValue(configResponse(validConfig, { status: 302 }));
    const nonJSON = vi
      .fn()
      .mockResolvedValue(new Response("<html></html>", { status: 200 }));
    const oversized = vi
      .fn()
      .mockResolvedValue(
        new Response("x".repeat(70_000), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    const unavailable = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ detail: "private upstream detail" }), {
        status: 503,
        headers: { "Content-Type": "application/problem+json" },
      }),
    );

    for (const fetcher of [redirect, nonJSON, oversized, unavailable]) {
      await expect(loadBrowserConfig(fetcher)).rejects.toThrow(
        "Browser configuration unavailable",
      );
    }
  });
});
