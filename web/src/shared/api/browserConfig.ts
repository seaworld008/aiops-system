import { z } from "zod";

import type { components } from "./schema";

type GeneratedBrowserConfig = components["schemas"]["BrowserConfig"];
type GeneratedOIDCConfig = GeneratedBrowserConfig["oidc"];

export type OIDCConfig = Omit<GeneratedOIDCConfig, "client_id"> & {
  clientId: GeneratedOIDCConfig["client_id"];
};

export type BrowserConfig = Omit<
  GeneratedBrowserConfig,
  "oidc" | "api_base_path"
> & {
  oidc: OIDCConfig;
  apiBasePath: GeneratedBrowserConfig["api_base_path"];
};

export type BrowserConfigFetcher = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

const safeBuildValue = z
  .string()
  .min(1)
  .max(128)
  .refine((value) => value === value.trim() && !hasControl(value));

const browserConfigSchema = z
  .object({
    oidc: z
      .object({
        url: z.string().min(1).max(2048),
        realm: z
          .string()
          .regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/),
        client_id: z.literal("control-plane-web"),
      })
      .strict(),
    api_base_path: z.literal("/api/v1"),
    build: z
      .object({
        version: safeBuildValue,
        commit: safeBuildValue,
        contract_digest: z.string().regex(/^sha256:[a-f0-9]{64}$/),
      })
      .strict(),
  })
  .strict();

const maximumBrowserConfigBytes = 65_536;

export async function loadBrowserConfig(
  fetcher: BrowserConfigFetcher = globalThis.fetch.bind(globalThis),
): Promise<BrowserConfig> {
  try {
    const response = await fetcher("/api/v1/browser-config", {
      method: "GET",
      headers: { Accept: "application/json" },
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
    });
    const contentType = response.headers.get("Content-Type")?.toLowerCase() ?? "";
    const declaredLength = Number(response.headers.get("Content-Length") ?? "0");
    if (
      response.status !== 200 ||
      response.redirected ||
      !contentType.startsWith("application/json") ||
      !Number.isSafeInteger(declaredLength) ||
      declaredLength < 0 ||
      declaredLength > maximumBrowserConfigBytes
    ) {
      throw new Error("closed response rejected");
    }
    const text = await response.text();
    if (text.length === 0 || new TextEncoder().encode(text).length > maximumBrowserConfigBytes) {
      throw new Error("closed response rejected");
    }
    const parsed = browserConfigSchema.parse(JSON.parse(text));
    if (!isPublicHTTPSOIDCURL(parsed.oidc.url)) {
      throw new Error("OIDC URL rejected");
    }
    return {
      oidc: {
        url: parsed.oidc.url,
        realm: parsed.oidc.realm,
        clientId: parsed.oidc.client_id,
      },
      apiBasePath: parsed.api_base_path,
      build: parsed.build,
    };
  } catch {
    throw new Error("Browser configuration unavailable");
  }
}

function isPublicHTTPSOIDCURL(value: string): boolean {
  if (
    value !== value.trim() ||
    hasControl(value) ||
    value.includes("\\") ||
    /\/(?:\.{1,2})(?:\/|$)/.test(value)
  ) {
    return false;
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.search !== "" ||
    parsed.hash !== ""
  ) {
    return false;
  }
  return isPublicOIDCHost(parsed.hostname);
}

function isPublicOIDCHost(value: string): boolean {
  const host = value.toLowerCase();
  if (host !== value || host === "" || host.length > 253 || host.endsWith(".")) {
    return false;
  }
  if (host.startsWith("[") && host.endsWith("]")) {
    const address = host.slice(1, -1);
    const mappedIPv4 = ipv4FromMappedIPv6(address);
    if (mappedIPv4 !== undefined) {
      return isPublicIPv4(mappedIPv4);
    }
    return (
      address !== "::1" &&
      address !== "::" &&
      !/^(?:fc|fd|fe[89ab])/i.test(address) &&
      !/^ff/i.test(address) &&
      !/^2001:db8:/i.test(address)
    );
  }
  const ipv4 = parseIPv4(host);
  if (ipv4 !== undefined) {
    return isPublicIPv4(ipv4);
  }
  for (const suffix of [
    "localhost",
    ".localhost",
    ".local",
    ".internal",
    ".invalid",
    ".test",
    ".home.arpa",
  ]) {
    if (host === suffix.replace(/^\./, "") || host.endsWith(suffix)) {
      return false;
    }
  }
  const labels = host.split(".");
  if (labels.length < 2) {
    return false;
  }
  return labels.every(
    (label) =>
      label.length > 0 &&
      label.length <= 63 &&
      !label.startsWith("-") &&
      !label.endsWith("-") &&
      /^[a-z0-9-]+$/.test(label),
  );
}

function parseIPv4(value: string): readonly [number, number, number, number] | undefined {
  const parts = value.split(".");
  if (parts.length !== 4) {
    return undefined;
  }
  const octets = parts.map((part) => {
    if (!/^(?:0|[1-9][0-9]{0,2})$/.test(part)) {
      return Number.NaN;
    }
    return Number(part);
  });
  if (octets.some((octet) => !Number.isInteger(octet) || octet > 255)) {
    return undefined;
  }
  return [octets[0] ?? 0, octets[1] ?? 0, octets[2] ?? 0, octets[3] ?? 0];
}

function ipv4FromMappedIPv6(
  value: string,
): readonly [number, number, number, number] | undefined {
  if (!value.startsWith("::ffff:")) {
    return undefined;
  }
  const suffix = value.slice("::ffff:".length);
  const dotted = parseIPv4(suffix);
  if (dotted !== undefined) {
    return dotted;
  }
  const words = suffix.split(":");
  if (words.length !== 2 || words.some((word) => !/^[a-f0-9]{1,4}$/.test(word))) {
    return undefined;
  }
  const high = Number.parseInt(words[0] ?? "", 16);
  const low = Number.parseInt(words[1] ?? "", 16);
  if (!Number.isInteger(high) || !Number.isInteger(low)) {
    return undefined;
  }
  return [high >> 8, high & 0xff, low >> 8, low & 0xff];
}

function isPublicIPv4(
  value: readonly [number, number, number, number],
): boolean {
  const [first, second] = value;
  return !(
    first === 0 ||
    first === 10 ||
    first === 127 ||
    first >= 224 ||
    (first === 100 && second >= 64 && second <= 127) ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168) ||
    (first === 192 && second === 0) ||
    (first === 198 && (second === 18 || second === 19)) ||
    (first === 198 && second === 51) ||
    (first === 203 && second === 0)
  );
}

function hasControl(value: string): boolean {
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (code <= 31 || code === 127) {
      return true;
    }
  }
  return false;
}
