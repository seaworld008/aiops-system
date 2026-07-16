import { http, HttpResponse } from "msw";

import {
  browserConfigFixture,
  sessionFixture,
} from "./fixtures";

const noStoreHeaders = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Trace-ID": "1".repeat(32),
};

export const handlers = [
  http.get("/api/v1/browser-config", () =>
    HttpResponse.json(browserConfigFixture, {
      headers: noStoreHeaders,
    }),
  ),
  http.get("/api/v1/session", () =>
    HttpResponse.json(sessionFixture, {
      headers: noStoreHeaders,
    }),
  ),
];
