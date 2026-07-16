import "@testing-library/jest-dom/vitest";

import { cleanup } from "@testing-library/react";
import { afterAll, afterEach, beforeAll } from "vitest";

import { testServer } from "./msw/server";

beforeAll(() => {
  testServer.listen({ onUnhandledRequest: "error" });
});

afterEach(() => {
  cleanup();
  testServer.resetHandlers();
  document.cookie = "";
});

afterAll(() => {
  testServer.close();
});
