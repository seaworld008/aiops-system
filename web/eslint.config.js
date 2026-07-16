import js from "@eslint/js";
import path from "node:path";
import { fileURLToPath } from "node:url";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import globals from "globals";
import tseslint from "typescript-eslint";

const rootDirectory = fileURLToPath(new URL(".", import.meta.url));

function layerForFile(filename) {
  const normalized = filename.split(path.sep).join("/");
  const marker = "/src/";
  const sourceIndex = normalized.lastIndexOf(marker);
  if (sourceIndex === -1) {
    return undefined;
  }
  const [layer, feature] = normalized.slice(sourceIndex + marker.length).split("/");
  return { layer, feature };
}

function targetForImport(filename, source) {
  if (source.startsWith("@/")) {
    return layerForFile(path.join(rootDirectory, "src", source.slice(2)));
  }
  if (source.startsWith(".")) {
    return layerForFile(path.resolve(path.dirname(filename), source));
  }
  return undefined;
}

const architecturePlugin = {
  rules: {
    "layer-direction": {
      meta: {
        type: "problem",
        schema: [],
        messages: {
          invalidLayer: "{{sourceLayer}} must not import {{targetLayer}}",
          crossFeature: "features must not import another feature directly",
        },
      },
      create(context) {
        const source = layerForFile(context.filename);
        if (source === undefined) {
          return {};
        }
        return {
          ImportDeclaration(node) {
            const imported = targetForImport(context.filename, node.source.value);
            if (imported === undefined) {
              return;
            }
            if (
              source.layer === "shared" &&
              (imported.layer === "app" || imported.layer === "features")
            ) {
              context.report({
                node,
                messageId: "invalidLayer",
                data: { sourceLayer: "shared", targetLayer: imported.layer },
              });
            }
            if (source.layer === "features" && imported.layer === "app") {
              context.report({
                node,
                messageId: "invalidLayer",
                data: { sourceLayer: "features", targetLayer: "app" },
              });
            }
            if (
              source.layer === "features" &&
              imported.layer === "features" &&
              source.feature !== imported.feature
            ) {
              context.report({ node, messageId: "crossFeature" });
            }
          },
        };
      },
    },
    "shared-api-only-network": {
      meta: {
        type: "problem",
        schema: [],
        messages: {
          restricted: "network primitives are allowed only in src/shared/api",
        },
      },
      create(context) {
        const normalized = context.filename.split(path.sep).join("/");
        if (normalized.includes("/src/shared/api/")) {
          return {};
        }
        return {
          CallExpression(node) {
            const directFetch =
              node.callee.type === "Identifier" && node.callee.name === "fetch";
            const globalFetch =
              node.callee.type === "MemberExpression" &&
              node.callee.computed === false &&
              node.callee.property.type === "Identifier" &&
              node.callee.property.name === "fetch" &&
              node.callee.object.type === "Identifier" &&
              (node.callee.object.name === "window" ||
                node.callee.object.name === "globalThis");
            const sendBeacon =
              node.callee.type === "MemberExpression" &&
              node.callee.computed === false &&
              node.callee.property.type === "Identifier" &&
              node.callee.property.name === "sendBeacon";
            if (directFetch || globalFetch || sendBeacon) {
              context.report({ node, messageId: "restricted" });
            }
          },
          NewExpression(node) {
            const directNetworkConstructor =
              node.callee.type === "Identifier" &&
              ["XMLHttpRequest", "EventSource", "WebSocket"].includes(node.callee.name);
            const memberNetworkConstructor =
              node.callee.type === "MemberExpression" &&
              node.callee.computed === false &&
              node.callee.property.type === "Identifier" &&
              ["XMLHttpRequest", "EventSource", "WebSocket"].includes(
                node.callee.property.name,
              ) &&
              node.callee.object.type === "Identifier" &&
              (node.callee.object.name === "window" ||
                node.callee.object.name === "globalThis");
            if (directNetworkConstructor || memberNetworkConstructor) {
              context.report({ node, messageId: "restricted" });
            }
          },
        };
      },
    },
  },
};

export default tseslint.config(
  {
    ignores: [
      "dist/**",
      "coverage/**",
      "playwright-report/**",
      "test-results/**",
      "src/shared/api/schema.d.ts",
      "**/__snapshots__/**",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    ...tseslint.configs.disableTypeChecked,
    files: ["**/*.js"],
    languageOptions: {
      ...tseslint.configs.disableTypeChecked.languageOptions,
      globals: {
        ...globals.node,
      },
    },
  },
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: rootDirectory,
      },
      globals: {
        ...globals.browser,
        ...globals.es2024,
      },
    },
    plugins: {
      architecture: architecturePlugin,
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      ...reactHooks.configs.flat.recommended.rules,
      ...reactRefresh.configs.vite.rules,
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-non-null-assertion": "error",
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/no-misused-promises": "error",
      "architecture/layer-direction": "error",
      "architecture/shared-api-only-network": "error",
      "no-console": "error",
      "no-restricted-imports": [
        "error",
        {
          "patterns": [
            {
              "group": ["node:*"],
              "message": "Node built-ins are not available in the browser bundle",
            },
            {
              "group": ["@/test/**", "../test/**", "../../test/**", "../../../test/**"],
              "message": "test fakes must not be imported by production modules",
            },
          ],
        },
      ],
    },
  },
  {
    files: ["vite.config.ts"],
    languageOptions: {
      globals: {
        ...globals.node,
      },
    },
  },
  {
    files: ["src/app/scope/ScopeProvider.tsx", "src/app/providers.tsx"],
    rules: {
      "react-refresh/only-export-components": "off",
    },
  },
  {
    files: ["src/shared/ui/DataTable.tsx"],
    rules: {
      "react-hooks/incompatible-library": "off",
    },
  },
  {
    files: ["**/*.test.{ts,tsx}", "src/test/**/*.{ts,tsx}"],
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.es2024,
        ...globals.node,
      },
    },
    rules: {
      "no-console": "off",
      "no-restricted-imports": "off",
    },
  },
);
