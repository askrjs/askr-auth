import { defineConfig } from "vite-plus";

export default defineConfig({
  test: {
    // Vitest v4 compatibility: preserve mock call history.
    // Remove after tests no longer rely on calls from setup or earlier tests.
    // https://viteplus.dev/guide/vitest-v5#remove-unneeded-compatibility-settings
    // https://vitest.dev/guide/migration/#clearmocks-is-enabled-by-default
    clearMocks: false,
  },
  pack: {
    entry: {
      index: "src/index.ts",
      jwt: "src/jwt.ts",
      oidc: "src/oidc.ts",
      server: "src/server.ts",
      "providers/auth0": "src/providers/auth0.ts",
      "providers/microsoft": "src/providers/microsoft.ts",
      "providers/google": "src/providers/google.ts",
      "providers/apple": "src/providers/apple.ts",
      saml: "src/saml.ts",
      mfa: "src/mfa.ts",
      "webauthn-client": "src/webauthn-client.ts",
    },
    format: ["esm"],
    outDir: "dist",
    platform: "neutral",
    dts: true,
    sourcemap: "hidden",
    deps: {
      // tsdown <0.23 compatibility: resolve external dependency subpaths.
      // Remove to preserve subpath imports as written (the new default).
      // https://tsdown.dev/options/dependencies#deps-resolvedepsubpath
      resolveDepSubpath: true,
      neverBundle: [/^node:/],
    },
  },
});
