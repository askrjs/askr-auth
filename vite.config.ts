import { defineConfig } from "vite-plus";

export default defineConfig({
  pack: {
    entry: {
      index: "src/index.ts",
      jwt: "src/jwt.ts",
      oidc: "src/oidc.ts",
      browser: "src/browser.ts",
      auth0: "src/auth0.ts",
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
      neverBundle: [/^node:/, /^@auth0\/auth0-spa-js$/],
    },
  },
});
