import { defineConfig } from "vite-plus";

export default defineConfig({
  pack: {
    entry: {
      index: "src/index.ts",
      jwt: "src/jwt.ts",
      oidc: "src/oidc.ts",
      saml: "src/saml.ts",
      mfa: "src/mfa.ts",
    },
    format: ["esm"],
    outDir: "dist",
    platform: "neutral",
    dts: true,
    sourcemap: "hidden",
  },
});
