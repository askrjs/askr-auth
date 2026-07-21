import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "..");

describe("package architecture", () => {
  it("should give the expected result when keep public index barrels re-export only", () => {
    for (const file of ["src/index.ts", "src/jwt.ts", "src/oidc.ts", "src/saml.ts", "src/mfa.ts"]) {
      const source = readFileSync(resolve(root, file), "utf8");
      expect(
        source
          .split("\n")
          .filter(Boolean)
          .every((line) => line.startsWith("export ")),
      ).toBe(true);
    }
  });

  it("should give the expected result when keep production modules within the clean-break size limit", () => {
    for (const file of [
      "src/auth-cookie.ts",
      "src/auth-resolver.ts",
      "src/auth-types.ts",
      "src/jwt-claims.ts",
      "src/jwt-encoding.ts",
      "src/jwt-error.ts",
      "src/jwt-types.ts",
      "src/jwt-validator.ts",
      "src/model.ts",
      "src/oidc-client.ts",
      "src/oidc-crypto.ts",
      "src/oidc-discovery.ts",
      "src/oidc-token.ts",
      "src/oidc-types.ts",
      "src/requirements.ts",
      "src/saml-client.ts",
      "src/saml-crypto.ts",
      "src/saml-dom.ts",
      "src/saml-metadata.ts",
      "src/saml-request.ts",
      "src/saml-response.ts",
      "src/saml-types.ts",
      "src/cbor.ts",
      "src/cose.ts",
      "src/mfa-error.ts",
      "src/totp.ts",
      "src/webauthn.ts",
    ]) {
      expect(
        readFileSync(resolve(root, file), "utf8").split("\n").length,
        file,
      ).toBeLessThanOrEqual(300);
    }
  });
});
