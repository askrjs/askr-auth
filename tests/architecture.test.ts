import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "..");

describe("package architecture", () => {
  it("should keep public index barrels re-export only", () => {
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
});
