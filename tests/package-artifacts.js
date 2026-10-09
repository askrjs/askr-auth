import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, normalize } from "node:path";
import { readPackRecord } from "./pack-result.js";

const npmCli = process.env.npm_execpath;
if (!npmCli) throw new Error("Run artifact checks through npm run pack:check.");
const packRecord = readPackRecord(
  JSON.parse(
    execFileSync(process.execPath, [npmCli, "pack", "--ignore-scripts", "--dry-run", "--json"], {
      encoding: "utf8",
    }),
  ),
);

const packedFiles = new Set(packRecord.files.map(({ path }) => normalize(path)));
for (const required of [
  "dist/index.js",
  "dist/index.d.ts",
  "dist/jwt.js",
  "dist/jwt.d.ts",
  "dist/oidc.js",
  "dist/oidc.d.ts",
  "dist/browser.js",
  "dist/browser.d.ts",
  "dist/saml.js",
  "dist/saml.d.ts",
  "dist/mfa.js",
  "dist/mfa.d.ts",
  "dist/webauthn-client.js",
  "dist/webauthn-client.d.ts",
]) {
  if (!packedFiles.has(normalize(required)))
    throw new Error(`Packed artifact is missing ${required}.`);
}
const sourceMappingPattern = /[#@]\s*sourceMappingURL=([^\s*]+)/gu;

for (const file of packRecord.files) {
  if (!/\.(?:css|d\.ts|js)$/u.test(file.path)) continue;

  const source = readFileSync(file.path, "utf8");
  for (const match of source.matchAll(sourceMappingPattern)) {
    const reference = match[1];
    if (reference.startsWith("data:")) continue;
    if (/^[a-z][a-z\d+.-]*:/iu.test(reference)) {
      throw new Error(`${file.path} references external source map ${reference}.`);
    }

    const mapPath = normalize(join(dirname(file.path), decodeURIComponent(reference)));
    if (!packedFiles.has(mapPath)) {
      throw new Error(`${file.path} references missing packed source map ${mapPath}.`);
    }
  }
}
