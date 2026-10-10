import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { access, mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import ts from "@typescript/typescript6";
import { readPackRecord } from "./pack-result.js";

const npmCli = process.env.npm_execpath;
if (!npmCli) throw new Error("Run packed checks through npm run test:packed.");
const root = process.cwd();
const runNpm = (args, options) => execFileSync(process.execPath, [npmCli, ...args], options);
const contract = JSON.parse(await readFile("tests/public-contract.json", "utf8"));
const consumer = await mkdtemp(join(tmpdir(), "askr-auth-contract-"));
try {
  const packed = readPackRecord(
    JSON.parse(
      runNpm(["pack", "--ignore-scripts", "--json", "--pack-destination", consumer], {
        encoding: "utf8",
      }),
    ),
  );
  await writeFile(
    join(consumer, "package.json"),
    JSON.stringify({ private: true, type: "module" }),
  );
  runNpm(
    ["install", "--no-audit", "--no-fund", "--no-package-lock", join(consumer, packed.filename)],
    { cwd: consumer, stdio: "pipe" },
  );
  await assert.rejects(access(join(consumer, "node_modules/@auth0/auth0-spa-js")));
  const manifest = JSON.parse(
    await readFile(join(consumer, "node_modules/@askrjs/auth/package.json"), "utf8"),
  );
  assert.deepEqual(Object.keys(manifest.exports).sort(), contract.exportKeys);
  assert.equal(manifest.peerDependencies["@auth0/auth0-spa-js"], "^2.28.3");
  assert.equal(manifest.peerDependenciesMeta["@auth0/auth0-spa-js"].optional, true);
  const imports = contract.entrypoints
    .map((entry, index) => `import * as Entry${index} from '${entry.specifier}';`)
    .join("\n");
  const negatives = contract.entrypoints
    .flatMap((entry, index) =>
      entry.removed.map(
        (name) =>
          `// @ts-expect-error Removed public export must stay private.\nimport type { ${name} as Removed${index}_${name} } from '${entry.specifier}';`,
      ),
    )
    .join("\n");
  await writeFile(
    join(consumer, "fixture.ts"),
    `${imports}\n${negatives}
    const principal: Entry0.Principal = { id: 'user', roles: ['admin'] };
    const requirement: Entry0.AuthRequirement = Entry0.requireRole('admin');
    const jwt: Entry1.JwtValidatorOptions = { issuer: 'issuer', jwks: { keys: [] }, clock: () => 0 };
    const oidc: Entry2.OidcClientOptions = { issuer: 'https://issuer.test', clientId: 'client', redirectUri: 'https://app.test/callback' };
    const browser: Entry3.BrowserOidcSessionOptions = { ...oidc, authorizationParams: { audience: "https://api.test" }, silent: { responseFormat: "auth0" } };
    const sdk: Entry7.Auth0SessionOptions = { domain: "tenant.auth0.com", clientId: "client", redirectUri: "https://app.test/callback" };
    // @ts-expect-error SDK persistence/cache configuration is deliberately not an Askr option.
    const persistent: Entry7.Auth0SessionOptions = { ...sdk, cacheLocation: "localstorage" };
    // @ts-expect-error Response formats must be explicitly selected.
    const guessed: Entry3.BrowserOidcSessionOptions = { ...oidc, silent: { responseFormat: "auto" } };
    void [sdk, persistent, guessed];
    const totp: Entry5.VerifyTotpOptions = { secret: 'secret', code: '123456', at: new Date() };
    const algorithm: Entry5.CoseAlgorithm = -7;
    const challenge: Entry6.GetPasskeyAssertionOptions = { challenge: 'AQID', rpId: 'app.test' };
    // @ts-expect-error An authenticated principal needs an application identity.
    const missing: Entry0.Principal = {};
    // @ts-expect-error Only supported WebAuthn key algorithms can be persisted.
    const unsupported: Entry5.CoseAlgorithm = -999;
    void [principal, requirement, jwt, oidc, browser, totp, algorithm, challenge, missing, unsupported];
  `,
  );
  await writeFile(
    join(consumer, "tsconfig.json"),
    JSON.stringify({
      compilerOptions: {
        target: "ES2022",
        module: "NodeNext",
        moduleResolution: "NodeNext",
        strict: true,
        noEmit: true,
        types: [],
        lib: ["ES2022", "DOM"],
      },
      files: ["fixture.ts"],
    }),
  );
  execFileSync(
    process.execPath,
    [join(root, "node_modules/typescript/bin/tsc"), "-p", "tsconfig.json"],
    { cwd: consumer, stdio: "pipe" },
  );
  const fixture = join(consumer, "fixture.ts");
  const program = ts.createProgram([fixture], {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext,
    strict: true,
    noEmit: true,
    types: [],
    lib: ["lib.es2022.d.ts", "lib.dom.d.ts"],
  });
  const diagnostics = ts.getPreEmitDiagnostics(program);
  assert.equal(
    diagnostics.length,
    0,
    ts.formatDiagnosticsWithColorAndContext(diagnostics, {
      getCanonicalFileName: (file) => file,
      getCurrentDirectory: () => consumer,
      getNewLine: () => "\n",
    }),
  );
  const checker = program.getTypeChecker();
  for (const entry of contract.entrypoints) {
    const declaration = program
      .getSourceFile(fixture)
      .statements.find(
        (statement) =>
          ts.isImportDeclaration(statement) && statement.moduleSpecifier.text === entry.specifier,
      );
    const symbols = checker
      .getExportsOfModule(checker.getSymbolAtLocation(declaration.moduleSpecifier))
      .map((symbol) => symbol.name)
      .sort();
    assert.deepEqual(
      symbols,
      [...entry.values, ...entry.types].sort(),
      `${entry.specifier} declaration surface`,
    );
  }
  await writeFile(
    join(consumer, "runtime.mjs"),
    `
    import assert from 'node:assert/strict';
    import { generateKeyPairSync } from 'node:crypto';
    assert.equal(typeof globalThis.window, "undefined");
    for (const entry of ${JSON.stringify(contract.entrypoints.filter((entry) => entry.specifier !== "@askrjs/auth/auth0"))}) {
      const values = await import(entry.specifier);
      assert.deepEqual(Object.keys(values).sort(), entry.values, entry.specifier);
    }
    for (const path of ${JSON.stringify(contract.privateSubpaths)})
      await assert.rejects(import('@askrjs/auth/' + path), { code: 'ERR_PACKAGE_PATH_NOT_EXPORTED' });
    const { createJwtIssuer, createJwtValidator } = await import('@askrjs/auth/jwt');
    const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const tokenIssuer = createJwtIssuer({ privateKey: pair.privateKey.export({ format: 'jwk' }), kid: 'key', issuer: 'issuer', audience: 'api', ttlSeconds: 60, clock: () => 100 });
    const token = await tokenIssuer.issue({ subject: 'user', roles: ['admin'] });
    assert.equal((await tokenIssuer.validator.validate(token)).id, 'user');
    const keys = { keys: [{ ...pair.publicKey.export({ format: 'jwk' }), kid: 'key', alg: 'RS256' }] };
    await assert.rejects(createJwtValidator({ issuer: 'issuer', jwks: keys, clock: () => NaN }).validate(token), TypeError);
    await assert.rejects(createJwtValidator({ issuer: 'issuer', jwks: keys, clock: () => 160 }).validate(token), { code: 'invalid_claim' });
    const { verifyTotpCode } = await import('@askrjs/auth/mfa');
    const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
    assert.deepEqual(await verifyTotpCode({ secret, code: '755224', at: 0, window: 1 }), { valid: true, counter: 0, drift: 0 });
    await assert.rejects(verifyTotpCode({ secret, code: '000000', at: NaN }), { code: 'malformed-input' });
  `,
  );
  execFileSync(process.execPath, [join(consumer, "runtime.mjs")], { cwd: consumer, stdio: "pipe" });
  // The adapter is opt-in: importing it without its optional SDK fails, while
  // all native/server paths and every declaration above work without that peer.
  await writeFile(
    join(consumer, "adapter-missing.mjs"),
    `import assert from 'node:assert/strict'; await assert.rejects(import('@askrjs/auth/auth0'), { code: 'ERR_MODULE_NOT_FOUND' });`,
  );
  execFileSync(process.execPath, [join(consumer, "adapter-missing.mjs")], {
    cwd: consumer,
    stdio: "pipe",
  });
  runNpm(["install", "--no-audit", "--no-fund", "@auth0/auth0-spa-js@2.28.3"], {
    cwd: consumer,
    stdio: "pipe",
  });
  await writeFile(
    join(consumer, "adapter-installed.mjs"),
    `import assert from 'node:assert/strict'; import * as adapter from '@askrjs/auth/auth0'; assert.deepEqual(Object.keys(adapter), ['createAuth0Session']); assert.equal(typeof globalThis.window, 'undefined');`,
  );
  execFileSync(process.execPath, [join(consumer, "adapter-installed.mjs")], {
    cwd: consumer,
    stdio: "pipe",
  });
  const compilers = [];
  for (const compiler of ["typescript", "@typescript/typescript6"]) {
    const executable = join(root, "node_modules", compiler, "bin/tsc");
    compilers.push(
      execFileSync(process.execPath, [executable, "--version"], { encoding: "utf8" })
        .trim()
        .replace(/^Version /, ""),
    );
    execFileSync(process.execPath, [executable, "-p", "tsconfig.json"], {
      cwd: consumer,
      stdio: "pipe",
    });
  }
  console.log(
    JSON.stringify({
      declarationNames: contract.entrypoints.reduce(
        (count, entry) => count + entry.values.length + entry.types.length,
        0,
      ),
      removedNames: contract.entrypoints.reduce((count, entry) => count + entry.removed.length, 0),
      privateSubpaths: contract.privateSubpaths.length,
      compilers,
      normalInstall: true,
      nativeSdkAbsent: true,
      optionalSdkNormalInstall: "2.28.3",
    }),
  );
} finally {
  await rm(consumer, { recursive: true, force: true });
}
