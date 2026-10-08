import { execFileSync } from "node:child_process";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test, expect } from "@playwright/test";
import { readPackRecord } from "../pack-result.js";

const npmCli = process.env.npm_execpath;
if (!npmCli) throw new Error("Run the installed browser tests through npm run test:browser.");
const issuer = "https://login.example.test";
const keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...keys.publicKey.export({ format: "jwk" }), kid: "browser-key", alg: "RS256" };
let consumer;

test.beforeAll(async () => {
  consumer = await mkdtemp(join(tmpdir(), "askr-auth-browser-"));
  const record = readPackRecord(
    JSON.parse(
      execFileSync(
        process.execPath,
        [npmCli, "pack", "--ignore-scripts", "--json", "--pack-destination", consumer],
        { encoding: "utf8", timeout: 120_000 },
      ),
    ),
  );
  await writeFile(
    join(consumer, "package.json"),
    JSON.stringify({ private: true, type: "module" }),
  );
  execFileSync(
    process.execPath,
    [
      npmCli,
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      join(consumer, record.filename),
    ],
    {
      cwd: consumer,
      stdio: "pipe",
      timeout: 120_000,
    },
  );
}, 120_000);

test.afterAll(async () => {
  if (consumer) await rm(consumer, { recursive: true, force: true });
});

test.beforeEach(async ({ page }) => {
  await page.route("http://localhost/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/") {
      await route.fulfill({
        contentType: "text/html",
        body: '<script type="importmap">{"imports":{"@askrjs/auth/oidc":"/oidc.js"}}</script>',
      });
    } else if (/^\/[\w-]+\.js$/.test(path)) {
      await route.fulfill({
        contentType: "text/javascript",
        body: await readFile(
          join(consumer, "node_modules/@askrjs/auth/dist", path.slice(1)),
          "utf8",
        ),
      });
    } else {
      await route.abort();
    }
  });
  await page.goto("http://localhost/");
  expect(await page.evaluate(() => typeof globalThis.Buffer)).toBe("undefined");
});

function token(nonce = "browser-nonce", signingKey = keys.privateKey) {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const data = `${encode({ alg: "RS256", kid: jwk.kid })}.${encode({
    iss: issuer,
    aud: "browser-client",
    sub: "browser-user",
    name: "Zo\u00eb \u6771\u4eac",
    nonce,
    exp: Math.floor(Date.now() / 1000) + 3600,
  })}`;
  return `${data}.${sign("RSA-SHA256", Buffer.from(data), signingKey).toString("base64url")}`;
}

async function exchange(page, idToken) {
  return page.evaluate(
    async ({ issuer, jwk, idToken }) => {
      const { createOidcClient } = await import("@askrjs/auth/oidc");
      const calls = [];
      const client = createOidcClient({
        issuer,
        clientId: "browser-client",
        redirectUri: "http://localhost/callback",
        fetch: async (input, init) => {
          const url = String(input);
          calls.push(url);
          if (url === `${issuer}/.well-known/openid-configuration`) {
            return Response.json({
              issuer,
              authorization_endpoint: `${issuer}/authorize`,
              token_endpoint: `${issuer}/token`,
              jwks_uri: `${issuer}/jwks`,
            });
          }
          if (url === `${issuer}/jwks`) return Response.json({ keys: [jwk] });
          if (url === `${issuer}/token`) {
            const form = new URLSearchParams(init.body);
            if (form.get("code_verifier") !== "browser-verifier" || init.method !== "POST") {
              throw new Error("Invalid PKCE exchange.");
            }
            return Response.json({
              token_type: "Bearer",
              access_token: "access",
              id_token: idToken,
            });
          }
          throw new Error(`Unexpected OIDC request: ${url}`);
        },
      });
      const request = await client.createAuthorizationRequest({
        state: "browser-state",
        nonce: "browser-nonce",
        codeVerifier: "browser-verifier",
      });
      const authorization = new URL(request.url);
      if (
        authorization.searchParams.get("code_challenge_method") !== "S256" ||
        !authorization.searchParams.get("code_challenge")
      )
        throw new Error("Missing PKCE challenge.");
      try {
        const result = await client.exchangeCode({
          code: "signed-code",
          state: request.state,
          request,
        });
        return { result, calls };
      } catch (error) {
        return { code: error.code, cause: error.cause?.code, message: error.cause?.message, calls };
      }
    },
    { issuer, jwk, idToken },
  );
}

test("packed OIDC client completes a signed PKCE exchange without Node globals", async ({
  page,
}) => {
  const exchanged = await exchange(page, token());
  expect(exchanged).toMatchObject({
    result: {
      tokens: { access_token: "access" },
      principal: { id: "browser-user", name: "Zo\u00eb \u6771\u4eac", nonce: "browser-nonce" },
    },
  });
  expect(exchanged.calls).toEqual([
    `${issuer}/.well-known/openid-configuration`,
    `${issuer}/token`,
    `${issuer}/jwks`,
  ]);
});

test("packed OIDC client rejects a signature from a different key", async ({ page }) => {
  const wrongKeys = generateKeyPairSync("rsa", { modulusLength: 2048 });
  expect(await exchange(page, token("browser-nonce", wrongKeys.privateKey))).toMatchObject({
    code: "invalid-id-token",
    cause: "invalid_signature",
  });
});

test("packed OIDC client rejects a signed token with the wrong nonce", async ({ page }) => {
  expect(await exchange(page, token("wrong-nonce"))).toMatchObject({
    code: "invalid-id-token",
    cause: "invalid_claim",
    message: "OIDC ID token nonce is invalid.",
  });
});
