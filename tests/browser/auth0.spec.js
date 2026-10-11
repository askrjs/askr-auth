import { execFileSync, spawn } from "node:child_process";
import { generateKeyPairSync, sign } from "node:crypto";
import { access, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test, expect } from "@playwright/test";
import { readPackRecord } from "../pack-result.js";

const npmCli = process.env.npm_execpath;
if (!npmCli) throw new Error("Run SDK integration through npm run test:browser.");
const issuer = "https://login.auth0.example.test";
const keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
let consumer;
let mode;
let exchanges;
let claimOverride;
let releaseToken;
let tokenEntered;
let tokenWaiting;
let grants;
let authorizations;
let signatureDamaged;
let algorithm;
test.use({ ignoreHTTPSErrors: true });

test.beforeAll(async () => {
  consumer = await mkdtemp(join(tmpdir(), "askr-auth0-browser-"));
  const packed = readPackRecord(
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
      "--no-audit",
      "--no-fund",
      join(consumer, packed.filename),
      "@auth0/auth0-spa-js@2.28.3",
    ],
    { cwd: consumer, stdio: "pipe", timeout: 120_000 },
  );
  await expect(access(join(consumer, "node_modules/react"))).rejects.toThrow();
}, 120_000);

test.afterAll(async () => {
  if (consumer) await rm(consumer, { recursive: true, force: true });
});

test.beforeEach(async ({ page }) => {
  mode = "success";
  exchanges = 0;
  claimOverride = {};
  grants = [];
  authorizations = 0;
  signatureDamaged = false;
  algorithm = "RS256";
  tokenEntered = new Promise((resolve) => {
    tokenWaiting = resolve;
  });
  releaseToken = undefined;
  await page.route(`${issuer}/**`, async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const headers = {
      "access-control-allow-origin": "http://localhost",
      "access-control-allow-headers": "content-type,auth0-client",
      "access-control-allow-methods": "POST,GET,OPTIONS",
    };
    if (request.method() === "OPTIONS") {
      await route.fulfill({ status: 204, headers });
      return;
    }
    if (url.pathname === "/authorize") {
      authorizations++;
      const params = url.searchParams;
      const response =
        mode === "interaction"
          ? {
              state: params.get("state"),
              error: "login_required",
              error_description: "Provider session expired.",
            }
          : { state: params.get("state"), code: params.get("nonce") };
      await route.fulfill({
        contentType: "text/html",
        body:
          mode === "hold-iframe"
            ? "<p>Waiting for provider interaction</p>"
            : `<script>parent.postMessage(${JSON.stringify({ type: "authorization_response", response })},'http://localhost')</script>`,
      });
    } else if (url.pathname === "/oauth/token") {
      const exchange = ++exchanges;
      const form = request.headers()["content-type"]?.includes("json")
        ? JSON.parse(request.postData())
        : Object.fromEntries(new URLSearchParams(request.postData()));
      grants.push(form.grant_type);
      if (form.grant_type === "authorization_code") expect(form.code_verifier).toBeTruthy();
      else expect(form.refresh_token).toMatch(/^sdk-refresh-/u);
      expect(form.client_secret).toBeUndefined();
      tokenWaiting();
      if (mode === "hold")
        await new Promise((resolve) => {
          releaseToken = resolve;
        });
      if (mode === "denied") {
        await route.fulfill({
          status: 403,
          headers,
          json: { error: "access_denied", error_description: "Provider denied the grant." },
        });
        return;
      }
      const data = `${encode({ alg: algorithm, typ: "JWT" })}.${encode({ iss: `${issuer}/`, aud: "auth0-client", sub: "sdk-user", org_id: "org_demo", name: "Zoë 東京", nonce: form.code, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 3600, ...claimOverride })}`;
      const signature = sign("RSA-SHA256", Buffer.from(data), keys.privateKey);
      if (signatureDamaged) signature[0] ^= 1;
      await route.fulfill({
        headers,
        json: {
          access_token: `sdk-access-${exchange}`,
          token_type: "Bearer",
          expires_in: 180,
          ...(mode === "refresh" ? { refresh_token: `sdk-refresh-${exchange}` } : {}),
          id_token: `${data}.${signature.toString("base64url")}`,
        },
      });
    } else await route.abort();
  });
  await page.route("http://localhost/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/" || path === "/callback")
      await route.fulfill({
        contentType: "text/html",
        body: '<script type="importmap">{"imports":{"@askrjs/auth/auth0":"/auth/auth0.js","@auth0/auth0-spa-js":"/sdk.js"}}</script>',
      });
    else if (path === "/sdk.js")
      await route.fulfill({
        contentType: "text/javascript",
        body: await readFile(
          join(consumer, "node_modules/@auth0/auth0-spa-js/dist/auth0-spa-js.production.esm.js"),
          "utf8",
        ),
      });
    else if (/^\/auth\/[\w-]+\.js$/u.test(path))
      await route.fulfill({
        contentType: "text/javascript",
        body: await readFile(
          join(consumer, "node_modules/@askrjs/auth/dist", path.slice(6)),
          "utf8",
        ),
      });
    else await route.abort();
  });
  await page.goto("http://localhost/");
  await page.evaluate(async () => {
    const { createAuth0Session } = await import("@askrjs/auth/auth0");
    window.createSession = createAuth0Session;
    window.options = {
      domain: "https://login.auth0.example.test",
      clientId: "auth0-client",
      redirectUri: "http://localhost/callback",
      authorizationParams: { audience: "https://api.example.test", organization: "org_demo" },
      authorizationTimeoutSeconds: 1,
    };
    window.session = createAuth0Session(window.options);
  });
  expect(await page.evaluate(() => typeof Buffer)).toBe("undefined");
});
function encode(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}
async function callback(page) {
  return page.evaluate(async () => {
    const url = new URL(await window.session.login());
    window.loginParams = Object.fromEntries(url.searchParams);
    const callback = new URL("http://localhost/callback");
    callback.searchParams.set("state", url.searchParams.get("state"));
    callback.searchParams.set("code", url.searchParams.get("nonce"));
    return callback.href;
  });
}

test("normally installed official SDK owns PKCE, callback correlation and memory-only reload", async ({
  page,
}) => {
  const url = await callback(page);
  expect(await page.evaluate(() => window.loginParams)).toMatchObject({
    audience: "https://api.example.test",
    organization: "org_demo",
    client_id: "auth0-client",
    response_type: "code",
    code_challenge_method: "S256",
  });
  const result = await page.evaluate(async (url) => {
    const stored = Object.values(sessionStorage);
    window.session = window.createSession(window.options);
    const restored = await window.session.restore(url);
    const cached = await window.session.getToken();
    return {
      stored,
      restored,
      cached,
      sessionStorage: Object.values(sessionStorage),
      localStorage: Object.values(localStorage),
    };
  }, url);
  expect(result.stored).toHaveLength(1);
  expect(result.stored.join()).not.toMatch(/access_token|id_token|refresh_token/);
  expect(result.restored).toMatchObject({
    status: "authenticated",
    principal: { id: "sdk-user", name: "Zoë 東京" },
    accessToken: "sdk-access-1",
  });
  expect(result.cached).toEqual(result.restored);
  expect(exchanges).toBe(1);
  expect(result.sessionStorage).toEqual([]);
  expect(result.localStorage).toEqual([]);
  const replay = await page.evaluate(async (url) => {
    const session = window.createSession(window.options);
    try {
      await session.restore(url);
    } catch (error) {
      return { code: error.code, cause: error.cause?.error };
    }
  }, url);
  expect(replay).toEqual({ code: "invalid-transaction", cause: "missing_transaction" });
  const reloaded = await page.evaluate(async () => {
    window.session = window.createSession(window.options);
    return window.session.restore();
  });
  expect(reloaded).toMatchObject({ status: "authenticated", accessToken: "sdk-access-2" });
  expect(exchanges).toBe(2);
});

test("SDK cache hits keep absolute expiry and concurrent lead-time renewal is deduplicated", async ({
  page,
}) => {
  await page.clock.install();
  const first = await page.evaluate(() => window.session.getToken());
  await page.clock.fastForward(30_000);
  const cached = await page.evaluate(() => window.session.getToken());
  expect(cached).toEqual(first);
  expect(exchanges).toBe(1);
  await page.clock.fastForward(91_000);
  const renewed = await page.evaluate(() =>
    Promise.all([window.session.getToken(), window.session.getToken(), window.session.getToken()]),
  );
  expect(renewed.map((value) => value.accessToken)).toEqual([
    "sdk-access-2",
    "sdk-access-2",
    "sdk-access-2",
  ]);
  expect(exchanges).toBe(2);
  expect(renewed[0].expiresAt).toBeGreaterThan(first.expiresAt);
});

test("SDK state, nonce, issuer, audience and expiry failures remain authoritative", async ({
  page,
}) => {
  let url = await callback(page);
  const wrong = new URL(url);
  wrong.searchParams.set("state", "wrong");
  expect(
    await page.evaluate(async (url) => {
      try {
        await window.session.restore(url);
      } catch (error) {
        return { code: error.code, cause: error.cause?.error };
      }
    }, wrong.href),
  ).toEqual({ code: "invalid-transaction", cause: "state_mismatch" });
  for (const claims of [
    { nonce: "wrong" },
    { sub: "" },
    { aud: ["auth0-client", "another-client"], azp: "wrong" },
    { iss: "https://wrong.test/" },
    { aud: "wrong" },
    { exp: 1 },
  ]) {
    claimOverride = claims;
    url = await callback(page);
    expect(
      await page.evaluate(async (url) => {
        try {
          await window.session.restore(url);
        } catch (error) {
          return { code: error.code, cause: error.cause?.message };
        }
      }, url),
    ).toMatchObject({ code: "authorization-error", cause: expect.any(String) });
  }
});

test("SDK interaction and denial outcomes recover through a fresh explicit login", async ({
  page,
}) => {
  await page.clock.install();
  await page.evaluate(() => window.session.getToken());
  await page.clock.fastForward(121_000);
  mode = "interaction";
  expect(await page.evaluate(() => window.session.getToken())).toMatchObject({
    status: "interaction-required",
    error: "login_required",
  });
  mode = "denied";
  expect(
    await page.evaluate(async () => {
      try {
        await window.session.getToken();
      } catch (error) {
        return { code: error.code, cause: error.cause?.error };
      }
    }),
  ).toEqual({ code: "authorization-error", cause: "access_denied" });
  mode = "success";
  const url = await callback(page);
  expect(await page.evaluate((url) => window.session.restore(url), url)).toMatchObject({
    status: "authenticated",
  });
});

for (const operation of ["renewal", "callback"])
  for (const action of ["logout", "dispose", "login"])
    test(`pending SDK ${operation} cannot publish after ${action}`, async ({ page }) => {
      const pendingCallback = operation === "callback" ? await callback(page) : undefined;
      mode = "hold";
      await page.evaluate((url) => {
        window.pending = (url ? window.session.restore(url) : window.session.getToken()).then(
          (result) => result,
          (error) => ({ code: error.code }),
        );
      }, pendingCallback);
      await tokenEntered;
      await page.evaluate(() => {
        window.joined = window.session.getToken().then(
          (result) => result,
          (error) => ({ code: error.code }),
        );
      });
      await page.evaluate(async (action) => {
        if (action === "login") await window.session.login();
        else window.session[action]();
      }, action);
      expect(await page.evaluate(() => window.pending)).toEqual({ code: "cancelled" });
      expect(await page.evaluate(() => window.joined)).toEqual({ code: "cancelled" });
      mode = "success";
      releaseToken();
      if (action === "dispose")
        expect(
          await page.evaluate(() => {
            try {
              window.session.getToken();
            } catch (error) {
              return error.code;
            }
          }),
        ).toBe("disposed");
      else {
        // Re-enter through a new SDK-owned redirect transaction after stale transport settles.
        const fresh = await callback(page);
        expect(await page.evaluate((url) => window.session.restore(url), fresh)).toMatchObject({
          status: "authenticated",
          accessToken: "sdk-access-2",
        });
      }
      expect(page.url()).toBe("http://localhost/");
    });

test("retired SDK redirect preparation cannot overwrite a newer login transaction", async ({
  page,
}) => {
  await page.evaluate(() => {
    const digest = crypto.subtle.digest.bind(crypto.subtle);
    let first = true;
    crypto.subtle.digest = async (...args) => {
      if (first) {
        first = false;
        window.digestEntered = true;
        await new Promise((resolve) => {
          window.releaseDigest = resolve;
        });
      }
      return digest(...args);
    };
    window.oldLogin = window.session.login().then(
      () => "stale-url",
      (error) => error.code,
    );
  });
  await page.waitForFunction(() => window.digestEntered);
  await page.evaluate(() => {
    window.session.logout();
    window.newLogin = window.session.login();
  });
  expect(await page.evaluate(() => window.oldLogin)).toBe("cancelled");
  await page.evaluate(() => window.releaseDigest());
  const url = await page.evaluate(async () => {
    const authorization = new URL(await window.newLogin);
    const callback = new URL("http://localhost/callback");
    callback.searchParams.set("state", authorization.searchParams.get("state"));
    callback.searchParams.set("code", authorization.searchParams.get("nonce"));
    return callback.href;
  });
  expect(await page.evaluate((url) => window.session.restore(url), url)).toMatchObject({
    status: "authenticated",
  });
  expect(exchanges).toBe(1);
});

test("standalone SDK SPA normally installs, navigates, restores, renews and logs out", async ({
  page,
}) => {
  const installed = JSON.parse(
    await readFile(join(consumer, "node_modules/@askrjs/auth/package.json"), "utf8"),
  );
  const example = JSON.parse(
    await readFile(new URL("../../examples/auth0-session/package.json", import.meta.url), "utf8"),
  );
  expect(example.dependencies["@askrjs/auth"]).toBe(
    `file:../../askrjs-auth-${installed.version}.tgz`,
  );
  for (const file of ["server.mjs", "index.html", "localhost-key.pem", "localhost-cert.pem"])
    await writeFile(
      join(consumer, file),
      await readFile(new URL(`../../examples/auth0-session/${file}`, import.meta.url)),
    );
  const server = spawn(process.execPath, [join(consumer, "server.mjs")], {
    cwd: consumer,
    env: { ...process.env, ASKR_AUTH_DEMO_PORT: "0" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  server.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  try {
    const origin = await new Promise((resolve, reject) => {
      let output = "";
      const timer = setTimeout(
        () => reject(new Error(`SDK demo startup timeout: ${stderr}`)),
        10_000,
      );
      server.once("exit", (code) => {
        clearTimeout(timer);
        reject(new Error(`SDK demo exited ${code}: ${stderr}`));
      });
      server.stdout.on("data", (chunk) => {
        output += chunk;
        const match = /Demo ready at (https:\/\/127\.0\.0\.1:\d+)/u.exec(output);
        if (match) {
          clearTimeout(timer);
          resolve(match[1]);
        }
      });
    });
    await page.goto(origin);
    await expect(page.locator("#status")).toContainText("Interaction required: login_required");
    await page.locator("#login").click();
    await expect(page.locator("#status")).toContainText("Signed in as Demo user");
    await expect(page).toHaveURL(`${origin}/`);
    const expiry = await page.locator("#status").textContent();
    await page.locator("#reload").click();
    await expect(page.locator("#status")).toContainText("Signed in as Demo user");
    await page.clock.install();
    await page.clock.fastForward(121_000);
    await page.locator("#token").click();
    await expect(page.locator("#status")).toContainText("Signed in as Demo user");
    await expect(page.locator("#status")).not.toHaveText(expiry);
    await page.locator("#logout").click();
    await expect(page.locator("#status")).toHaveText("Signed out.");
    await page.locator("#reload").click();
    await expect(page.locator("#status")).toContainText("Interaction required: login_required");
    await page.locator("#login").click();
    await expect(page.locator("#status")).toContainText("Signed in as Demo user");
    expect(
      await page.evaluate(() => ({
        buffer: typeof Buffer,
        localStorage: Object.values(localStorage),
        sessionStorage: Object.values(sessionStorage),
      })),
    ).toEqual({ buffer: "undefined", localStorage: [], sessionStorage: [] });
  } finally {
    server.kill();
    await new Promise((resolve) => {
      if (server.exitCode !== null) resolve();
      else server.once("exit", resolve);
    });
  }
});

test("explicit refresh-token renewal stays in the SDK memory cache and rotates without an iframe", async ({
  page,
}) => {
  mode = "refresh";
  await page.clock.install();
  await page.evaluate(() => {
    window.session.dispose();
    window.session = window.createSession({ ...window.options, useRefreshTokens: true });
  });
  const url = await callback(page);
  expect(await page.evaluate(() => window.loginParams.scope)).toContain("offline_access");
  await page.evaluate((url) => window.session.restore(url), url);
  await page.clock.fastForward(121_000);
  const renewed = await page.evaluate(() =>
    Promise.all([window.session.getToken(), window.session.getToken()]),
  );
  expect(renewed.map((value) => value.accessToken)).toEqual(["sdk-access-2", "sdk-access-2"]);
  expect(grants).toEqual(["authorization_code", "refresh_token"]);
  expect(authorizations).toBe(0);
  expect(
    await page.evaluate(() => ({
      local: Object.values(localStorage),
      session: Object.values(sessionStorage),
    })),
  ).toEqual({ local: [], session: [] });
  await page.evaluate(() => window.session.logout());
  expect(
    await page.evaluate(async () => {
      try {
        await window.session.getToken();
      } catch (error) {
        return { code: error.code, cause: error.cause?.error };
      }
    }),
  ).toEqual({ code: "authorization-error", cause: "missing_refresh_token" });
});

test("SDK timeout remains a typed cause and removes its waiting iframe", async ({ page }) => {
  mode = "hold-iframe";
  await page.evaluate(() => {
    window.session.dispose();
    window.session = window.createSession({ ...window.options, authorizationTimeoutSeconds: 0.05 });
  });
  expect(
    await page.evaluate(async () => {
      try {
        await window.session.getToken();
      } catch (error) {
        return { code: error.code, cause: error.cause?.error };
      }
    }),
  ).toEqual({ code: "authorization-error", cause: "timeout" });
  await expect(page.locator("iframe")).toHaveCount(0);
});

test("qualified SDK checks the algorithm label but does not provide native signature verification", async ({
  page,
}) => {
  algorithm = "HS256";
  expect(
    await page.evaluate(async () => {
      try {
        await window.session.getToken();
      } catch (error) {
        return error.code;
      }
    }),
  ).toBe("authorization-error");
  algorithm = "RS256";
  signatureDamaged = true;
  // Intentional SDK characterization: the native OIDC suite rejects a bad
  // signature; this path delegates to SDK claim handling and must not claim it.
  expect(await page.evaluate(() => window.session.getToken())).toMatchObject({
    status: "authenticated",
    principal: { id: "sdk-user" },
  });
});
