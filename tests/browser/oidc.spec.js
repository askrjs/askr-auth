import { execFileSync, spawn } from "node:child_process";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { test, expect } from "@playwright/test";
import { readPackRecord } from "../pack-result.js";

const npmCli = process.env.npm_execpath;
if (!npmCli) throw new Error("Run the installed browser tests through npm run test:browser.");
const issuer = "https://login.example.test";
test.use({ ignoreHTTPSErrors: true });
const keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...keys.publicKey.export({ format: "jwk" }), kid: "browser-key", alg: "RS256" };
let consumer;
let silentMode = "success";
let tokenExchanges = 0;

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
  silentMode = "success";
  tokenExchanges = 0;
  await page.route(`${issuer}/**`, async (route) => {
    const url = new URL(route.request().url());
    const headers = { "access-control-allow-origin": "http://localhost" };
    if (url.pathname === "/.well-known/openid-configuration") {
      await route.fulfill({
        headers,
        json: {
          issuer,
          authorization_endpoint: `${issuer}/authorize`,
          token_endpoint: `${issuer}/token`,
          jwks_uri: `${issuer}/jwks`,
        },
      });
    } else if (url.pathname === "/jwks") {
      await route.fulfill({ headers, json: { keys: [jwk] } });
    } else if (url.pathname === "/token") {
      tokenExchanges += 1;
      const form = new URLSearchParams(route.request().postData());
      if (!form.get("code_verifier") || form.get("client_secret"))
        throw new Error("Expected public PKCE exchange.");
      const [nonce, subject = "browser-user"] = form.get("code").split("|");
      await route.fulfill({
        headers,
        json: {
          access_token: `access-${tokenExchanges}`,
          token_type: "Bearer",
          expires_in: 60,
          id_token: token(nonce, keys.privateKey, subject),
          refresh_token: "discard-this-refresh-token",
        },
      });
    } else if (url.pathname === "/authorize") {
      const state = url.searchParams.get("state");
      const nonce = url.searchParams.get("nonce");
      const response =
        silentMode === "interaction" ? { state, error: "login_required" } : { state, code: nonce };
      await route.fulfill({
        contentType: "text/html",
        body:
          silentMode === "hold"
            ? "<p>waiting</p>"
            : `<script>parent.postMessage(${JSON.stringify(response)}, 'http://localhost')</script>`,
      });
    } else await route.abort();
  });
  await page.route("http://localhost/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/") {
      await route.fulfill({
        contentType: "text/html",
        body: '<script type="importmap">{"imports":{"@askrjs/auth/oidc":"/oidc.js","@askrjs/auth/browser":"/browser.js"}}</script>',
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

test("browser session keeps redirect correlation one-time and tokens in memory", async ({
  page,
}) => {
  const result = await page.evaluate(async () => {
    const { createBrowserOidcSession } = await import("@askrjs/auth/browser");
    const session = createBrowserOidcSession({
      issuer: "https://login.example.test",
      clientId: "browser-client",
      redirectUri: "http://localhost/callback",
      fetch: async () =>
        Response.json({
          issuer: "https://login.example.test",
          authorization_endpoint: "https://login.example.test/authorize",
          token_endpoint: "https://login.example.test/token",
          jwks_uri: "https://login.example.test/jwks",
        }),
    });
    const url = await session.login();
    const authorization = new URL(url);
    const state = authorization.searchParams.get("state");
    const stored = Object.values(sessionStorage);
    session.logout();
    return { state, stored, remaining: sessionStorage.length };
  });
  expect(result.state).toBeTruthy();
  expect(result.stored).toHaveLength(1);
  expect(result.stored.join()).not.toMatch(/access_token|id_token|refresh_token|clientSecret/);
  expect(result.remaining).toBe(0);
});

test("packed server and browser entrypoints import without DOM globals in Node", async () => {
  expect(typeof globalThis.window).toBe("undefined");
  for (const entry of ["index", "oidc", "browser"]) {
    const module = await import(
      pathToFileURL(join(consumer, `node_modules/@askrjs/auth/dist/${entry}.js`)).href
    );
    expect(module).toBeDefined();
    if (entry === "browser") {
      const session = module.createBrowserOidcSession({
        issuer,
        clientId: "browser-client",
        redirectUri: "http://localhost/callback",
      });
      expect(await session.getToken()).toMatchObject({ status: "interaction-required" });
    }
  }
});

function token(nonce = "browser-nonce", signingKey = keys.privateKey, subject = "browser-user") {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const data = `${encode({ alg: "RS256", kid: jwk.kid })}.${encode({
    iss: issuer,
    aud: "browser-client",
    sub: subject,
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

async function createSession(page, overrides = {}) {
  await page.evaluate(async (overrides) => {
    const { createBrowserOidcSession } = await import("@askrjs/auth/browser");
    window.sessionClock = Date.now();
    window.sessionOptions = {
      issuer: "https://login.example.test",
      clientId: "browser-client",
      redirectUri: "http://localhost/callback",
      silent: { timeoutMs: 5000 },
      clockLeewaySeconds: 10,
      now: () => window.sessionClock,
      ...overrides,
    };
    window.session = createBrowserOidcSession(window.sessionOptions);
  }, overrides);
}

async function loginCallback(page, subject = "browser-user") {
  return page.evaluate(async (subject) => {
    const url = new URL(await window.session.login());
    return `http://localhost/callback?state=${url.searchParams.get("state")}&code=${url.searchParams.get("nonce")}|${subject}`;
  }, subject);
}

test("session validates a signed redirect and restores after recreation without stored tokens", async ({
  page,
}) => {
  await createSession(page);
  const callback = await loginCallback(page);
  const result = await page.evaluate(async (callback) => {
    const { createBrowserOidcSession } = await import("@askrjs/auth/browser");
    // A new object simulates a document reload; only transaction storage survives.
    window.session = createBrowserOidcSession(window.sessionOptions);
    const restored = await window.session.restore(callback);
    const cached = await window.session.getToken();
    return {
      restored,
      cached,
      sessionStorage: Object.values(sessionStorage),
      localStorage: Object.values(localStorage),
    };
  }, callback);
  expect(result.restored).toMatchObject({
    status: "authenticated",
    principal: { id: "browser-user" },
    accessToken: "access-1",
  });
  expect(result.cached).toEqual(result.restored);
  expect(tokenExchanges).toBe(1);
  expect(result.sessionStorage).toEqual([]);
  expect(result.localStorage).toEqual([]);
  expect(JSON.stringify(result)).not.toMatch(/discard-this-refresh-token|id_token/);
  const replay = await page.evaluate(async (callback) => {
    try {
      await window.session.restore(callback);
    } catch (error) {
      return error.code;
    }
  }, callback);
  expect(replay).toBe("invalid-transaction");
  expect(tokenExchanges).toBe(1);
  const renewed = await page.evaluate(async () => {
    const { createBrowserOidcSession } = await import("@askrjs/auth/browser");
    window.session = createBrowserOidcSession(window.sessionOptions);
    return window.session.restore("http://localhost/");
  });
  expect(renewed.status).toBe("authenticated");
  expect(tokenExchanges).toBe(2);
});

test("session rejects wrong state, expired transactions and duplicate callback parameters", async ({
  page,
}) => {
  await createSession(page, { transactionTtlMs: 100 });
  for (const scenario of ["state", "expired", "duplicate", "path", "both"]) {
    const callback = await loginCallback(page);
    const code = await page.evaluate(
      async ({ callback, scenario }) => {
        const url = new URL(callback);
        if (scenario === "state") url.searchParams.set("state", "wrong");
        if (scenario === "expired") window.sessionClock += 100;
        if (scenario === "duplicate") url.searchParams.append("state", "extra");
        if (scenario === "path") url.pathname = "/wrong";
        if (scenario === "both") url.searchParams.set("error", "login_required");
        try {
          await window.session.restore(url);
        } catch (error) {
          return error.code;
        }
      },
      { callback, scenario },
    );
    expect(code).toBe(
      scenario === "expired"
        ? "expired-transaction"
        : scenario === "state"
          ? "invalid-transaction"
          : "invalid-callback",
    );
  }
  expect(tokenExchanges).toBe(0);
});

test("session deduplicates expiry renewal and applies clock leeway", async ({ page }) => {
  await createSession(page);
  const callback = await loginCallback(page);
  await page.evaluate((callback) => window.session.restore(callback), callback);
  const results = await page.evaluate(async () => {
    window.sessionClock += 49_999;
    const fresh = await window.session.getToken();
    window.sessionClock += 1;
    const renewed = await Promise.all([
      window.session.getToken(),
      window.session.getToken(),
      window.session.getToken(),
    ]);
    return { fresh, renewed, frames: document.querySelectorAll("iframe").length };
  });
  expect(results.fresh.accessToken).toBe("access-1");
  expect(results.renewed.map((item) => item.accessToken)).toEqual([
    "access-2",
    "access-2",
    "access-2",
  ]);
  expect(results.frames).toBe(0);
  expect(tokenExchanges).toBe(2);
});

test("session reports interaction-required and leaves provider logout under application ownership", async ({
  page,
}) => {
  await createSession(page);
  silentMode = "interaction";
  expect(await page.evaluate(() => window.session.restore())).toMatchObject({
    status: "interaction-required",
    error: "login_required",
  });
  expect(await page.locator("iframe").count()).toBe(0);
  await page.evaluate(() => window.session.logout());
  expect(tokenExchanges).toBe(0);
  expect(await page.evaluate(() => sessionStorage.length)).toBe(0);
});

test("web-message transport ignores wrong origin, source, state and malformed responses", async ({
  page,
}) => {
  await createSession(page);
  silentMode = "hold";
  await page.evaluate(() => {
    window.renewal = window.session.getToken();
  });
  await expect(page.locator("iframe")).toHaveCount(1);
  await page.frameLocator("iframe").locator("body").waitFor({ state: "attached" });
  const providerFrame = page
    .frames()
    .find((frame) => frame.url().startsWith(`${issuer}/authorize`));
  if (!providerFrame) throw new Error("Missing provider frame.");
  const valid = await page.evaluate(() => {
    const url = new URL(document.querySelector("iframe").src);
    window.receivedMessages = 0;
    window.addEventListener("message", () => {
      window.receivedMessages++;
    });
    return { state: url.searchParams.get("state"), code: url.searchParams.get("nonce") };
  });
  // Real cross-origin messages avoid Firefox rejecting synthetic MessageEvent sources.
  await page.route("https://attacker.test/message", (route) =>
    route.fulfill({ contentType: "text/html", body: "<p>attacker</p>" }),
  );
  await page.evaluate(() => {
    const frame = document.createElement("iframe");
    frame.id = "attacker";
    frame.src = "https://attacker.test/message";
    document.body.append(frame);
  });
  await page
    .frameLocator("#attacker")
    .locator("body")
    .evaluate((_body, data) => parent.postMessage(data, "*"), valid);
  await page.evaluate((data) => {
    window.dispatchEvent(
      new MessageEvent("message", { origin: "https://login.example.test", source: window, data }),
    );
  }, valid);
  await providerFrame.evaluate((data) => {
    parent.postMessage({ ...data, state: "wrong" }, "*");
    parent.postMessage({ ...data, error: "login_required" }, "*");
  }, valid);
  await page.waitForFunction(() => window.receivedMessages === 4);
  await page.locator("#attacker").evaluate((frame) => frame.remove());
  expect(tokenExchanges).toBe(0);
  await expect(page.locator("iframe")).toHaveCount(1);
  await providerFrame.evaluate((data) => parent.postMessage(data, "*"), valid);
  const result = await page.evaluate(() => window.renewal);
  expect(result.status).toBe("authenticated");
  expect(tokenExchanges).toBe(1);
  await expect(page.locator("iframe")).toHaveCount(0);
});

test("silent timeout and disposal remove message listeners and frames", async ({ page }) => {
  await createSession(page, { silent: { timeoutMs: 50 } });
  silentMode = "hold";
  await page.evaluate(() => {
    const add = window.addEventListener.bind(window);
    const remove = window.removeEventListener.bind(window);
    window.messageListeners = new Set();
    window.addEventListener = (type, listener, options) => {
      if (type === "message") window.messageListeners.add(listener);
      add(type, listener, options);
    };
    window.removeEventListener = (type, listener, options) => {
      if (type === "message") window.messageListeners.delete(listener);
      remove(type, listener, options);
    };
  });
  expect(
    await page.evaluate(async () => {
      try {
        await window.session.getToken();
      } catch (error) {
        return error.code;
      }
    }),
  ).toBe("silent-timeout");
  expect(await page.evaluate(() => window.messageListeners.size)).toBe(0);
  await page.evaluate(() => window.session.dispose());
  await createSession(page, { silent: { timeoutMs: 5000 } });
  await page.evaluate(() => {
    window.renewal = window.session.getToken().catch((error) => error.code);
  });
  await expect(page.locator("iframe")).toHaveCount(1);
  expect(
    await page.evaluate(async () => {
      window.session.dispose();
      return {
        result: await window.renewal,
        listeners: window.messageListeners.size,
        frames: document.querySelectorAll("iframe").length,
      };
    }),
  ).toEqual({ result: "cancelled", listeners: 0, frames: 0 });
  expect(
    await page.evaluate(() => {
      try {
        window.session.getToken();
      } catch (error) {
        return error.code;
      }
    }),
  ).toBe("disposed");
});

test("late exchanges cannot restore a logged-out or replaced identity even when fetch ignores abort", async ({
  page,
}) => {
  await createSession(page);
  await page.evaluate(async () => {
    const { createBrowserOidcSession } = await import("@askrjs/auth/browser");
    window.session = createBrowserOidcSession({
      ...window.sessionOptions,
      fetch: async (input, init) => {
        const response = await fetch(input, { ...init, signal: undefined });
        if (String(input).endsWith("/token") && window.holdToken) {
          return new Promise((resolve) => {
            window.releaseToken = () => resolve(response);
          });
        }
        return response;
      },
    });
    window.holdToken = true;
    window.renewal = window.session.getToken().catch((error) => error.code);
  });
  await expect.poll(() => page.evaluate(() => typeof window.releaseToken)).toBe("function");
  expect(
    await page.evaluate(async () => {
      window.session.logout();
      window.releaseToken();
      return window.renewal;
    }),
  ).toBe("cancelled");
  await page.evaluate(() => {
    window.releaseToken = undefined;
    window.renewal = window.session.getToken().catch((error) => error.code);
  });
  await expect.poll(() => page.evaluate(() => typeof window.releaseToken)).toBe("function");
  await page.evaluate(() => {
    window.holdToken = false;
  });
  const callback = await loginCallback(page, "replacement-user");
  const result = await page.evaluate(async (callback) => {
    const replacement = await window.session.restore(callback);
    window.releaseToken();
    const late = await window.renewal;
    const token = await window.session.getToken();
    return { replacement, late, token };
  }, callback);
  expect(result.late).toBe("cancelled");
  expect(result.replacement.principal.id).toBe("replacement-user");
  expect(result.token.principal.id).toBe("replacement-user");
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

test("interactive login pauses silent work and correlated provider errors consume transactions", async ({
  page,
}) => {
  await createSession(page);
  const callback = await loginCallback(page);
  expect(await page.evaluate(() => window.session.getToken())).toMatchObject({
    status: "interaction-required",
  });
  expect(tokenExchanges).toBe(0);
  const result = await page.evaluate(async (callback) => {
    const url = new URL(callback);
    url.searchParams.delete("code");
    url.searchParams.set("error", "consent_required");
    const error = await window.session.restore(url);
    try {
      await window.session.restore(url);
    } catch (replay) {
      return { error, replay: replay.code };
    }
  }, callback);
  expect(result).toMatchObject({
    error: { status: "interaction-required", error: "consent_required" },
    replay: "invalid-transaction",
  });
});

test("exchange validation cannot extend an access token past its lifetime", async ({ page }) => {
  await createSession(page);
  await page.evaluate(async () => {
    const { createBrowserOidcSession } = await import("@askrjs/auth/browser");
    window.session = createBrowserOidcSession({
      ...window.sessionOptions,
      fetch: async (input, init) => {
        const response = await fetch(input, init);
        if (String(input).endsWith("/jwks")) window.sessionClock += 61_000;
        return response;
      },
    });
  });
  const callback = await loginCallback(page);
  expect(
    await page.evaluate(async (callback) => {
      try {
        await window.session.restore(callback);
      } catch (error) {
        return error.code;
      }
    }, callback),
  ).toBe("invalid-token-response");
  expect(await page.evaluate(() => sessionStorage.length)).toBe(0);
});

test("standalone packed SPA exercises signed login, reload restoration, expiry renewal and logout", async ({
  page,
}) => {
  const installed = JSON.parse(
    await readFile(join(consumer, "node_modules/@askrjs/auth/package.json"), "utf8"),
  );
  const example = JSON.parse(
    await readFile(new URL("../../examples/browser-session/package.json", import.meta.url), "utf8"),
  );
  expect(example.dependencies["@askrjs/auth"]).toBe(
    `file:../../askrjs-auth-${installed.version}.tgz`,
  );
  await page.unrouteAll({ behavior: "wait" });
  await writeFile(
    join(consumer, "server.mjs"),
    await readFile(new URL("../../examples/browser-session/server.mjs", import.meta.url)),
  );
  await writeFile(
    join(consumer, "index.html"),
    await readFile(new URL("../../examples/browser-session/index.html", import.meta.url)),
  );
  for (const file of ["localhost-key.pem", "localhost-cert.pem"]) {
    await writeFile(
      join(consumer, file),
      await readFile(new URL(`../../examples/browser-session/${file}`, import.meta.url)),
    );
  }
  const server = spawn(process.execPath, [join(consumer, "server.mjs")], {
    cwd: consumer,
    env: { ...process.env, ASKR_AUTH_DEMO_PORT: "0" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  try {
    const url = await new Promise((resolve, reject) => {
      let output = "";
      server.stdout.on("data", (chunk) => {
        output += chunk;
        const match = output.match(/Demo ready at (https:\/\/127\.0\.0\.1:\d+)/);
        if (match) resolve(match[1]);
      });
      server.on("error", reject);
      server.once("exit", (code) => reject(new Error(`Demo exited with ${code}. ${output}`)));
      server.stderr.on("data", (chunk) => {
        output += chunk;
      });
    });
    await page.goto(url);
    await expect(page.locator("#status")).toContainText("Interaction required");
    await page.getByRole("button", { name: "Login", exact: true }).click();
    await expect(page.locator("#status")).toContainText("Signed in as Demo user");
    await expect(page).toHaveURL(`${url}/`);
    expect(await page.evaluate(() => typeof globalThis.Buffer)).toBe("undefined");
    await page.getByRole("button", { name: "Reload", exact: true }).click();
    await expect(page.locator("#status")).toContainText("Signed in as Demo user");
    const before = await page.locator("#status").textContent();
    await page.clock.install();
    await page.clock.fastForward(26_000);
    await page.getByRole("button", { name: "Get token", exact: true }).click();
    await expect(page.locator("#status")).not.toHaveText(before);
    await expect(page.locator("#status")).toContainText("Signed in as Demo user");
    expect(await page.evaluate(() => [sessionStorage.length, localStorage.length])).toEqual([0, 0]);
    await page.getByRole("button", { name: "Logout", exact: true }).click();
    await expect(page.locator("#status")).toHaveText("Signed out.");
    await page.getByRole("button", { name: "Reload", exact: true }).click();
    await expect(page.locator("#status")).toContainText("Interaction required: login_required");
    const attack = new URL(`${url}/provider/authorize`);
    const attackState = "</script><script>globalThis.demoInjected=true</script>";
    const parameters = {
      redirect_uri: `${url}/callback`,
      client_id: "demo-spa",
      response_type: "code",
      code_challenge_method: "S256",
      code_challenge: "A".repeat(43),
      nonce: "demo-nonce",
      state: attackState,
      prompt: "none",
      response_mode: "web_message",
    };
    for (const [name, value] of Object.entries(parameters)) attack.searchParams.set(name, value);
    await page.goto(attack.href);
    expect(await page.evaluate(() => globalThis.demoInjected)).toBeUndefined();
    expect(await page.evaluate(() => new URL(location.href).searchParams.get("state"))).toBe(
      attackState,
    );
    expect(await page.locator("script:not([src])").count()).toBe(0);
  } finally {
    const stopped = new Promise((resolve) => server.once("exit", resolve));
    server.kill();
    if (server.exitCode === null) await stopped;
  }
});
