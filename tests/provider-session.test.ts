import { createServer } from "node:http";
import { generateKeyPairSync } from "node:crypto";
import { afterEach, expect, it } from "vite-plus/test";
import { createJwtSigner } from "../src/jwt";
import { codeChallenge } from "../src/oidc-crypto";
import { createOidcProvider, createProviderSession } from "../src/server";
import type { OidcProviderOptions, ProviderSessionOptions } from "../src/server";
import { memoryAuthority } from "../src/provider-session-storage";

const origin = "https://app.test";
const issuer = "https://provider.test";
const key = Buffer.alloc(32, 19).toString("base64url");
const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
const signer = createJwtSigner({
  privateKey: pair.privateKey.export({ format: "jwk" }),
  kid: "one",
});
const cleanup: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const close of cleanup.splice(0).reverse()) await close();
});

function cookies(response: Response, previous = "") {
  const jar = new Map(
    previous
      .split("; ")
      .filter(Boolean)
      .map((part) => part.split("=", 2) as [string, string]),
  );
  for (const value of response.headers.getSetCookie()) {
    const [name, content] = value.split(";", 1)[0]!.split("=", 2);
    if (content) jar.set(name!, content);
    else jar.delete(name!);
  }
  return [...jar].map(([name, value]) => `${name}=${value}`).join("; ");
}

async function fixture(
  responseMode: "query" | "form_post" = "query",
  configure: {
    provider?: Partial<OidcProviderOptions>;
    session?: Partial<ProviderSessionOptions["session"]>;
    onSignIn?: ProviderSessionOptions["onSignIn"];
    ignoreCancellation?: boolean;
  } = {},
) {
  let now = 1_800_000_000_000;
  let exchanges = 0;
  let refreshes = 0;
  let refreshError: string | undefined;
  const refreshTokens = new Set<string>();
  const refreshSignals: AbortSignal[] = [];
  let delay: Promise<void> | undefined;
  let claims: Record<string, unknown> = {};
  const codes = new Map<string, { nonce: string; challenge: string }>();
  const server = createServer(async (request, response) => {
    try {
      const url = new URL(request.url!, issuer);
      const json = (body: unknown) => {
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify(body));
      };
      if (url.pathname === "/.well-known/openid-configuration")
        return json({
          issuer,
          authorization_endpoint: `${issuer}/authorize`,
          token_endpoint: `${issuer}/token`,
          jwks_uri: `${issuer}/jwks`,
        });
      if (url.pathname === "/jwks")
        return json({
          keys: [{ ...pair.publicKey.export({ format: "jwk" }), kid: "one", alg: "RS256" }],
        });
      if (url.pathname === "/authorize") {
        const code = crypto.randomUUID();
        codes.set(code, {
          nonce: url.searchParams.get("nonce")!,
          challenge: url.searchParams.get("code_challenge")!,
        });
        const callback = new URL(url.searchParams.get("redirect_uri")!);
        callback.searchParams.set("code", code);
        callback.searchParams.set("state", url.searchParams.get("state")!);
        response.writeHead(302, { location: callback.href });
        response.end();
        return;
      }
      if (url.pathname === "/token") {
        let body = "";
        for await (const chunk of request) body += chunk;
        const form = new URLSearchParams(body);
        expect(request.headers.authorization).toBe(`Basic ${btoa("client:SECRET_CANARY")}`);
        if (form.get("grant_type") === "refresh_token") {
          refreshes++;
          const sequence = refreshes;
          expect(refreshTokens.delete(form.get("refresh_token")!)).toBe(true);
          await delay;
          if (refreshError) {
            response.statusCode = 400;
            return json({ error: refreshError, error_description: "PRIVATE_ERROR_CANARY" });
          }
          refreshTokens.add(`ROTATED_${sequence}`);
          return json({
            access_token: `RENEWED_${sequence}`,
            refresh_token: `ROTATED_${sequence}`,
            token_type: "Bearer",
            expires_in: 60,
            scope: form.get("scope"),
          });
        }
        exchanges++;
        const stored = codes.get(form.get("code")!);
        codes.delete(form.get("code")!);
        expect(form.get("grant_type")).toBe("authorization_code");
        expect(form.get("redirect_uri")).toBe(`${origin}/auth/callback/oidc`);
        expect(stored).toBeDefined();
        expect(await codeChallenge(form.get("code_verifier")!)).toBe(stored!.challenge);
        await delay;
        const refreshToken = `REFRESH_CANARY_${exchanges}`;
        refreshTokens.add(refreshToken);
        return json({
          access_token: "ACCESS_CANARY",
          refresh_token: refreshToken,
          token_type: "Bearer",
          expires_in: 60,
          id_token: await signer.sign({
            claims: {
              iss: issuer,
              sub: "account-one",
              aud: "client",
              nonce: stored!.nonce,
              iat: now / 1000,
              exp: now / 1000 + 600,
              email: "PRIVATE_EMAIL_CANARY",
              ...claims,
            },
          }),
        });
      }
      response.statusCode = 404;
      response.end();
    } catch {
      response.statusCode = 400;
      response.end("provider failure");
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  cleanup.push(
    () =>
      new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
  );
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Expected owned HTTP listener");
  const providerFetch: typeof fetch = (input, init) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    expect(url.origin).toBe(issuer);
    if (
      url.pathname === "/token" &&
      init?.body instanceof URLSearchParams &&
      init.body.get("grant_type") === "refresh_token" &&
      init.signal
    )
      refreshSignals.push(init.signal);
    return fetch(
      `http://127.0.0.1:${address.port}${url.pathname}${url.search}`,
      configure.ignoreCancellation ? { ...init, signal: undefined } : init,
    );
  };
  const provider = createOidcProvider({
    id: "oidc",
    issuer,
    clientId: "client",
    clientAuthentication: { method: "client_secret_basic", secret: "SECRET_CANARY" },
    responseMode,
    ...configure.provider,
  });
  const options = {
    origin,
    providers: [provider],
    session: { secrets: [key], ...configure.session },
    fetch: providerFetch,
    clock: () => now,
    onSignIn: configure.onSignIn,
  };
  const engine = createProviderSession(options);
  cleanup.push(() => engine.close());
  async function start(
    cookie = "",
    login: { resource?: string; scopes?: readonly string[]; returnTo?: string } = {},
  ) {
    const request = new Request(`${origin}/auth/login/oidc`, { headers: { cookie } });
    const response = await engine.finalize(
      request,
      await engine.login(request, { provider: "oidc", returnTo: "/private?tab=one", ...login }),
    );
    const authorization = response.headers.get("location")!;
    const result = await providerFetch(authorization, { redirect: "manual" });
    return {
      cookie: cookies(response, cookie),
      location: result.headers.get("location")!,
      response,
      authorization,
    };
  }
  function callback(location: string, cookie: string, mutate?: (fields: URLSearchParams) => void) {
    const url = new URL(location);
    mutate?.(url.searchParams);
    return responseMode === "form_post"
      ? new Request(`${origin}/auth/callback/oidc`, {
          method: "POST",
          headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
          body: url.searchParams,
        })
      : new Request(url, { headers: { cookie } });
  }
  async function signIn(login: { resource?: string; scopes?: readonly string[] } = {}) {
    const started = await start("", login);
    const request = callback(started.location, started.cookie);
    const response = await engine.finalize(
      request,
      await engine.callback(request, { provider: "oidc" }),
    );
    return { cookie: cookies(response, started.cookie), response, request };
  }
  return {
    engine,
    options,
    provider,
    start,
    callback,
    signIn,
    exchanges: () => exchanges,
    refreshes: () => refreshes,
    refreshSignals: () => [...refreshSignals],
    refreshError: (value: string) => {
      refreshError = value;
    },
    advance: (ms: number) => {
      now += ms;
    },
    delay: (promise: Promise<void>) => {
      delay = promise;
    },
    claims: (value: Record<string, unknown>) => {
      claims = value;
    },
  };
}

it("validates real signed HTTP OIDC exchange and exposes only minimal identity", async () => {
  const f = await fixture();
  const started = await f.start();
  expect(started.response.status).toBe(303);
  const authorization = new URL(started.authorization);
  expect(authorization.searchParams.get("code_challenge_method")).toBe("S256");
  const request = f.callback(started.location, started.cookie);
  const response = await f.engine.finalize(
    request,
    await f.engine.callback(request, { provider: "oidc" }),
  );
  expect(response.status).toBe(303);
  expect(response.headers.get("location")).toBe(`${origin}/private?tab=one`);
  const auth = await f.engine.resolve(
    new Request(`${origin}/private`, { headers: { cookie: cookies(response, started.cookie) } }),
  );
  expect(auth.authenticated).toBe(true);
  expect(auth.principal).toEqual({
    id: JSON.stringify([issuer, "account-one"]),
    subject: "account-one",
  });
  expect(Object.keys(auth.session!).sort()).toEqual(["expiresAt", "id", "subject"]);
  expect(JSON.stringify(auth) + JSON.stringify([...response.headers])).not.toMatch(
    /ACCESS_CANARY|REFRESH_CANARY|SECRET_CANARY|PRIVATE_EMAIL_CANARY/,
  );
  expect(response.headers.getSetCookie().find((s) => s.startsWith("__Host-askr-session="))).toMatch(
    /Path=\/;.*HttpOnly;.*Secure;.*SameSite=Lax/,
  );
  expect(f.exchanges()).toBe(1);
});

it("atomically consumes a copied transaction before either concurrent exchange", async () => {
  const f = await fixture();
  const started = await f.start();
  const results = await Promise.allSettled(
    [0, 1].map(() =>
      f.engine.callback(f.callback(started.location, started.cookie), { provider: "oidc" }),
    ),
  );
  expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
  expect(results.find((r) => r.status === "rejected")).toMatchObject({
    reason: { code: "invalid-transaction" },
  });
  expect(f.exchanges()).toBe(1);
});

it.each(["wrong-state", "denial", "duplicate-code"])(
  "consumes %s callbacks and cannot replay the original cookie",
  async (failure) => {
    const f = await fixture();
    const started = await f.start();
    const request = f.callback(started.location, started.cookie, (p) => {
      if (failure === "wrong-state") p.set("state", "bad");
      if (failure === "denial") p.set("error", "PROVIDER_ERROR_CANARY");
      if (failure === "duplicate-code") p.append("code", "second");
    });
    await expect(f.engine.callback(request, { provider: "oidc" })).rejects.toMatchObject({
      code: "invalid-callback",
    });
    const finalized = await f.engine.finalize(
      request,
      new Response("safe failure", { status: 400 }),
    );
    expect(
      finalized.headers
        .getSetCookie()
        .some((value) => value.startsWith("__Host-askr-txn-oidc=;") && value.includes("Max-Age=0")),
    ).toBe(true);
    await expect(
      f.engine.callback(f.callback(started.location, started.cookie), { provider: "oidc" }),
    ).rejects.toMatchObject({ code: "invalid-transaction" });
    expect(f.exchanges()).toBe(0);
  },
);

it("correlates form_post without a Lax session cookie and clears the None transaction cookie", async () => {
  const f = await fixture("form_post");
  const started = await f.start();
  const tx = started.cookie
    .split("; ")
    .filter((p) => p.startsWith("__Host-askr-txn-"))
    .join("; ");
  expect(
    started.response.headers.getSetCookie().find((p) => p.startsWith("__Host-askr-txn-")),
  ).toContain("SameSite=None");
  const request = f.callback(started.location, tx);
  const response = await f.engine.finalize(
    request,
    await f.engine.callback(request, { provider: "oidc" }),
  );
  expect(
    (await f.engine.resolve(new Request(origin, { headers: { cookie: cookies(response) } })))
      .authenticated,
  ).toBe(true);
});

it("rejects a slow exchange after its original transaction expiry", async () => {
  const f = await fixture();
  const started = await f.start();
  let release!: () => void;
  f.delay(
    new Promise<void>((resolve) => {
      release = resolve;
    }),
  );
  const request = f.callback(started.location, started.cookie);
  const pending = f.engine.callback(request, { provider: "oidc" });
  let settled = false;
  void pending.then(
    () => {
      settled = true;
    },
    () => {
      settled = true;
    },
  );
  try {
    await expect.poll(() => f.exchanges(), { timeout: 1000 }).toBe(1);
    f.advance(300_001);
  } finally {
    release();
  }
  await expect.poll(() => settled, { timeout: 1000 }).toBe(true);
  await expect(pending).rejects.toMatchObject({ code: "invalid-transaction" });
  expect(
    (await f.engine.finalize(request, new Response("failure"))).headers
      .getSetCookie()
      .some((p) => p.startsWith("__Host-askr-session=")),
  ).toBe(false);
});

it("rejects an invalid signed issuer without exposing token/provider canaries", async () => {
  const f = await fixture();
  f.claims({ iss: "https://untrusted.test" });
  const started = await f.start();
  let error: unknown;
  try {
    await f.engine.callback(f.callback(started.location, started.cookie), { provider: "oidc" });
  } catch (caught) {
    error = caught;
  }
  expect(error).toMatchObject({ code: "invalid-callback" });
  expect(String(error) + JSON.stringify(error)).not.toMatch(/CANARY|untrusted/);
});

it("does not enroll copied session cookies into a restarted default authority", async () => {
  const f = await fixture();
  const started = await f.start();
  const request = f.callback(started.location, started.cookie);
  const response = await f.engine.finalize(
    request,
    await f.engine.callback(request, { provider: "oidc" }),
  );
  const restored = createProviderSession(f.options);
  cleanup.push(() => restored.close());
  expect(
    (await restored.resolve(new Request(origin, { headers: { cookie: cookies(response) } })))
      .authenticated,
  ).toBe(false);
});

it("preserves a validated local app fragment without sending it as the provider callback", async () => {
  const f = await fixture();
  const started = await f.start("", { returnTo: "/private?a=1#x" });
  expect(new URL(started.authorization).searchParams.get("redirect_uri")).toBe(
    `${origin}/auth/callback/oidc`,
  );
  const request = f.callback(started.location, started.cookie);
  expect((await f.engine.callback(request, { provider: "oidc" })).headers.get("location")).toBe(
    `${origin}/private?a=1#x`,
  );
});

it("supersedes an older copied transaction while retaining the current identity during a new login", async () => {
  const f = await fixture();
  const signed = await f.signIn();
  const older = await f.start(signed.cookie);
  const newer = await f.start(older.cookie);
  expect(
    (await f.engine.resolve(new Request(origin, { headers: { cookie: newer.cookie } })))
      .authenticated,
  ).toBe(true);
  await expect(
    f.engine.callback(f.callback(older.location, older.cookie), { provider: "oidc" }),
  ).rejects.toMatchObject({ code: "invalid-transaction" });
  expect(f.exchanges()).toBe(1);
  f.claims({ sub: "account-two" });
  const request = f.callback(newer.location, newer.cookie);
  const response = await f.engine.finalize(
    request,
    await f.engine.callback(request, { provider: "oidc" }),
  );
  expect(
    (await f.engine.resolve(new Request(origin, { headers: { cookie: cookies(response) } })))
      .principal?.subject,
  ).toBe("account-two");
  expect(
    (await f.engine.resolve(new Request(origin, { headers: { cookie: signed.cookie } })))
      .authenticated,
  ).toBe(false);
});

it("rechecks stale issuance after logout and preserves unrelated cookies on repeated finalization", async () => {
  const f = await fixture();
  const signed = await f.signIn();
  const logoutRequest = new Request(`${origin}/auth/logout`, {
    method: "POST",
    headers: { cookie: signed.cookie },
  });
  await f.engine.finalize(logoutRequest, await f.engine.logout(logoutRequest));
  const supplied = new Response("application", { headers: { "set-cookie": "app=value; Path=/" } });
  const first = await f.engine.finalize(signed.request, supplied);
  const second = await f.engine.finalize(signed.request, first);
  expect(second.headers.getSetCookie().filter((value) => value.startsWith("app="))).toEqual([
    "app=value; Path=/",
  ]);
  expect(
    second.headers.getSetCookie().some((value) => value.startsWith("__Host-askr-session=")),
  ).toBe(false);
  expect(second.headers.get("cache-control")).toBe("no-store");
});

it("cannot issue a session after cancellation during the awaited application sign-in callback", async () => {
  let entered = false;
  let release!: () => void;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  const f = await fixture("query", {
    onSignIn: async () => {
      entered = true;
      await held;
    },
  });
  const started = await f.start();
  const controller = new AbortController();
  const callback = f.callback(started.location, started.cookie);
  const request = new Request(callback, { signal: controller.signal });
  const pending = f.engine.callback(request, { provider: "oidc" });
  let settled = false;
  void pending.then(
    () => {
      settled = true;
    },
    () => {
      settled = true;
    },
  );
  try {
    await expect.poll(() => entered, { timeout: 1000 }).toBe(true);
    controller.abort();
    await expect.poll(() => settled, { timeout: 1000 }).toBe(true);
    await expect(pending).rejects.toMatchObject({
      name: "AbortError",
      message: "Authentication operation was cancelled.",
    });
  } finally {
    controller.abort();
    release();
  }
  await expect(
    f.engine.callback(f.callback(started.location, started.cookie), { provider: "oidc" }),
  ).rejects.toMatchObject({ code: "invalid-transaction" });
});

const apiPolicy = {
  renewal: "refresh" as const,
  incrementalConsent: true,
  resources: [{ resource: "https://api.test", scopes: ["read"] }],
};
it("uses the sole resource, isolates identity scopes and deduplicates renewal independently of starter cancellation", async () => {
  const f = await fixture("query", { provider: { capabilities: apiPolicy } });
  const signed = await f.signIn({ resource: "https://api.test", scopes: ["read"] });
  const request = () => new Request(origin, { headers: { cookie: signed.cookie } });
  expect((await f.engine.resolve(request())).scopes).toEqual(["email", "openid", "profile"]);
  expect(await f.engine.token(request(), "oidc", { scopes: ["read"] })).toBe("ACCESS_CANARY");
  f.advance(30_000);
  let release!: () => void;
  f.delay(
    new Promise<void>((resolve) => {
      release = resolve;
    }),
  );
  let joined!: Promise<string>;
  try {
    const starter = new AbortController();
    const pending = f.engine.token(request(), "oidc", { scopes: ["read"], signal: starter.signal });
    void pending.catch(() => undefined);
    await expect.poll(() => f.refreshes(), { timeout: 1000 }).toBe(1);
    joined = f.engine.token(request(), "oidc", { scopes: ["read"] });
    void joined.catch(() => undefined);
    starter.abort();
    await expect(pending).rejects.toMatchObject({ name: "AbortError" });
  } finally {
    release();
  }
  expect(await joined).toBe("RENEWED_1");
  expect(f.refreshes()).toBe(1);
  // An older cookie revision reads the authoritative rotation instead of reusing the old refresh token.
  expect(await f.engine.token(request(), "oidc", { scopes: ["read"] })).toBe("RENEWED_1");
  expect(f.refreshes()).toBe(1);
});

it("keeps transport failures distinct and never retries a possibly consumed refresh grant", async () => {
  const f = await fixture("query", { provider: { capabilities: apiPolicy } });
  const signed = await f.signIn({ resource: "https://api.test", scopes: ["read"] });
  f.advance(30_000);
  f.refreshError("temporarily_unavailable");
  const request = new Request(origin, { headers: { cookie: signed.cookie } });
  await expect(f.engine.token(request, "oidc", { scopes: ["read"] })).rejects.toMatchObject({
    code: "provider-unavailable",
  });
  await expect(f.engine.token(request, "oidc", { scopes: ["read"] })).rejects.toMatchObject({
    code: "interaction-required",
    reason: "login",
    resource: "https://api.test",
  });
  expect(f.refreshes()).toBe(1);
});

it("canonicalizes only a sole configured resource before interaction errors", async () => {
  const single = await fixture("query", { provider: { capabilities: apiPolicy } });
  await expect(
    single.engine.token(new Request(origin), "oidc", { scopes: ["read"] }),
  ).rejects.toMatchObject({
    code: "interaction-required",
    resource: "https://api.test",
    scopes: ["read"],
  });
  const none = await fixture();
  await expect(
    none.engine.token(new Request(origin), "oidc", { scopes: ["openid"] }),
  ).rejects.toMatchObject({ code: "configuration" });
  const multiple = await fixture("query", {
    provider: {
      capabilities: {
        ...apiPolicy,
        resources: [...apiPolicy.resources, { resource: "https://other.test", scopes: ["read"] }],
      },
    },
  });
  await expect(
    multiple.engine.token(new Request(origin), "oidc", { scopes: ["read"] }),
  ).rejects.toMatchObject({ code: "configuration" });
});

it.each(["//foreign.test/path", "/\\foreign.test/path", "https://foreign.test/path", "/bad\npath"])(
  "rejects unsafe app targets before provider work: %s",
  async (returnTo) => {
    const f = await fixture();
    const request = new Request(`${origin}/auth/login/oidc`);
    await expect(f.engine.login(request, { provider: "oidc", returnTo })).rejects.toMatchObject({
      code: "configuration",
    });
    expect(f.exchanges()).toBe(0);
  },
);

it("contains failed form-body reads in the safe callback error surface", async () => {
  const f = await fixture("form_post");
  const started = await f.start();
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.error(new Error("FORM_PRIVATE_CANARY"));
    },
  });
  const init: RequestInit & { duplex: "half" } = {
    method: "POST",
    headers: { cookie: started.cookie, "content-type": "application/x-www-form-urlencoded" },
    body,
    duplex: "half",
  };
  const request = new Request(`${origin}/auth/callback/oidc`, init);
  let error: unknown;
  try {
    await f.engine.callback(request, { provider: "oidc" });
  } catch (caught) {
    error = caught;
  }
  expect(error).toMatchObject({ code: "invalid-callback" });
  expect(String(error) + JSON.stringify(error)).not.toContain("FORM_PRIVATE_CANARY");
  expect(f.exchanges()).toBe(0);
});

it.each(["32769", "-1", "1.5", "1e4", "NaN", "9007199254740992"])(
  "consumes invalid declared callback length %s before reading or exchanging",
  async (length) => {
    const f = await fixture("form_post");
    const started = await f.start();
    let reads = 0;
    const body = new ReadableStream<Uint8Array>(
      {
        pull() {
          reads++;
        },
      },
      { highWaterMark: 0 },
    );
    const init: RequestInit & { duplex: "half" } = {
      method: "POST",
      headers: {
        cookie: started.cookie,
        "content-type": "application/x-www-form-urlencoded",
        "content-length": length,
      },
      body,
      duplex: "half",
    };
    const request = new Request(`${origin}/auth/callback/oidc`, init);
    await expect(f.engine.callback(request, { provider: "oidc" })).rejects.toMatchObject({
      code: "invalid-callback",
    });
    expect(reads).toBe(0);
    expect(f.exchanges()).toBe(0);
    const response = await f.engine.finalize(
      request,
      new Response("safe failure", { status: 400 }),
    );
    expect(
      response.headers
        .getSetCookie()
        .some((line) => line.startsWith("__Host-askr-txn-oidc=;") && line.includes("Max-Age=0")),
    ).toBe(true);
    await expect(
      f.engine.callback(f.callback(started.location, started.cookie), { provider: "oidc" }),
    ).rejects.toMatchObject({ code: "invalid-transaction" });
    expect(f.exchanges()).toBe(0);
  },
);

it("settles and cancels a stalled consumed form body when logout retires its owner", async () => {
  const f = await fixture("form_post");
  const started = await f.start();
  let reading = false;
  let canceled = false;
  let streamController!: ReadableStreamDefaultController<Uint8Array>;
  const body = new ReadableStream<Uint8Array>(
    {
      start(controller) {
        streamController = controller;
      },
      pull() {
        reading = true;
      },
      cancel() {
        canceled = true;
      },
    },
    { highWaterMark: 0 },
  );
  const init: RequestInit & { duplex: "half" } = {
    method: "POST",
    headers: { cookie: started.cookie, "content-type": "application/x-www-form-urlencoded" },
    body,
    duplex: "half",
  };
  const pending = f.engine.callback(new Request(`${origin}/auth/callback/oidc`, init), {
    provider: "oidc",
  });
  let settled = false;
  void pending.then(
    () => {
      settled = true;
    },
    () => {
      settled = true;
    },
  );
  try {
    await expect.poll(() => reading, { timeout: 1000 }).toBe(true);
    await f.engine.logout(
      new Request(`${origin}/auth/logout`, { method: "POST", headers: { cookie: started.cookie } }),
    );
    await expect.poll(() => settled, { timeout: 1000 }).toBe(true);
    await expect(pending).rejects.toMatchObject({ name: "AbortError" });
    expect(canceled).toBe(true);
    expect(f.exchanges()).toBe(0);
  } finally {
    if (!canceled) streamController.close();
  }
});

it("checks one final authority snapshot before attaching any staged login issuance", async () => {
  const actual = memoryAuthority(100, () => 0);
  let intercept: (() => Promise<void>) | undefined;
  let reads = 0;
  const store = {
    ...actual,
    async read(id: string, options: { signal: AbortSignal }) {
      reads++;
      if (intercept && reads === 2) {
        const run = intercept;
        intercept = undefined;
        await run();
      }
      return actual.read(id, options);
    },
  };
  const f = await fixture("query", { session: { store } });
  const started = await f.start();
  const loginRequest = new Request(`${origin}/auth/login/oidc`, {
    headers: { cookie: started.cookie },
  });
  const loginResponse = await f.engine.login(loginRequest, {
    provider: "oidc",
    returnTo: "/private",
  });
  reads = 0;
  let retired = false;
  intercept = async () => {
    await f.engine.logout(
      new Request(`${origin}/auth/logout`, { method: "POST", headers: { cookie: started.cookie } }),
    );
    retired = true;
  };
  const response = await f.engine.finalize(loginRequest, loginResponse);
  expect(retired).toBe(true);
  expect(
    response.headers
      .getSetCookie()
      .some(
        (line) =>
          line.startsWith("__Host-askr-session=") || line.startsWith("__Host-askr-txn-oidc="),
      ),
  ).toBe(false);
});

it("does not finalize an older callback failure by clearing a newer login transaction", async () => {
  const f = await fixture();
  const older = await f.start();
  const failed = f.callback(older.location, older.cookie, (fields) => fields.set("state", "wrong"));
  await expect(f.engine.callback(failed, { provider: "oidc" })).rejects.toMatchObject({
    code: "invalid-callback",
  });
  const newer = await f.start(older.cookie);
  const lateFailure = await f.engine.finalize(
    failed,
    new Response("safe failure", { status: 400 }),
  );
  expect(
    lateFailure.headers.getSetCookie().some((line) => line.startsWith("__Host-askr-txn-oidc=")),
  ).toBe(false);
  const request = f.callback(newer.location, newer.cookie);
  expect((await f.engine.callback(request, { provider: "oidc" })).status).toBe(303);
});

it("does not attach issuance when absolute authority expiry passes during final read", async () => {
  const actual = memoryAuthority(100, () => 0);
  let reads = 0;
  let advance: (() => void) | undefined;
  const store = {
    ...actual,
    async read(id: string, options: { signal: AbortSignal }) {
      reads++;
      if (advance && reads === 2) {
        const run = advance;
        advance = undefined;
        run();
      }
      return actual.read(id, options);
    },
  };
  const f = await fixture("query", { session: { store, maxAgeSeconds: 1 } });
  const signed = await f.signIn();
  const request = new Request(`${origin}/auth/login/oidc`, { headers: { cookie: signed.cookie } });
  const response = await f.engine.login(request, { provider: "oidc", returnTo: "/private" });
  reads = 0;
  advance = () => f.advance(1001);
  expect((await f.engine.finalize(request, response)).headers.getSetCookie()).toEqual([]);
});

it("requires API scopes to be explicitly allowed on that exact resource", async () => {
  const f = await fixture("query", { provider: { capabilities: apiPolicy } });
  await expect(
    f.engine.token(new Request(origin), "oidc", {
      resource: "https://api.test",
      scopes: ["openid"],
    }),
  ).rejects.toMatchObject({ code: "configuration" });
  await expect(
    f.engine.login(new Request(origin), {
      provider: "oidc",
      returnTo: "/",
      resource: "https://api.test",
      scopes: ["openid"],
    }),
  ).rejects.toMatchObject({ code: "configuration" });
});

it.each([null, undefined, new Array(1)])(
  "rejects malformed or sparse resource records at setup: %s",
  (resource) => {
    expect(() =>
      Reflect.apply(createOidcProvider, undefined, [
        {
          id: "oidc",
          issuer,
          clientId: "client",
          clientAuthentication: { method: "client_secret_basic", secret: "secret" },
          capabilities: { resources: Array.isArray(resource) ? resource : [resource] },
        },
      ]),
    ).toThrow(expect.objectContaining({ code: "configuration" }));
  },
);

it("rejects sparse session keys at setup rather than during storage work", async () => {
  const f = await fixture();
  expect(() =>
    createProviderSession({ ...f.options, session: { secrets: new Array<string>(1) } }),
  ).toThrow(expect.objectContaining({ code: "configuration" }));
});

it("aborts shared renewal on logout and fences ignored old completion", async () => {
  const f = await fixture("query", {
    provider: { capabilities: apiPolicy },
    ignoreCancellation: true,
  });
  const signed = await f.signIn({ resource: "https://api.test", scopes: ["read"] });
  f.advance(30_000);
  let release!: () => void;
  f.delay(
    new Promise<void>((resolve) => {
      release = resolve;
    }),
  );
  const request = () => new Request(origin, { headers: { cookie: signed.cookie } });
  try {
    const first = f.engine.token(request(), "oidc", { scopes: ["read"] });
    void first.catch(() => undefined);
    await expect.poll(() => f.refreshes(), { timeout: 1000 }).toBe(1);
    const second = f.engine.token(request(), "oidc", { scopes: ["read"] });
    const both = Promise.allSettled([first, second]);
    await f.engine.logout(request());
    const outcomes = await both;
    expect(
      outcomes.every(
        (outcome) =>
          outcome.status === "rejected" &&
          (outcome.reason.name === "AbortError" ||
            (outcome.reason.code === "interaction-required" && outcome.reason.reason === "login")),
      ),
    ).toBe(true);
  } finally {
    release();
  }
  await expect(f.engine.token(request(), "oidc", { scopes: ["read"] })).rejects.toMatchObject({
    code: "interaction-required",
    reason: "login",
  });
  expect(f.refreshes()).toBe(1);
});

it("uses one atomic store across independent engines for copied callback consumption", async () => {
  const store = memoryAuthority(100, () => 0);
  const f = await fixture("query", { session: { store } });
  const other = createProviderSession(f.options);
  cleanup.push(() => other.close());
  const started = await f.start();
  const outcomes = await Promise.allSettled(
    [f.engine, other].map((engine) =>
      engine.callback(f.callback(started.location, started.cookie), { provider: "oidc" }),
    ),
  );
  expect(outcomes.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
  expect(outcomes.filter((outcome) => outcome.status === "rejected")).toEqual([
    expect.objectContaining({ reason: expect.objectContaining({ code: "invalid-transaction" }) }),
  ]);
  expect(f.exchanges()).toBe(1);
});

it("retires naturally expired identity owners without canceling a still-live identity", async () => {
  const f = await fixture("query", {
    provider: { capabilities: apiPolicy },
    session: { maxAgeSeconds: 2, leewaySeconds: 60 },
    ignoreCancellation: true,
  });
  const older = await f.signIn({ resource: "https://api.test", scopes: ["read"] });
  f.advance(1000);
  const newer = await f.signIn({ resource: "https://api.test", scopes: ["read"] });
  let release!: () => void;
  f.delay(
    new Promise<void>((resolve) => {
      release = resolve;
    }),
  );
  let newPending!: Promise<string>;
  try {
    const oldPending = f.engine.token(
      new Request(origin, { headers: { cookie: older.cookie } }),
      "oidc",
      { scopes: ["read"] },
    );
    const oldOutcome = oldPending.then(
      () => null,
      (error: unknown) => error,
    );
    await expect.poll(() => f.refreshes(), { timeout: 1000 }).toBe(1);
    newPending = f.engine.token(
      new Request(origin, { headers: { cookie: newer.cookie } }),
      "oidc",
      { scopes: ["read"] },
    );
    void newPending.catch(() => undefined);
    await expect.poll(() => f.refreshes(), { timeout: 1000 }).toBe(2);
    const [oldSignal, newSignal] = f.refreshSignals();
    expect(oldSignal?.aborted).toBe(false);
    expect(newSignal?.aborted).toBe(false);
    f.advance(1001);
    await f.engine.resolve(new Request(origin));
    expect(oldSignal?.aborted).toBe(true);
    expect(newSignal?.aborted).toBe(false);
    expect(await oldOutcome).toMatchObject({ name: "AbortError" });
  } finally {
    release();
  }
  expect(await newPending).toBe("RENEWED_2");
  expect(
    (await f.engine.resolve(new Request(origin, { headers: { cookie: older.cookie } })))
      .authenticated,
  ).toBe(false);
  expect(
    (await f.engine.resolve(new Request(origin, { headers: { cookie: newer.cookie } })))
      .authenticated,
  ).toBe(true);
});

it.each(["request", "close"] as const)(
  "preserves %s cancellation when expiry already aborted the callback owner",
  async (cancellation) => {
    const f = await fixture("query", { ignoreCancellation: true });
    const started = await f.start();
    let release!: () => void;
    f.delay(
      new Promise<void>((resolve) => {
        release = resolve;
      }),
    );
    const controller = new AbortController();
    const request = new Request(f.callback(started.location, started.cookie), {
      signal: controller.signal,
    });
    const pending = f.engine.callback(request, { provider: "oidc" });
    const outcome = pending.then(
      () => null,
      (error: unknown) => error,
    );
    let settled = false;
    void outcome.then(() => {
      settled = true;
    });
    try {
      await expect.poll(() => f.exchanges(), { timeout: 1000 }).toBe(1);
      f.advance(300_001);
      // live() runs synchronously before resolve's first await; cancellation follows
      // before the expired callback's catch can run in a subsequent microtask.
      const sweep = f.engine.resolve(new Request(origin)).catch(() => undefined);
      if (cancellation === "request") controller.abort();
      else await f.engine.close();
      await sweep;
      await expect.poll(() => settled, { timeout: 1000 }).toBe(true);
      expect(await outcome).toMatchObject({
        name: "AbortError",
        message: "Authentication operation was cancelled.",
      });
    } finally {
      controller.abort();
      release();
    }
  },
);

it.each(["logout", "new-login"] as const)(
  "preserves %s retirement of a callback before its expiry",
  async (retirement) => {
    const f = await fixture("query", { ignoreCancellation: true });
    const started = await f.start();
    let release!: () => void;
    f.delay(
      new Promise<void>((resolve) => {
        release = resolve;
      }),
    );
    const request = f.callback(started.location, started.cookie);
    const pending = f.engine.callback(request, { provider: "oidc" });
    const outcome = pending.then(
      () => null,
      (error: unknown) => error,
    );
    let settled = false;
    void outcome.then(() => {
      settled = true;
    });
    try {
      await expect.poll(() => f.exchanges(), { timeout: 1000 }).toBe(1);
      if (retirement === "logout")
        await f.engine.logout(new Request(origin, { headers: { cookie: started.cookie } }), {});
      else await f.start(started.cookie);
      f.advance(300_001);
      await f.engine.resolve(new Request(origin));
      await expect.poll(() => settled, { timeout: 1000 }).toBe(true);
      expect(await outcome).toMatchObject({
        name: "AbortError",
        message: "Authentication operation was cancelled.",
      });
      expect(
        (await f.engine.finalize(request, new Response("failure"))).headers
          .getSetCookie()
          .some((line) => line.startsWith("__Host-askr-session=")),
      ).toBe(false);
    } finally {
      release();
    }
  },
);

it("requires login for a fresh API token request after absolute session expiry", async () => {
  const f = await fixture("query", {
    provider: { capabilities: apiPolicy },
    session: { maxAgeSeconds: 2 },
  });
  const signed = await f.signIn({ resource: "https://api.test", scopes: ["read"] });
  f.advance(2001);
  await expect(
    f.engine.token(new Request(origin, { headers: { cookie: signed.cookie } }), "oidc", {
      scopes: ["read"],
    }),
  ).rejects.toMatchObject({
    code: "interaction-required",
    reason: "login",
    provider: "oidc",
    resource: "https://api.test",
    scopes: ["read"],
  });
  expect(f.refreshes()).toBe(0);
});
