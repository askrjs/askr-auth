import assert from "node:assert/strict";
import { generateKeyPairSync, verify } from "node:crypto";
import { createServer } from "node:http";
import { createJwtSigner } from "../src/jwt";
import { createProviderSession } from "../src/server";
import type {
  ProviderDefinition,
  ProviderSessionOptions,
  ProviderSessionStore,
} from "../src/server";

export const appleOrigin = "https://appleid.apple.com";
export const appOrigin = "https://apple-app.example.test";
export const servicesId = "test.apple.service";
export const teamId = "TEAM123456";
export const keyId = "KEY1234567";
const signing = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
export const appleKey = signing.privateKey.export({ format: "jwk" });
const identity = generateKeyPairSync("rsa", { modulusLength: 2048 });
const signer = createJwtSigner({
  privateKey: identity.privateKey.export({ format: "jwk" }),
  kid: "apple-test",
});
const cleanup: (() => Promise<void>)[] = [];
export async function closeAppleFixtures() {
  const errors: unknown[] = [];
  for (const close of cleanup.splice(0).reverse()) {
    try {
      await close();
    } catch (error) {
      errors.push(error);
    }
  }
  if (errors.length) throw new AggregateError(errors, "Apple test cleanup failed.");
}
export async function boundedObservation(predicate: () => boolean) {
  const deadline = Date.now() + 2000;
  while (!predicate()) {
    assert.ok(Date.now() < deadline, "owned provider must reach the held boundary");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}
export function cookieJar(response: Response, previous = "") {
  const jar = new Map(
    previous
      .split("; ")
      .filter(Boolean)
      .map((part) => part.split("=", 2) as [string, string]),
  );
  for (const line of response.headers.getSetCookie()) {
    const [name, value] = line.split(";", 1)[0]!.split("=", 2);
    if (value) jar.set(name!, value);
    else jar.delete(name!);
  }
  return [...jar].map(([name, value]) => `${name}=${value}`).join("; ");
}
/** Native signed HTTP protocol oracle; no private Askr helper is imported. */
export async function appleFixture(
  provider: ProviderDefinition,
  options: {
    onSignIn?: ProviderSessionOptions["onSignIn"];
    store?: ProviderSessionStore;
    maxAgeSeconds?: number;
  } = {},
) {
  let time = 1_800_000_000_000;
  let claims: Record<string, unknown> = {};
  let refreshClaims: Record<string, unknown> = {};
  let refreshFailure: string | undefined;
  let transportFailure = false;
  let refreshIdToken = true;
  let issueRefreshToken = true;
  let invalidSignature = false;
  let rotate = false;
  let user: string | undefined;
  let refreshes = 0;
  let exchanges = 0;
  const requests: {
    url: string;
    fields: URLSearchParams;
    secret: string;
    secretClaims: Record<string, unknown>;
  }[] = [];
  const errors: unknown[] = [];
  const codes = new Map<string, { nonce: string; challenge: string }>();
  const refreshTokens = new Map<string, { nonce: string }>();
  const holds = new Set<() => void>();
  let held: { promise: Promise<void>; release: () => void; entered: boolean } | undefined;
  const signedToken = async (claims: Readonly<Record<string, unknown>>) => {
    const token = await signer.sign({ claims });
    if (!invalidSignature) return token;
    const [head, body, signature] = token.split(".");
    return `${head}.${body}.${signature![0] === "A" ? "B" : "A"}${signature!.slice(1)}`;
  };
  const server = createServer(async (request, response) => {
    try {
      const url = new URL(String(request.headers["x-apple-url"]));
      const json = (value: unknown) => {
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify(value));
      };
      if (url.pathname === "/.well-known/openid-configuration")
        return json({
          issuer: appleOrigin,
          authorization_endpoint: `${appleOrigin}/auth/authorize`,
          token_endpoint: `${appleOrigin}/auth/token`,
          jwks_uri: `${appleOrigin}/auth/keys`,
          revocation_endpoint: `${appleOrigin}/auth/revoke`,
          scopes_supported: ["openid", "email", "name"],
        });
      if (url.pathname === "/auth/keys")
        return json({
          keys: [
            { ...identity.publicKey.export({ format: "jwk" }), kid: "apple-test", alg: "RS256" },
          ],
        });
      if (url.pathname === "/auth/authorize") {
        assert.equal(url.searchParams.get("client_id"), servicesId);
        assert.equal(url.searchParams.get("redirect_uri"), `${appOrigin}/auth/callback/apple`);
        assert.equal(url.searchParams.get("response_type"), "code");
        assert.equal(url.searchParams.get("response_mode"), "form_post");
        assert.equal(url.searchParams.get("code_challenge_method"), "S256");
        assert.deepEqual(url.searchParams.get("scope")!.split(" ").sort(), [
          "email",
          "name",
          "openid",
        ]);
        for (const name of ["resource", "audience"])
          assert.equal(url.searchParams.has(name), false);
        const code = crypto.randomUUID();
        codes.set(code, {
          nonce: url.searchParams.get("nonce")!,
          challenge: url.searchParams.get("code_challenge")!,
        });
        // The native fixture transports the authorized fields in Location; complete() submits
        // them as the real form_post request. Browser auto-posting is a separate app gate.
        const callback = new URL(url.searchParams.get("redirect_uri")!);
        callback.searchParams.set("code", code);
        callback.searchParams.set("state", url.searchParams.get("state")!);
        response.writeHead(303, { location: callback.href });
        response.end();
        return;
      }
      let body = "";
      for await (const chunk of request) body += chunk;
      const fields = new URLSearchParams(body);
      assert.equal(request.method, "POST");
      assert.equal(fields.get("client_id"), servicesId);
      assert.equal(request.headers.authorization, undefined);
      const secret = fields.get("client_secret")!;
      const [header, payload, signature] = secret.split(".");
      assert.deepEqual(JSON.parse(Buffer.from(header!, "base64url").toString()), {
        alg: "ES256",
        kid: keyId,
      });
      assert.ok(
        verify(
          "sha256",
          Buffer.from(`${header}.${payload}`),
          { key: signing.publicKey, dsaEncoding: "ieee-p1363" },
          Buffer.from(signature!, "base64url"),
        ),
        "real ES256 signature must verify independently",
      );
      const secretClaims = JSON.parse(Buffer.from(payload!, "base64url").toString());
      assert.equal(secretClaims.iss, teamId);
      assert.equal(secretClaims.sub, servicesId);
      assert.equal(secretClaims.aud, appleOrigin);
      assert.ok(Number.isInteger(secretClaims.iat) && secretClaims.iat <= time / 1000);
      assert.equal(secretClaims.exp - secretClaims.iat, 300);
      assert.ok(secretClaims.exp > time / 1000);
      requests.push({ url: url.href, fields, secret, secretClaims });
      if (url.pathname === "/auth/revoke") {
        assert.equal(fields.get("token_type_hint"), "refresh_token");
        assert.ok(refreshTokens.delete(fields.get("token")!));
        response.end();
        return;
      }
      assert.equal(url.pathname, "/auth/token");
      for (const name of ["resource", "audience", "scope"]) assert.equal(fields.has(name), false);
      if (fields.get("grant_type") === "refresh_token") {
        refreshes++;
        const prior = refreshTokens.get(fields.get("refresh_token")!);
        assert.ok(prior);
        const activeHold = held;
        if (activeHold) {
          activeHold.entered = true;
          await activeHold.promise;
        }
        if (transportFailure) {
          response.statusCode = 503;
          return json({ error: "PRIVATE_UPSTREAM_CANARY" });
        }
        if (refreshFailure) {
          response.statusCode = 400;
          return json({ error: refreshFailure });
        }
        const next = `APPLE_ROTATED_${refreshes}`;
        if (rotate) {
          refreshTokens.delete(fields.get("refresh_token")!);
          refreshTokens.set(next, prior);
        }
        return json({
          access_token: `APPLE_UNUSED_RENEWED_${refreshes}`,
          token_type: "Bearer",
          expires_in: 3600,
          refresh_token: rotate ? next : undefined,
          id_token: refreshIdToken
            ? await signedToken({
                iss: appleOrigin,
                aud: servicesId,
                sub: "apple-account",
                iat: time / 1000,
                exp: time / 1000 + 600,
                ...refreshClaims,
              })
            : undefined,
        });
      }
      assert.equal(fields.get("grant_type"), "authorization_code");
      exchanges++;
      const authorized = codes.get(fields.get("code")!);
      codes.delete(fields.get("code")!);
      assert.ok(authorized);
      assert.equal(fields.get("redirect_uri"), `${appOrigin}/auth/callback/apple`);
      assert.equal(
        Buffer.from(
          await crypto.subtle.digest(
            "SHA-256",
            new TextEncoder().encode(fields.get("code_verifier")!),
          ),
        ).toString("base64url"),
        authorized.challenge,
      );
      const refresh = `APPLE_REFRESH_${exchanges}`;
      refreshTokens.set(refresh, { nonce: authorized.nonce });
      return json({
        access_token: `APPLE_PRIVATE_ACCESS_${exchanges}`,
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: issueRefreshToken ? refresh : undefined,
        id_token: await signedToken({
          iss: appleOrigin,
          aud: servicesId,
          sub: "apple-account",
          nonce: authorized.nonce,
          iat: time / 1000,
          exp: time / 1000 + 600,
          ...claims,
        }),
      });
    } catch (error) {
      errors.push(error);
      response.statusCode = 500;
      response.end("Owned Apple protocol assertion failed.");
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  cleanup.push(async () => {
    for (const release of holds) release();
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
    assert.deepEqual(errors, []);
  });
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const providerFetch: typeof fetch = (input, init) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    assert.equal(url.origin, appleOrigin);
    const headers = new Headers(init?.headers);
    headers.set("x-apple-url", url.href);
    return fetch(`http://127.0.0.1:${address.port}${url.pathname}${url.search}`, {
      ...init,
      headers,
    });
  };
  const makeEngine = () =>
    createProviderSession({
      origin: appOrigin,
      providers: [provider],
      session: {
        secrets: [Buffer.alloc(32, 73).toString("base64url")],
        store: options.store,
        maxAgeSeconds: options.maxAgeSeconds ?? 259200,
      },
      fetch: providerFetch,
      clock: () => time,
      onSignIn: options.onSignIn,
    });
  const engine = makeEngine();
  cleanup.push(() => engine.close());
  const appRequest = (cookie: string, signal?: AbortSignal) =>
    new Request(`${appOrigin}/private`, { headers: { cookie }, signal });
  async function start(cookie = "") {
    const request = appRequest(cookie);
    const response = await engine.finalize(
      request,
      await engine.login(request, { provider: "apple", returnTo: "/private?tab=one#name" }),
    );
    const authorization = new URL(response.headers.get("location")!);
    const issued = await providerFetch(authorization.href, { redirect: "manual" });
    assert.equal(issued.status, 303);
    return {
      cookie: cookieJar(response, cookie),
      response,
      authorization,
      fields: new URL(issued.headers.get("location")!).searchParams,
      user,
    };
  }
  function callbackRequest(started: Awaited<ReturnType<typeof start>>, signal?: AbortSignal) {
    const fields = new URLSearchParams(started.fields);
    if (started.user !== undefined) fields.set("user", started.user);
    return new Request(`${appOrigin}/auth/callback/apple`, {
      method: "POST",
      headers: {
        cookie: started.cookie
          .split("; ")
          .filter((part) => part.startsWith("__Host-askr-txn-apple="))
          .join("; "),
        "content-type": "application/x-www-form-urlencoded",
      },
      body: fields,
      signal,
    });
  }
  async function complete(started: Awaited<ReturnType<typeof start>>) {
    const request = callbackRequest(started);
    const response = await engine.finalize(
      request,
      await engine.callback(request, { provider: "apple" }),
    );
    assert.equal(response.headers.get("location"), `${appOrigin}/private?tab=one#name`);
    return { cookie: cookieJar(response, started.cookie), response };
  }
  return {
    engine,
    sibling() {
      assert.ok(options.store, "sibling engines require the explicitly shared store");
      const sibling = makeEngine();
      cleanup.push(() => sibling.close());
      return sibling;
    },
    provider,
    requests,
    appRequest,
    start,
    complete,
    callbackRequest,
    async signIn(cookie = "") {
      return complete(await start(cookie));
    },
    async logout(cookie: string, revoke = false) {
      const request = appRequest(cookie);
      const response = await engine.finalize(
        request,
        await engine.logout(request, { provider: "apple", revoke }),
      );
      return { cookie: cookieJar(response, cookie), response };
    },
    advance(milliseconds: number) {
      time += milliseconds;
    },
    setClaims(value: Record<string, unknown>) {
      claims = value;
    },
    setRefreshClaims(value: Record<string, unknown>) {
      refreshClaims = value;
    },
    setRefreshFailure(value: string | undefined) {
      refreshFailure = value;
    },
    setTransportFailure(value: boolean) {
      transportFailure = value;
    },
    setInvalidSignature(value: boolean) {
      invalidSignature = value;
    },
    setIssueRefreshToken(value: boolean) {
      issueRefreshToken = value;
    },
    setRefreshIdToken(value: boolean) {
      refreshIdToken = value;
    },
    setRotation(value: boolean) {
      rotate = value;
    },
    setUser(value: string | undefined) {
      user = value;
    },
    holdRefresh() {
      let release!: () => void;
      const promise = new Promise<void>((resolve) => {
        release = resolve;
      });
      const state = { promise, release, entered: false };
      held = state;
      holds.add(release);
      return state;
    },
    get time() {
      return time;
    },
    get refreshes() {
      return refreshes;
    },
    get exchanges() {
      return exchanges;
    },
  };
}
