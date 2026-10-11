import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { createServer } from "node:http";
import { createJwtSigner } from "../src/jwt";
import { createProviderSession } from "../src/server";
import type {
  ProviderDefinition,
  ProviderLoginRequest,
  ProviderLogoutRequest,
} from "../src/server";

export const appOrigin = "https://app.example.test";
export const clientId = "test-client";
export const clientSecret = "TEST_ONLY_CLIENT_SECRET";
const key = Buffer.alloc(32, 41).toString("base64url");
const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
const signer = createJwtSigner({
  privateKey: pair.privateKey.export({ format: "jwk" }),
  kid: "preset",
});
const cleanup: (() => Promise<void>)[] = [];
export async function closePresetFixtures() {
  const failures: unknown[] = [];
  for (const close of cleanup.splice(0).reverse()) {
    try {
      await close();
    } catch (error) {
      failures.push(error);
    }
  }
  if (failures.length) throw new AggregateError(failures, "Simulated provider cleanup failed.");
}

export function responseCookies(response: Response, previous = "") {
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

/** A real owned HTTP provider. Only HTTPS transport is redirected; protocol validation stays active. */
export async function presetFixture(
  provider: ProviderDefinition,
  options: {
    authorization: string;
    token: string;
    jwks: string;
    logout?: string;
    revocation?: string;
    resourceParameter?: string;
  },
) {
  let now = 1_800_000_000_000;
  let claims: Record<string, unknown> = {};
  let discoveryIssuer = provider.issuer;
  let tokenIssuer = provider.issuer;
  let exchanges = 0;
  let refreshes = 0;
  const requests: { url: string; method: string; fields: URLSearchParams }[] = [];
  const protocolErrors: unknown[] = [];
  const codes = new Map<
    string,
    { nonce: string; challenge: string; scopes: string; resource: string }
  >();
  const refreshTokens = new Set<string>();
  const origins = new Set(
    [
      provider.issuer,
      options.authorization,
      options.token,
      options.jwks,
      options.logout,
      options.revocation,
    ]
      .filter((value): value is string => value !== undefined)
      .map((value) => new URL(value).origin),
  );
  const server = createServer(async (request, response) => {
    try {
      const url = new URL(String(request.headers["x-test-provider-url"]));
      const json = (value: unknown) => {
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify(value));
      };
      if (url.href === `${provider.issuer.replace(/\/$/u, "")}/.well-known/openid-configuration`)
        return json({
          issuer: discoveryIssuer,
          authorization_endpoint: options.authorization,
          token_endpoint: options.token,
          jwks_uri: options.jwks,
          ...(options.logout ? { end_session_endpoint: options.logout } : {}),
          ...(options.revocation ? { revocation_endpoint: options.revocation } : {}),
        });
      if (url.href === options.jwks)
        return json({
          keys: [{ ...pair.publicKey.export({ format: "jwk" }), kid: "preset", alg: "RS256" }],
        });
      if (url.origin + url.pathname === options.authorization) {
        assert.equal(url.searchParams.get("client_id"), clientId);
        assert.equal(url.searchParams.get("response_type"), "code");
        assert.equal(url.searchParams.get("code_challenge_method"), "S256");
        assert.equal(
          url.searchParams.get("redirect_uri"),
          `${appOrigin}/auth/callback/${provider.id}`,
        );
        const code = crypto.randomUUID();
        codes.set(code, {
          nonce: url.searchParams.get("nonce")!,
          challenge: url.searchParams.get("code_challenge")!,
          scopes: url.searchParams.get("scope")!,
          resource: url.searchParams.get(options.resourceParameter ?? "resource") ?? "identity",
        });
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
      requests.push({ url: url.href, method: request.method!, fields });
      if (url.href === options.token || url.href === options.revocation) {
        assert.equal(request.method, "POST");
        assert.equal(fields.get("client_id"), clientId);
        assert.equal(fields.get("client_secret"), clientSecret);
        assert.equal(request.headers.authorization, undefined);
      }
      if (url.href === options.revocation) {
        assert.equal(fields.get("token_type_hint"), "refresh_token");
        assert.ok(refreshTokens.delete(fields.get("token")!));
        response.statusCode = 200;
        response.end();
        return;
      }
      if (url.href === options.token) {
        if (fields.get("grant_type") === "refresh_token") {
          refreshes++;
          assert.ok(refreshTokens.delete(fields.get("refresh_token")!));
          const rotated = `ROTATED_${refreshes}`;
          refreshTokens.add(rotated);
          return json({
            access_token: `RENEWED_${refreshes}`,
            refresh_token: rotated,
            expires_in: 60,
            token_type: "Bearer",
            scope: fields.get("scope"),
          });
        }
        exchanges++;
        assert.equal(fields.get("grant_type"), "authorization_code");
        const stored = codes.get(fields.get("code")!);
        codes.delete(fields.get("code")!);
        assert.ok(stored, "authorization code must be unconsumed");
        const challenge = Buffer.from(
          await crypto.subtle.digest(
            "SHA-256",
            new TextEncoder().encode(fields.get("code_verifier")!),
          ),
        ).toString("base64url");
        assert.equal(challenge, stored.challenge);
        assert.equal(fields.get("redirect_uri"), `${appOrigin}/auth/callback/${provider.id}`);
        if (options.resourceParameter)
          assert.equal(
            fields.get(options.resourceParameter),
            stored.resource === "identity" ? null : stored.resource,
          );
        const refresh = `REFRESH_${exchanges}`;
        refreshTokens.add(refresh);
        return json({
          access_token: `ACCESS_${exchanges}_${stored.resource}`,
          refresh_token: refresh,
          expires_in: 60,
          token_type: "Bearer",
          scope: stored.scopes,
          id_token: await signer.sign({
            claims: {
              iss: tokenIssuer,
              sub: "account",
              aud: clientId,
              nonce: stored.nonce,
              iat: now / 1000,
              exp: now / 1000 + 600,
              ...claims,
            },
          }),
        });
      }
      response.statusCode = 404;
      response.end();
    } catch (error) {
      protocolErrors.push(error);
      response.statusCode = 500;
      response.end("Simulated provider contract failed.");
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  cleanup.push(async () => {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
    assert.deepEqual(protocolErrors, [], "real HTTP provider must receive valid protocol requests");
  });
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const providerFetch: typeof fetch = (input, init) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    assert.ok(
      origins.has(url.origin),
      "only configured provider transport may reach the owned listener",
    );
    const headers = new Headers(init?.headers);
    headers.set("x-test-provider-url", url.href);
    return fetch(`http://127.0.0.1:${address.port}${url.pathname}${url.search}`, {
      ...init,
      headers,
    });
  };
  const engine = createProviderSession({
    origin: appOrigin,
    providers: [provider],
    session: { secrets: [key] },
    postLogoutRedirects: ["/", "/signed-out"],
    fetch: providerFetch,
    clock: () => now,
  });
  cleanup.push(() => engine.close());
  function appRequest(cookie: string, path = "/private") {
    return new Request(`${appOrigin}${path}`, { headers: { cookie } });
  }
  async function start(
    cookie = "",
    options: Omit<ProviderLoginRequest, "provider" | "returnTo"> = {},
  ) {
    const request = appRequest(cookie, `/auth/login/${provider.id}`);
    const response = await engine.finalize(
      request,
      await engine.login(request, {
        provider: provider.id,
        returnTo: "/private?tab=one#section",
        ...options,
      }),
    );
    const authorization = new URL(response.headers.get("location")!);
    const result = await providerFetch(authorization.href, { redirect: "manual" });
    assert.equal(result.status, 303);
    return {
      cookie: responseCookies(response, cookie),
      response,
      authorization,
      callback: new URL(result.headers.get("location")!),
    };
  }
  async function complete(started: Awaited<ReturnType<typeof start>>) {
    const request = new Request(started.callback, { headers: { cookie: started.cookie } });
    const response = await engine.finalize(
      request,
      await engine.callback(request, { provider: provider.id }),
    );
    assert.equal(response.headers.get("location"), `${appOrigin}/private?tab=one#section`);
    return { cookie: responseCookies(response, started.cookie), response };
  }
  return {
    provider,
    engine,
    requests,
    appRequest,
    start,
    complete,
    async signIn(cookie = "", options: Omit<ProviderLoginRequest, "provider" | "returnTo"> = {}) {
      return complete(await start(cookie, options));
    },
    async logout(cookie: string, options: ProviderLogoutRequest = {}) {
      const request = appRequest(cookie, "/auth/logout");
      const response = await engine.finalize(request, await engine.logout(request, options));
      return { response, cookie: responseCookies(response, cookie) };
    },
    setClaims(value: Record<string, unknown>) {
      claims = value;
    },
    setDiscoveryIssuer(value: string) {
      discoveryIssuer = value;
    },
    setTokenIssuer(value: string) {
      tokenIssuer = value;
    },
    advance(milliseconds: number) {
      now += milliseconds;
    },
    get exchanges() {
      return exchanges;
    },
    get refreshes() {
      return refreshes;
    },
  };
}
