import { generateKeyPairSync } from "node:crypto";
import { expect, it } from "vite-plus/test";
import { createJwtSigner } from "../src/jwt";
import { createOidcClient } from "../src/oidc";
import {
  exchangeProviderTokens,
  providerMetadata,
  providerTransport,
  validateProviderIdentity,
} from "../src/provider-session-oidc";
import { createOidcProvider } from "../src/server";
import { parseBoundedJsonResponse } from "../src/oidc-response";

const issuer = "https://login.example.test";
const metadata = {
  issuer,
  authorization_endpoint: `${issuer}/authorize`,
  token_endpoint: `${issuer}/token`,
  jwks_uri: `${issuer}/jwks`,
};
const provider = createOidcProvider({
  id: "oidc",
  issuer,
  clientId: "client",
  clientAuthentication: { method: "client_secret_post", secret: "secret" },
  identityScopes: ["openid"],
});
const keyPair = generateKeyPairSync("rsa", { modulusLength: 2048 });
const signer = createJwtSigner({
  privateKey: keyPair.privateKey.export({ format: "jwk" }) as JsonWebKey,
  kid: "key-1",
});
function streamedResponse(
  text: string,
  chunkBytes = 16_384,
  headers: Record<string, string> = {},
  status = 200,
) {
  const bytes = new TextEncoder().encode(text);
  let offset = 0;
  let enqueuedChunks = 0;
  let cancelled = false;
  let markCancelled!: () => void;
  const cancellation = new Promise<void>((resolve) => {
    markCancelled = resolve;
  });
  const totalChunks = Math.ceil(bytes.byteLength / chunkBytes);
  const body = new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        if (offset >= bytes.byteLength) {
          controller.close();
          return;
        }
        const end = Math.min(offset + chunkBytes, bytes.byteLength);
        controller.enqueue(bytes.subarray(offset, end));
        offset = end;
        enqueuedChunks++;
      },
      cancel() {
        cancelled = true;
        markCancelled();
      },
    },
    { highWaterMark: 0 },
  );
  return {
    response: new Response(body, { headers, status }),
    stats: () => ({ enqueuedChunks, totalChunks, cancelled }),
    cancellation,
  };
}

function stalledResponse() {
  let started!: () => void;
  let cancelled = false;
  const reading = new Promise<void>((resolve) => {
    started = resolve;
  });
  const body = new ReadableStream<Uint8Array>(
    {
      pull() {
        started();
        return new Promise<void>(() => {});
      },
      cancel() {
        cancelled = true;
      },
    },
    { highWaterMark: 0 },
  );
  return { response: new Response(body), reading, wasCancelled: () => cancelled };
}

function oversizedJson(paddingCharacters = 1_200_000): string {
  return JSON.stringify({ padding: "x".repeat(paddingCharacters) });
}

async function signedIdToken(nonce = "nonce") {
  const now = Math.floor(Date.now() / 1000);
  return signer.sign({
    claims: { iss: issuer, sub: "user-1", aud: "client", nonce, iat: now, exp: now + 300 },
  });
}

it("accepts a JSON body exactly at the byte limit and enforces streamed bytes despite Content-Length", async () => {
  await expect(
    parseBoundedJsonResponse(new Response(new TextEncoder().encode("{}  ")), { maxBytes: 4 }),
  ).resolves.toEqual({});

  const body = streamedResponse("{" + " ".repeat(16) + "}", 3, { "content-length": "1" });
  await expect(parseBoundedJsonResponse(body.response, { maxBytes: 8 })).rejects.toMatchObject({
    name: "OidcResponseTooLargeError",
  });
  expect(body.stats()).toMatchObject({ enqueuedChunks: 3, cancelled: true });
  expect(body.stats().enqueuedChunks).toBeLessThan(body.stats().totalChunks);
});

it("cancels an in-flight body read when its operation signal aborts", async () => {
  let cancelled = false;
  const controller = new AbortController();
  const body = new ReadableStream<Uint8Array>(
    {
      cancel() {
        cancelled = true;
      },
    },
    { highWaterMark: 0 },
  );
  const pending = parseBoundedJsonResponse(new Response(body), { signal: controller.signal });
  controller.abort();
  await expect(pending).rejects.toMatchObject({ name: "AbortError" });
  expect(cancelled).toBe(true);

  let cancelledBeforeRead = false;
  const alreadyAborted = new AbortController();
  alreadyAborted.abort();
  const unreadBody = new ReadableStream<Uint8Array>(
    {
      cancel() {
        cancelledBeforeRead = true;
      },
    },
    { highWaterMark: 0 },
  );
  await expect(
    parseBoundedJsonResponse(new Response(unreadBody), { signal: alreadyAborted.signal }),
  ).rejects.toMatchObject({ name: "AbortError" });
  expect(cancelledBeforeRead).toBe(true);
});

it("propagates operation cancellation through provider discovery, token and JWKS reads", async () => {
  const discoveryBody = stalledResponse();
  const discoveryAbort = new AbortController();
  const discovery = providerMetadata(
    provider,
    async () => discoveryBody.response,
    async () => {},
    discoveryAbort.signal,
  );
  await discoveryBody.reading;
  discoveryAbort.abort();
  await expect(discovery).rejects.toMatchObject({ name: "AbortError" });
  expect(discoveryBody.wasCancelled()).toBe(true);

  const tokenBody = stalledResponse();
  const tokenAbort = new AbortController();
  const tokenRead = exchangeProviderTokens(
    provider,
    async () => tokenBody.response,
    metadata.token_endpoint,
    new URLSearchParams(),
    ["openid"],
    Date.now(),
    tokenAbort.signal,
  );
  await tokenBody.reading;
  tokenAbort.abort();
  await expect(tokenRead).rejects.toMatchObject({ name: "AbortError" });
  expect(tokenBody.wasCancelled()).toBe(true);

  const jwksBody = stalledResponse();
  const jwksAbort = new AbortController();
  const jwksRead = validateProviderIdentity(
    provider,
    await signedIdToken(),
    "nonce",
    metadata.jwks_uri,
    async () => jwksBody.response,
    Date.now,
    undefined,
    jwksAbort.signal,
  );
  await jwksBody.reading;
  jwksAbort.abort();
  await expect(jwksRead).rejects.toMatchObject({ name: "AbortError" });
  expect(jwksBody.wasCancelled()).toBe(true);
});

it("cancels a provider response that arrives after its operation has aborted", async () => {
  let resolveResponse!: (response: Response) => void;
  let markRequested!: () => void;
  const requested = new Promise<void>((resolve) => {
    markRequested = resolve;
  });
  const pendingResponse = new Promise<Response>((resolve) => {
    resolveResponse = resolve;
  });
  const body = streamedResponse("{}");
  const controller = new AbortController();
  const transport = providerTransport(
    async () => {
      markRequested();
      return pendingResponse;
    },
    controller.signal,
    async () => {},
  );
  const pending = transport("https://login.example.test/metadata");
  await requested;
  controller.abort();
  await expect(pending).rejects.toMatchObject({ name: "AbortError" });
  resolveResponse(body.response);
  await body.cancellation;
  expect(body.stats().cancelled).toBe(true);
});

it("bounds public OIDC discovery response bodies", async () => {
  const body = streamedResponse(oversizedJson());
  const client = createOidcClient({
    issuer,
    clientId: "client",
    redirectUri: "https://app.example.test/callback",
    fetch: async () => body.response,
  });

  await expect(client.discover()).rejects.toMatchObject({ code: "invalid-metadata" });
  expect(body.stats().cancelled).toBe(true);
  expect(body.stats().enqueuedChunks).toBeLessThan(body.stats().totalChunks);
});

it("cancels rejected discovery response bodies without reading them", async () => {
  const body = streamedResponse(oversizedJson(), 16_384, {}, 503);
  const client = createOidcClient({
    issuer,
    clientId: "client",
    redirectUri: "https://app.example.test/callback",
    fetch: async () => body.response,
  });

  await expect(client.discover()).rejects.toMatchObject({ code: "discovery-failed" });
  await body.cancellation;
  expect(body.stats()).toMatchObject({ enqueuedChunks: 0, cancelled: true });
});

it("bounds provider-session discovery response bodies and maps them to provider unavailable", async () => {
  const body = streamedResponse(oversizedJson());
  await expect(
    providerMetadata(
      provider,
      async () => body.response,
      async () => {},
    ),
  ).rejects.toMatchObject({ code: "provider-unavailable" });
  expect(body.stats().cancelled).toBe(true);
  expect(body.stats().enqueuedChunks).toBeLessThan(body.stats().totalChunks);
});

it("bounds public OIDC token response bodies", async () => {
  const body = streamedResponse(oversizedJson());
  const client = createOidcClient({
    issuer,
    clientId: "client",
    redirectUri: "https://app.example.test/callback",
    fetch: async (input) =>
      String(input).endsWith("openid-configuration")
        ? new Response(JSON.stringify(metadata))
        : body.response,
  });

  await expect(
    client.exchangeCode({
      code: "code",
      state: "state",
      request: { state: "state", nonce: "nonce", codeVerifier: "verifier" },
    }),
  ).rejects.toMatchObject({ code: "invalid-token-response" });
  expect(body.stats().cancelled).toBe(true);
  expect(body.stats().enqueuedChunks).toBeLessThan(body.stats().totalChunks);
});

it("keeps oversized non-success token responses in the exchange-failed category", async () => {
  const body = streamedResponse(oversizedJson(), 16_384, {}, 503);
  const client = createOidcClient({
    issuer,
    clientId: "client",
    redirectUri: "https://app.example.test/callback",
    fetch: async (input) =>
      String(input).endsWith("openid-configuration")
        ? new Response(JSON.stringify(metadata))
        : body.response,
  });

  await expect(
    client.exchangeCode({
      code: "code",
      state: "state",
      request: { state: "state", nonce: "nonce", codeVerifier: "verifier" },
    }),
  ).rejects.toMatchObject({ code: "exchange-failed" });
  expect(body.stats().cancelled).toBe(true);
  expect(body.stats().enqueuedChunks).toBeLessThan(body.stats().totalChunks);
});

it("bounds provider-session token responses and preserves the former character boundary", async () => {
  const prefix =
    '{"access_token":"a","token_type":"Bearer","expires_in":60,"scope":"openid","padding":"';
  const suffix = '"}';
  const exactCharacterLimit = prefix + "é".repeat(131_072 - prefix.length - suffix.length) + suffix;
  expect(exactCharacterLimit.length).toBe(131_072);
  expect(new TextEncoder().encode(exactCharacterLimit).byteLength).toBeGreaterThan(131_072);
  await expect(
    exchangeProviderTokens(
      provider,
      async () => new Response(exactCharacterLimit),
      metadata.token_endpoint,
      new URLSearchParams(),
      ["openid"],
      Date.now(),
      new AbortController().signal,
    ),
  ).resolves.toMatchObject({ accessToken: "a" });

  const body = streamedResponse(oversizedJson(300_000));
  await expect(
    exchangeProviderTokens(
      provider,
      async () => body.response,
      metadata.token_endpoint,
      new URLSearchParams(),
      ["openid"],
      Date.now(),
      new AbortController().signal,
    ),
  ).rejects.toMatchObject({ code: "provider-unavailable" });
  expect(body.stats().cancelled).toBe(true);
  expect(body.stats().enqueuedChunks).toBeLessThan(body.stats().totalChunks);
});

it("bounds public OIDC JWKS response bodies", async () => {
  const idToken = await signedIdToken();
  const body = streamedResponse(oversizedJson());
  const client = createOidcClient({
    issuer,
    clientId: "client",
    redirectUri: "https://app.example.test/callback",
    fetch: async (input) => {
      const url = String(input);
      if (url.endsWith("openid-configuration")) return new Response(JSON.stringify(metadata));
      if (url === metadata.jwks_uri) return body.response;
      return new Response(
        JSON.stringify({ access_token: "access", token_type: "Bearer", id_token: idToken }),
      );
    },
  });

  await expect(
    client.exchangeCode({
      code: "code",
      state: "state",
      request: { state: "state", nonce: "nonce", codeVerifier: "verifier" },
    }),
  ).rejects.toMatchObject({ code: "invalid-id-token" });
  expect(body.stats().cancelled).toBe(true);
  expect(body.stats().enqueuedChunks).toBeLessThan(body.stats().totalChunks);
});

it("bounds provider-session JWKS response bodies as provider failures", async () => {
  const body = streamedResponse(oversizedJson());
  await expect(
    validateProviderIdentity(
      provider,
      await signedIdToken(),
      "nonce",
      metadata.jwks_uri,
      async () => body.response,
      Date.now,
    ),
  ).rejects.toMatchObject({ code: "provider-unavailable" });
  expect(body.stats().cancelled).toBe(true);
  expect(body.stats().enqueuedChunks).toBeLessThan(body.stats().totalChunks);
});
