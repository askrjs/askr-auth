import { describe, expect, it } from "vitest";
import { generateKeyPairSync, sign } from "node:crypto";
import {
  createAuth,
  allOf,
  anyOf,
  requireAnonymous,
  requirePermission,
  requireRole,
  requireScope,
  requireUser,
  type AuthContext,
  type Principal,
} from "../src";
import { createJwtValidator, validateOidcIdToken } from "../src/jwt";
import { createOidcClient } from "../src/oidc";

const oidcMetadata = {
  issuer: "https://login.example.test",
  authorization_endpoint: "https://login.example.test/authorize",
  token_endpoint: "https://login.example.test/token",
  jwks_uri: "https://login.example.test/.well-known/jwks.json",
  userinfo_endpoint: "https://login.example.test/userinfo",
};

const oidcFetch = async (input: RequestInfo | URL) => {
  expect(String(input)).toBe("https://login.example.test/.well-known/openid-configuration");
  return new Response(JSON.stringify(oidcMetadata), {
    headers: { "content-type": "application/json" },
  });
};

describe("OIDC client", () => {
  it("should discover an external OIDC provider from its issuer", async () => {
    const client = createOidcClient({
      issuer: "https://login.example.test",
      clientId: "askr-client",
      redirectUri: "https://app.example.test/auth/callback",
      fetch: oidcFetch,
    });

    await expect(client.discover()).resolves.toEqual(oidcMetadata);
  });

  it("should create an authorization-code PKCE request with state and nonce", async () => {
    const client = createOidcClient({
      issuer: "https://login.example.test",
      clientId: "askr-client",
      redirectUri: "https://app.example.test/auth/callback",
      scopes: ["openid", "profile", "email"],
      fetch: oidcFetch,
    });

    const request = await client.createAuthorizationRequest({
      state: "state-1",
      nonce: "nonce-1",
      codeVerifier: "test-verifier",
    });
    const url = new URL(request.url);
    expect(url.origin + url.pathname).toBe("https://login.example.test/authorize");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("client_id")).toBe("askr-client");
    expect(url.searchParams.get("redirect_uri")).toBe("https://app.example.test/auth/callback");
    expect(url.searchParams.get("scope")).toBe("openid profile email");
    expect(url.searchParams.get("state")).toBe("state-1");
    expect(url.searchParams.get("nonce")).toBe("nonce-1");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("code_challenge")).toBe("JBbiqONGWPaAmwXk_8bT6UnlPfrn65D32eZlJS-zGG0");
    expect(request.state).toBe("state-1");
    expect(request.codeVerifier).toBe("test-verifier");
  });

  it("should exchange an authorization code with PKCE parameters for tokens", async () => {
    let tokenInit: RequestInit | undefined;
    const fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith("openid-configuration")) {
        return new Response(JSON.stringify(oidcMetadata), { status: 200 });
      }
      tokenInit = init;
      return new Response(JSON.stringify({
        access_token: "access-1",
        id_token: "id-token-1",
        token_type: "Bearer",
        expires_in: 300,
      }), { status: 200 });
    };
    const client = createOidcClient({
      issuer: "https://login.example.test",
      clientId: "askr-client",
      redirectUri: "https://app.example.test/auth/callback",
      fetch,
    });

    await expect(client.exchangeCode({
      code: "code-1",
      codeVerifier: "test-verifier",
    })).resolves.toEqual({
      access_token: "access-1",
      id_token: "id-token-1",
      token_type: "Bearer",
      expires_in: 300,
    });
    expect(tokenInit?.method).toBe("POST");
    expect(tokenInit?.headers).toMatchObject({ "content-type": "application/x-www-form-urlencoded" });
    const body = new URLSearchParams(String(tokenInit?.body));
    expect(Object.fromEntries(body)).toEqual({
      grant_type: "authorization_code",
      code: "code-1",
      redirect_uri: "https://app.example.test/auth/callback",
      client_id: "askr-client",
      code_verifier: "test-verifier",
    });
  });

  it("should require the authorization request nonce in the validated ID token", async () => {
    await expect(validateOidcIdToken(token({ ...validPayload, nonce: "nonce-1" }), {
      issuer: validPayload.iss,
      audience: validPayload.aud,
      nonce: "nonce-1",
      jwks,
      clock: () => now,
    })).resolves.toMatchObject({ id: "user-1", nonce: "nonce-1" });

    await expect(validateOidcIdToken(token({ ...validPayload, nonce: "wrong" }), {
      issuer: validPayload.iss,
      audience: validPayload.aud,
      nonce: "nonce-1",
      jwks,
      clock: () => now,
    })).rejects.toMatchObject({ code: "invalid_claim" });
  });

  it("should authenticate a confidential client at the token endpoint", async () => {
    let tokenInit: RequestInit | undefined;
    const fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith("openid-configuration")) {
        return new Response(JSON.stringify(oidcMetadata), { status: 200 });
      }
      tokenInit = init;
      return new Response(JSON.stringify({ access_token: "access-1", token_type: "Bearer" }));
    };
    const client = createOidcClient({
      issuer: "https://login.example.test",
      clientId: "askr-client",
      clientSecret: "client-secret",
      redirectUri: "https://app.example.test/auth/callback",
      fetch,
    });

    await client.exchangeCode({ code: "code-1", codeVerifier: "test-verifier" });
    expect(new Headers(tokenInit?.headers).get("authorization")).toBe(
      `Basic ${btoa("askr-client:client-secret")}`,
    );
  });
});

const now = 1_700_000_000;
const keyPair = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = keyPair.publicKey.export({ format: "jwk" });

function base64url(value: string | Buffer): string {
  return Buffer.from(value).toString("base64url");
}

function token(payload: Record<string, unknown>, kid = "key-1", algorithm = "RS256") {
  const header = base64url(JSON.stringify({ alg: algorithm, kid, typ: "JWT" }));
  const body = base64url(JSON.stringify(payload));
  const input = `${header}.${body}`;
  const signature = algorithm === "none"
    ? ""
    : sign("RSA-SHA256", Buffer.from(input), keyPair.privateKey).toString("base64url");
  return `${input}.${signature}`;
}

const jwks = { keys: [{ ...jwk, kid: "key-1", alg: "RS256", use: "sig" }] };
const validPayload = {
  sub: "user-1",
  iss: "https://issuer.example.test",
  aud: "askr-api",
  iat: now,
  nbf: now,
  exp: now + 300,
  scope: "openid profile users:read",
  roles: ["admin"],
};

describe("JWT resource server", () => {
  it("should validate a signed RS256 access token and normalize its principal", async () => {
    const validator = createJwtValidator({
      issuer: validPayload.iss,
      audience: validPayload.aud,
      jwks,
      clock: () => now,
    });

    await expect(validator.validate(token(validPayload))).resolves.toMatchObject({
      id: "user-1",
      subject: "user-1",
      iss: validPayload.iss,
      scope: validPayload.scope,
      roles: ["admin"],
    });
  });

  it("should reject a token with an invalid signature", async () => {
    const validator = createJwtValidator({ issuer: validPayload.iss, jwks, clock: () => now });
    const signed = token(validPayload).split(".");
    signed[2] = `${signed[2][0] === "A" ? "B" : "A"}${signed[2].slice(1)}`;
    const invalid = signed.join(".");
    await expect(validator.validate(invalid)).rejects.toMatchObject({ code: "invalid_signature" });
  });

  it.each([
    ["issuer", { iss: "https://wrong.example.test" }],
    ["audience", { aud: "another-api" }],
    ["expiration", { exp: now - 1 }],
    ["not-before", { nbf: now + 1 }],
    ["issued-at", { iat: now + 1 }],
  ])("should reject a token with an invalid %s claim", async (_name, change) => {
    const validator = createJwtValidator({
      issuer: validPayload.iss,
      audience: validPayload.aud,
      jwks,
      clock: () => now,
    });
    await expect(validator.validate(token({ ...validPayload, ...change }))).rejects.toMatchObject({
      code: "invalid_claim",
    });
  });

  it("should reject alg none and unknown key ids", async () => {
    const validator = createJwtValidator({ issuer: validPayload.iss, jwks, clock: () => now });
    await expect(validator.validate(token(validPayload, "key-1", "none"))).rejects.toMatchObject({
      code: "unsupported_algorithm",
    });
    await expect(validator.validate(token(validPayload, "rotated-key"))).rejects.toMatchObject({
      code: "unknown_key",
    });
  });

  it("should resolve a rotated key through a key provider", async () => {
    const validator = createJwtValidator({
      issuer: validPayload.iss,
      jwks: async () => jwks,
      clock: () => now,
    });
    await expect(validator.validate(token(validPayload, "key-1"))).resolves.toHaveProperty("id", "user-1");
  });

  it("should resolve a bearer access token into the shared auth context", async () => {
    const validator = createJwtValidator({
      issuer: validPayload.iss,
      audience: validPayload.aud,
      jwks,
      clock: () => now,
    });
    const auth = createAuth({ jwt: validator });
    const bearerRequest = new Request("https://api.example.test/users", {
      headers: { authorization: `Bearer ${token(validPayload)}` },
    });

    await expect(auth.resolve(bearerRequest)).resolves.toMatchObject({
      authenticated: true,
      principal: { id: "user-1", subject: "user-1" },
      session: null,
      scopes: ["openid", "profile", "users:read"],
    });
  });
});

describe("Principal contract", () => {
  it("should describe identity, claims, roles, and permissions as one value", () => {
    const principal: Principal = {
      id: "user-1",
      subject: "auth0|user-1",
      roles: ["admin"],
      permissions: ["users:read"],
      plan: "pro",
    };

    expect(principal.id).toBe("user-1");
    expect(principal.subject).toBe("auth0|user-1");
    expect(principal.plan).toBe("pro");
    expect(principal.roles).toContain("admin");
    expect(principal.permissions).toContain("users:read");
  });

  it("should allow provider-specific claims without weakening the core contract", () => {
    const principal: Principal = { id: "user-1", organizationId: "org-1" };
    expect(principal.organizationId).toBe("org-1");
  });
});

const request = (url = "https://tenant.example.test/account") =>
  new Request(url, { headers: { cookie: "session=s-1" } });

describe("shared auth resolution", () => {
  it("should resolve anonymous requests with empty auth context", async () => {
    const auth = createAuth({ sessions: { get: async () => null } });
    await expect(auth.resolve(new Request("https://example.test/"))).resolves.toEqual({
      authenticated: false,
      principal: null,
      session: null,
      tenant: null,
    });
  });

  it("should resolve opaque browser sessions", async () => {
    const auth = createAuth({
      sessions: {
        get: async (id) => id === "s-1"
          ? { id, subject: "user-1", expiresAt: Date.now() + 60_000 }
          : null,
      },
      principals: { get: async (subject) => ({ id: subject, roles: ["admin"] }) },
    });
    await expect(auth.resolve(request())).resolves.toMatchObject({
      authenticated: true,
      session: { id: "s-1", subject: "user-1" },
      principal: { id: "user-1", roles: ["admin"] },
    });
  });

  it("should resolve the configured tenant explicitly", async () => {
    const auth = createAuth({
      tenant: async (req) => new URL(req.url).hostname,
      sessions: { get: async () => null },
    });
    await expect(auth.resolve(request())).resolves.toMatchObject({ tenant: "tenant.example.test" });
  });

  it("should isolate auth state across concurrent requests", async () => {
    const auth = createAuth({
      sessions: { get: async (id) => ({ id, subject: id, expiresAt: Date.now() + 60_000 }) },
      principals: { get: async (subject) => ({ id: subject }) },
    });
    const [one, two] = await Promise.all([
      auth.resolve(request("https://one.example.test/")),
      auth.resolve(new Request("https://two.example.test/", { headers: { cookie: "session=s-2" } })),
    ]);
    expect(one.principal?.id).toBe("s-1");
    expect(two.principal?.id).toBe("s-2");
  });

  it("should evaluate shared requirements against one auth context", async () => {
    const context: AuthContext = {
      authenticated: true,
      principal: { id: "u", roles: ["admin"], permissions: ["users:read"] },
      session: null,
      tenant: "t",
      scopes: ["users:read"],
    };
    await expect(Promise.resolve(requireUser()(context))).resolves.toEqual({ allowed: true });
    await expect(Promise.resolve(requireRole("admin")(context))).resolves.toEqual({ allowed: true });
    await expect(Promise.resolve(requirePermission("users:read")(context))).resolves.toEqual({ allowed: true });
    await expect(Promise.resolve(requireScope("users:read")(context))).resolves.toEqual({ allowed: true });
  });

  it("should return unauthenticated given requireUser and anonymous context", async () => {
    const context: AuthContext = {
      authenticated: false,
      principal: null,
      session: null,
      tenant: null,
    };
    await expect(Promise.resolve(requireUser()(context))).resolves.toEqual({
      allowed: false,
      reason: "unauthenticated",
    });
  });

  it("should return already authenticated given requireAnonymous and a user", async () => {
    const context: AuthContext = {
      authenticated: true,
      principal: { id: "user-1" },
      session: null,
      tenant: null,
    };
    await expect(Promise.resolve(requireAnonymous()(context))).resolves.toEqual({
      allowed: false,
      reason: "already_authenticated",
    });
  });

  it("should return forbidden given an authenticated user without a role", async () => {
    const context: AuthContext = {
      authenticated: true,
      principal: { id: "user-1" },
      session: null,
      tenant: null,
    };
    await expect(Promise.resolve(requireRole("admin")(context))).resolves.toEqual({
      allowed: false,
      reason: "forbidden",
    });
  });

  it("should compose requirements with allOf and anyOf", async () => {
    const context: AuthContext = {
      authenticated: true,
      principal: { id: "user-1", roles: ["admin"] },
      session: null,
      tenant: null,
    };
    await expect(Promise.resolve(allOf(requireUser(), requireRole("admin"))(context))).resolves.toEqual({ allowed: true });
    await expect(Promise.resolve(anyOf(requirePermission("write"), requireRole("admin"))(context))).resolves.toEqual({ allowed: true });
  });
});
