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
import { createJwtIssuer, createJwtValidator, validateOidcIdToken } from "../src/jwt";
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
  it("should give state-mismatch without network access when callback state differs", async () => {
    let calls = 0;
    const client = createOidcClient({ issuer: oidcMetadata.issuer, clientId: "askr-client", redirectUri: "https://app.example.test/callback", fetch: async () => { calls++; throw new Error("unexpected"); } });
    await expect(client.exchangeCode({ code: "code-1", state: "wrong", request: { state: "stored", nonce: "nonce-1", codeVerifier: "verifier" } })).rejects.toMatchObject({ code: "state-mismatch" });
    expect(calls).toBe(0);
  });

  it("should give invalid-metadata when discovery issuer does not exactly match", async () => {
    const client = createOidcClient({ issuer: oidcMetadata.issuer, clientId: "askr-client", redirectUri: "https://app.example.test/callback", fetch: async () => new Response(JSON.stringify({ ...oidcMetadata, issuer: `${oidcMetadata.issuer}/other` })) });
    await expect(client.discover()).rejects.toMatchObject({ code: "invalid-metadata" });
  });

  it("should give the expected result when discover an external OIDC provider from its issuer", async () => {
    const client = createOidcClient({
      issuer: "https://login.example.test",
      clientId: "askr-client",
      redirectUri: "https://app.example.test/auth/callback",
      fetch: oidcFetch,
    });

    await expect(client.discover()).resolves.toEqual(oidcMetadata);
  });

  it("should give the expected result when create an authorization-code PKCE request with state and nonce", async () => {
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
    expect(url.searchParams.get("code_challenge")).toBe(
      "JBbiqONGWPaAmwXk_8bT6UnlPfrn65D32eZlJS-zGG0",
    );
    expect(request.state).toBe("state-1");
    expect(request.codeVerifier).toBe("test-verifier");
  });

  it("should give the expected result when exchange an authorization code with PKCE parameters for tokens", async () => {
    let tokenInit: RequestInit | undefined;
    const fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith("openid-configuration")) {
        return new Response(JSON.stringify(oidcMetadata), { status: 200 });
      }
      if (String(input) === oidcMetadata.jwks_uri) return new Response(JSON.stringify(jwks));
      tokenInit = init;
      return new Response(
        JSON.stringify({
          access_token: "access-1",
          id_token: token({ ...validPayload, iss: oidcMetadata.issuer, aud: "askr-client", nonce: "nonce-1", iat: Math.floor(Date.now() / 1000), nbf: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 300 }),
          token_type: "Bearer",
          expires_in: 300,
        }),
        { status: 200 },
      );
    };
    const client = createOidcClient({
      issuer: "https://login.example.test",
      clientId: "askr-client",
      redirectUri: "https://app.example.test/auth/callback",
      fetch,
    });

    const exchanged = await client.exchangeCode({
      code: "code-1", state: "state-1",
      request: { state: "state-1", nonce: "nonce-1", codeVerifier: "test-verifier" },
    });
    expect(exchanged.principal).toMatchObject({ id: "user-1", nonce: "nonce-1" });
    expect(tokenInit?.method).toBe("POST");
    expect(tokenInit?.headers).toMatchObject({
      "content-type": "application/x-www-form-urlencoded",
    });
    const body = new URLSearchParams(String(tokenInit?.body));
    expect(Object.fromEntries(body)).toEqual({
      grant_type: "authorization_code",
      code: "code-1",
      redirect_uri: "https://app.example.test/auth/callback",
      client_id: "askr-client",
      code_verifier: "test-verifier",
    });
  });

  it("should give the expected result when require the authorization request nonce in the validated ID token", async () => {
    await expect(
      validateOidcIdToken(token({ ...validPayload, nonce: "nonce-1" }), {
        issuer: validPayload.iss,
        audience: validPayload.aud,
        nonce: "nonce-1",
        jwks,
        clock: () => now,
      }),
    ).resolves.toMatchObject({ id: "user-1", nonce: "nonce-1" });

    await expect(
      validateOidcIdToken(token({ ...validPayload, nonce: "wrong" }), {
        issuer: validPayload.iss,
        audience: validPayload.aud,
        nonce: "nonce-1",
        jwks,
        clock: () => now,
      }),
    ).rejects.toMatchObject({ code: "invalid_claim" });
  });

  it("should give the expected result when authenticate a confidential client at the token endpoint", async () => {
    let tokenInit: RequestInit | undefined;
    const fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith("openid-configuration")) {
        return new Response(JSON.stringify(oidcMetadata), { status: 200 });
      }
      if (String(input) === oidcMetadata.jwks_uri) return new Response(JSON.stringify(jwks));
      tokenInit = init;
      return new Response(JSON.stringify({ access_token: "access-1", token_type: "Bearer", id_token: token({ ...validPayload, iss: oidcMetadata.issuer, aud: "askr-client", nonce: "nonce-1", iat: Math.floor(Date.now() / 1000), nbf: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 300 }) }));
    };
    const client = createOidcClient({
      issuer: "https://login.example.test",
      clientId: "askr-client",
      clientSecret: "client-secret",
      redirectUri: "https://app.example.test/auth/callback",
      fetch,
    });

    await client.exchangeCode({ code: "code-1", state: "state-1", request: { state: "state-1", nonce: "nonce-1", codeVerifier: "test-verifier" } });
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

function token(
  payload: Record<string, unknown>,
  kid = "key-1",
  algorithm = "RS256",
  protectedHeader: Record<string, unknown> = {},
) {
  const header = base64url(
    JSON.stringify({ alg: algorithm, kid, typ: "JWT", ...protectedHeader }),
  );
  const body = base64url(JSON.stringify(payload));
  const input = `${header}.${body}`;
  const signature =
    algorithm === "none"
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
  it("should give the expected result when validate a signed RS256 access token and normalize its principal", async () => {
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

  it("should give the expected result when reject a token with an invalid signature", async () => {
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
  ])("should give the expected result when reject a token with an invalid %s claim", async (_name, change) => {
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

  it("should give the expected result when reject alg none and unknown key ids", async () => {
    const validator = createJwtValidator({ issuer: validPayload.iss, jwks, clock: () => now });
    await expect(validator.validate(token(validPayload, "key-1", "none"))).rejects.toMatchObject({
      code: "unsupported_algorithm",
    });
    await expect(validator.validate(token(validPayload, "rotated-key"))).rejects.toMatchObject({
      code: "unknown_key",
    });
  });

  it("should reject unsupported JOSE extensions and invalid typ profiles", async () => {
    const validator = createJwtValidator({
      issuer: validPayload.iss,
      jwks,
      clock: () => now,
      typ: ["at+jwt"],
    });
    await expect(
      validator.validate(token(validPayload, "key-1", "RS256", { crit: ["b64"] })),
    ).rejects.toMatchObject({ code: "unsupported_algorithm" });
    await expect(
      validator.validate(token(validPayload, "key-1", "RS256", { b64: false })),
    ).rejects.toMatchObject({ code: "unsupported_algorithm" });
    await expect(
      validator.validate(token(validPayload, "key-1", "RS256", { typ: null })),
    ).rejects.toMatchObject({
      code: "invalid_claim",
    });
    await expect(
      validator.validate(token(validPayload, "key-1", "RS256", { typ: "at+jwt" })),
    ).resolves.toHaveProperty("id", "user-1");
  });

  it("should validate JWT hardening options and required typ headers", async () => {
    for (const options of [
      { clockSkewSeconds: Number.NaN },
      { jwksRefreshCooldownSeconds: -1 },
      { unknownKeyCacheSeconds: Number.POSITIVE_INFINITY },
    ])
      expect(() =>
        createJwtValidator({ issuer: validPayload.iss, jwks, ...options }),
      ).toThrow(TypeError);

    const validator = createJwtValidator({
      issuer: validPayload.iss,
      jwks,
      clock: () => now,
      requireTyp: true,
    });
    await expect(
      validator.validate(token(validPayload, "key-1", "RS256", { typ: null })),
    ).rejects.toMatchObject({ code: "invalid_claim" });
    await expect(
      validator.validate(token(validPayload, "key-1", "RS256", { typ: "JWT" })),
    ).resolves.toHaveProperty("id", "user-1");
  });

  it("should singleflight and negatively cache unknown JWKS key refreshes", async () => {
    let calls = 0;
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const validator = createJwtValidator({
      issuer: validPayload.iss,
      jwks: async () => {
        calls += 1;
        if (calls > 1) await gate;
        return jwks;
      },
      clock: () => now,
      jwksRefreshCooldownSeconds: 0,
      unknownKeyCacheSeconds: 60,
    });
    await expect(validator.validate(token(validPayload))).resolves.toHaveProperty("id", "user-1");
    const forged = token(validPayload, "attacker-key");
    const attempts = [
      validator.validate(forged),
      validator.validate(forged),
      validator.validate(forged),
    ];
    release!();
    await Promise.all(attempts.map((attempt) => expect(attempt).rejects.toMatchObject({
      code: "unknown_key",
    })));
    expect(calls).toBe(2);
    await expect(validator.validate(forged)).rejects.toMatchObject({ code: "unknown_key" });
    expect(calls).toBe(2);
  });

  it("should not refresh JWKS after a known key produces an invalid signature", async () => {
    let calls = 0;
    const validator = createJwtValidator({
      issuer: validPayload.iss,
      jwks: async () => {
        calls += 1;
        return jwks;
      },
      clock: () => now,
    });
    const signed = token(validPayload).split(".");
    signed[2] = `${signed[2]![0] === "A" ? "B" : "A"}${signed[2]!.slice(1)}`;
    await expect(validator.validate(signed.join("."))).rejects.toMatchObject({
      code: "invalid_signature",
    });
    expect(calls).toBe(1);
  });

  it("should give the expected result when resolve a rotated key through a key provider", async () => {
    const validator = createJwtValidator({
      issuer: validPayload.iss,
      jwks: async () => jwks,
      clock: () => now,
    });
    await expect(validator.validate(token(validPayload, "key-1"))).resolves.toHaveProperty(
      "id",
      "user-1",
    );
  });

  it("should give the expected result when resolve a bearer access token into the shared auth context", async () => {
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

  it("should give the expected result when enrich a bearer principal through the configured principal store", async () => {
    const validator = createJwtValidator({ issuer: validPayload.iss, jwks, clock: () => now });
    const auth = createAuth({
      jwt: validator,
      principals: {
        get: async (subject) => ({
          id: subject,
          subject,
          roles: ["admin"],
          permissions: ["users:write"],
        }),
      },
    });
    const bearerRequest = new Request("https://api.example.test/users", {
      headers: { authorization: `Bearer ${token(validPayload)}` },
    });

    await expect(auth.resolve(bearerRequest)).resolves.toMatchObject({
      authenticated: true,
      principal: { id: "user-1", permissions: ["users:write"] },
    });
  });
});

describe("JWT issuer algorithms", () => {
  const issuerOptions = {
    kid: "issuer-key",
    issuer: validPayload.iss,
    audience: validPayload.aud,
    ttlSeconds: 300,
    clock: () => now,
  };

  it("should give the expected result when preserve RS256 issuance and validation", async () => {
    const privateKey = keyPair.privateKey.export({ format: "jwk" });
    const issuer = createJwtIssuer({ ...issuerOptions, privateKey });
    const issued = await issuer.issue({ subject: "rsa-user" });

    expect(JSON.parse(Buffer.from(issued.split(".")[0], "base64url").toString())).toMatchObject({
      alg: "RS256",
    });
    await expect(issuer.validator.validate(issued)).resolves.toMatchObject({ id: "rsa-user" });
  });

  it("should give the expected result when issue and validate ES256 with a Web Crypto P-256 key", async () => {
    const pair = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const privateKey = await crypto.subtle.exportKey("jwk", pair.privateKey);
    expect(privateKey.key_ops).toEqual(["sign"]);
    const issuer = createJwtIssuer({ ...issuerOptions, privateKey });
    const issued = await issuer.issue({ subject: "ec-user", roles: ["admin"] });

    expect(JSON.parse(Buffer.from(issued.split(".")[0], "base64url").toString())).toMatchObject({
      alg: "ES256",
    });
    expect(Buffer.from(issued.split(".")[2], "base64url")).toHaveLength(64);
    await expect(issuer.validator.validate(issued)).resolves.toMatchObject({
      id: "ec-user",
      roles: ["admin"],
    });
  });

  it("should give the expected result when validate ES256 from a public JWKS and reject an invalid signature", async () => {
    const ecPair = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const publicKey = ecPair.publicKey.export({ format: "jwk" });
    const header = base64url(JSON.stringify({ alg: "ES256", kid: "ec-key", typ: "JWT" }));
    const body = base64url(JSON.stringify(validPayload));
    const input = `${header}.${body}`;
    const signature = sign("SHA256", Buffer.from(input), {
      key: ecPair.privateKey,
      dsaEncoding: "ieee-p1363",
    }).toString("base64url");
    const validator = createJwtValidator({
      issuer: validPayload.iss,
      audience: validPayload.aud,
      jwks: { keys: [{ ...publicKey, kid: "ec-key" }] },
      clock: () => now,
    });

    await expect(validator.validate(`${input}.${signature}`)).resolves.toHaveProperty("id", "user-1");
    const invalid = `${input}.${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
    await expect(validator.validate(invalid)).rejects.toMatchObject({ code: "invalid_signature" });
  });

  it.each([
    ["RS256", { kty: "EC", crv: "P-256", x: "x", y: "y", kid: "mixed" }],
    ["ES256", { ...jwk, kid: "mixed" }],
  ])("should give the expected result when reject %s headers paired with a different key shape", async (alg, mixedKey) => {
    const validator = createJwtValidator({
      issuer: validPayload.iss,
      jwks: { keys: [mixedKey] },
      clock: () => now,
    });
    await expect(validator.validate(token(validPayload, "mixed", alg))).rejects.toMatchObject({
      code: "unsupported_algorithm",
    });
  });

  it("should give the expected result when reject unsupported curves and conflicting JWK algorithm metadata", async () => {
    expect(() =>
      createJwtIssuer({
        ...issuerOptions,
        privateKey: { kty: "EC", crv: "P-384", d: "d", x: "x", y: "y" },
      }),
    ).toThrow(TypeError);
    expect(() =>
      createJwtIssuer({
        ...issuerOptions,
        privateKey: { ...keyPair.privateKey.export({ format: "jwk" }), alg: "ES256" },
      }),
    ).toThrow(TypeError);

    const validator = createJwtValidator({
      issuer: validPayload.iss,
      jwks: { keys: [{ ...jwk, kid: "conflict", alg: "ES256" }] },
      clock: () => now,
    });
    await expect(validator.validate(token(validPayload, "conflict"))).rejects.toMatchObject({
      code: "unsupported_algorithm",
    });
  });
});

describe("Principal contract", () => {
  it("should give the expected result when describe identity, claims, roles, and permissions as one value", () => {
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

  it("should give the expected result when allow provider-specific claims without weakening the core contract", () => {
    const principal: Principal = { id: "user-1", organizationId: "org-1" };
    expect(principal.organizationId).toBe("org-1");
  });
});

const request = (url = "https://tenant.example.test/account") =>
  new Request(url, { headers: { cookie: "session=s-1" } });

describe("shared auth resolution", () => {
  it("should give the expected result when resolve anonymous requests with empty auth context", async () => {
    const auth = createAuth({ sessions: { get: async () => null } });
    await expect(auth.resolve(new Request("https://example.test/"))).resolves.toEqual({
      authenticated: false,
      principal: null,
      session: null,
      tenant: null,
    });
  });

  it("should give the expected result when resolve opaque browser sessions", async () => {
    const auth = createAuth({
      sessions: {
        get: async (id) =>
          id === "s-1" ? { id, subject: "user-1", expiresAt: Date.now() + 60_000 } : null,
      },
      principals: { get: async (subject) => ({ id: subject, roles: ["admin"] }) },
    });
    await expect(auth.resolve(request())).resolves.toMatchObject({
      authenticated: true,
      session: { id: "s-1", subject: "user-1" },
      principal: { id: "user-1", roles: ["admin"] },
    });
  });

  it("should give the expected result when resolve the configured tenant explicitly", async () => {
    const auth = createAuth({
      tenant: async (req) => new URL(req.url).hostname,
      sessions: { get: async () => null },
    });
    await expect(auth.resolve(request())).resolves.toMatchObject({ tenant: "tenant.example.test" });
  });

  it("should give the expected result when isolate auth state across concurrent requests", async () => {
    const auth = createAuth({
      sessions: { get: async (id) => ({ id, subject: id, expiresAt: Date.now() + 60_000 }) },
      principals: { get: async (subject) => ({ id: subject }) },
    });
    const [one, two] = await Promise.all([
      auth.resolve(request("https://one.example.test/")),
      auth.resolve(
        new Request("https://two.example.test/", { headers: { cookie: "session=s-2" } }),
      ),
    ]);
    expect(one.principal?.id).toBe("s-1");
    expect(two.principal?.id).toBe("s-2");
  });

  it("should give the expected result when evaluate shared requirements against one auth context", async () => {
    const context: AuthContext = {
      authenticated: true,
      principal: { id: "u", roles: ["admin"], permissions: ["users:read"] },
      session: null,
      tenant: "t",
      scopes: ["users:read"],
    };
    await expect(Promise.resolve(requireUser()(context))).resolves.toEqual({ allowed: true });
    await expect(Promise.resolve(requireRole("admin")(context))).resolves.toEqual({
      allowed: true,
    });
    await expect(Promise.resolve(requirePermission("users:read")(context))).resolves.toEqual({
      allowed: true,
    });
    await expect(Promise.resolve(requireScope("users:read")(context))).resolves.toEqual({
      allowed: true,
    });
  });

  it("should give the expected result when return unauthenticated given requireUser and anonymous context", async () => {
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

  it("should give the expected result when return already authenticated given requireAnonymous and a user", async () => {
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

  it("should give the expected result when return forbidden given an authenticated user without a role", async () => {
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

  it("should give the expected result when compose requirements with allOf and anyOf", async () => {
    const context: AuthContext = {
      authenticated: true,
      principal: { id: "user-1", roles: ["admin"] },
      session: null,
      tenant: null,
    };
    await expect(
      Promise.resolve(allOf(requireUser(), requireRole("admin"))(context)),
    ).resolves.toEqual({ allowed: true });
    await expect(
      Promise.resolve(anyOf(requirePermission("write"), requireRole("admin"))(context)),
    ).resolves.toEqual({ allowed: true });
  });
});
