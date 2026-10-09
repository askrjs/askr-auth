import { generateKeyPairSync, createHmac, createPrivateKey, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createAuth } from "../src";
import { createJwtSigner, createJwtValidator, issueTimedJwt } from "../src/jwt";
import { verifyTotpCode, verifyWebAuthnAuthentication } from "../src/mfa";

const now = 1_700_000_000;
const issuer = "https://issuer.example.test";
const pairs = [0, 1].map(() => generateKeyPairSync("rsa", { modulusLength: 2048 }));
const jwks = (index: number) => ({
  keys: [
    { ...pairs[index]!.publicKey.export({ format: "jwk" }), kid: `key-${index}`, alg: "RS256" },
  ],
});
function token(claims: Record<string, unknown> = {}, index = 0) {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: `key-${index}` })).toString(
    "base64url",
  );
  const body = Buffer.from(
    JSON.stringify({ iss: issuer, sub: "user", exp: now + 60, ...claims }),
  ).toString("base64url");
  const input = `${header}.${body}`;
  return `${input}.${sign("RSA-SHA256", Buffer.from(input), pairs[index]!.privateKey).toString("base64url")}`;
}

describe("JWT clocks and key rotation", () => {
  it.each([NaN, Infinity, -Infinity])(
    "propagates an invalid session clock %s and recovers",
    async (invalid) => {
      let current = invalid;
      const auth = createAuth({
        clock: () => current,
        sessions: { get: () => ({ id: "session", subject: "user", expiresAt: 100 }) },
      });
      const request = new Request("https://app.test", { headers: { cookie: "session=session" } });
      await expect(auth.resolve(request)).rejects.toThrow(TypeError);
      current = 100;
      await expect(auth.resolve(request)).resolves.toHaveProperty("authenticated", false);
      current = 99;
      await expect(auth.resolve(request)).resolves.toHaveProperty("authenticated", true);
    },
  );

  it("does not commit keys when the clock fails during an asynchronous refresh", async () => {
    let current = now;
    let calls = 0;
    const validator = createJwtValidator({
      issuer,
      clock: () => current,
      jwks: async () => {
        calls++;
        if (calls === 1) current = NaN;
        return jwks(0);
      },
    });
    await expect(validator.validate(token())).rejects.toThrow(TypeError);
    current = now;
    await expect(validator.validate(token())).resolves.toHaveProperty("id", "user");
    expect(calls).toBe(2);
  });
  it("uses the last duplicate JSON claim consistently with the ECMAScript parser", async () => {
    const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "key-0" })).toString(
      "base64url",
    );
    const compact = (expirations: string) => {
      const body = Buffer.from(`{"iss":"${issuer}","sub":"user",${expirations}}`).toString(
        "base64url",
      );
      const input = `${header}.${body}`;
      return `${input}.${sign("RSA-SHA256", Buffer.from(input), pairs[0]!.privateKey).toString("base64url")}`;
    };
    const validator = createJwtValidator({ issuer, jwks: jwks(0), clock: () => now });
    await expect(
      validator.validate(compact(`"exp":${now - 1},"exp":${now + 60}`)),
    ).resolves.toHaveProperty("id", "user");
    await expect(
      validator.validate(compact(`"exp":${now + 60},"exp":${now - 1}`)),
    ).rejects.toMatchObject({ code: "invalid_claim" });
  });

  it("retries a negatively cached key exactly when its TTL expires", async () => {
    let current = now;
    let published = 0;
    let calls = 0;
    const validator = createJwtValidator({
      issuer,
      clock: () => current,
      jwksRefreshCooldownSeconds: 5,
      unknownKeyCacheSeconds: 30,
      jwks: async () => {
        calls++;
        return jwks(published);
      },
    });
    await validator.validate(token());
    current += 5;
    await expect(validator.validate(token({}, 1))).rejects.toMatchObject({ code: "unknown_key" });
    published = 1;
    current += 29;
    await expect(validator.validate(token({}, 1))).rejects.toMatchObject({ code: "unknown_key" });
    expect(calls).toBe(2);
    current += 1;
    await expect(validator.validate(token({}, 1))).resolves.toHaveProperty("id", "user");
    expect(calls).toBe(3);
  });
  it.each([NaN, Infinity, -Infinity])(
    "rejects invalid clock %s and recovers on the next call",
    async (invalid) => {
      let clock = invalid;
      const validator = createJwtValidator({ issuer, jwks: jwks(0), clock: () => clock });
      await expect(validator.validate(token({ exp: now - 1 }))).rejects.toThrow(TypeError);
      clock = now;
      await expect(validator.validate(token({ exp: now - 1 }))).rejects.toMatchObject({
        code: "invalid_claim",
      });
      await expect(validator.validate(token())).resolves.toHaveProperty("id", "user");
    },
  );

  it.each([NaN, Infinity, -Infinity, Number.MAX_VALUE])(
    "rejects an unrepresentable issued lifetime at %s",
    async (clock) => {
      const signer = createJwtSigner({
        privateKey: pairs[0]!.privateKey.export({ format: "jwk" }),
        kid: "key-0",
      });
      await expect(
        issueTimedJwt(signer, {
          issuer,
          subject: "user",
          audience: "api",
          typ: "JWT",
          ttlSeconds: 60,
          clock: () => clock,
        }),
      ).rejects.toThrow(TypeError);
    },
  );

  it.each([
    { claims: { exp: now }, skew: 0, valid: false },
    { claims: { exp: now + 0.5 }, skew: 0, valid: true },
    { claims: { exp: now - 5 }, skew: 5, valid: false },
    { claims: { exp: now - 4.5 }, skew: 5, valid: true },
    { claims: { nbf: now + 5, iat: now + 5 }, skew: 5, valid: true },
    { claims: { nbf: now + 5.5 }, skew: 5, valid: false },
    { claims: { iat: now + 5.5 }, skew: 5, valid: false },
    { claims: { exp: String(now + 60) }, skew: 0, valid: false },
    { claims: { nbf: null }, skew: 0, valid: false },
  ])("enforces time boundary $claims with skew $skew", async ({ claims, skew, valid }) => {
    const result = createJwtValidator({
      issuer,
      jwks: jwks(0),
      clock: () => now,
      clockSkewSeconds: skew,
    }).validate(token(claims));
    if (valid) await expect(result).resolves.toHaveProperty("id", "user");
    else await expect(result).rejects.toMatchObject({ code: "invalid_claim" });
  });

  it("shares one refresh when concurrent requests encounter a genuinely rotated signing key", async () => {
    let current = now;
    let calls = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const validator = createJwtValidator({
      issuer,
      clock: () => current,
      jwksRefreshCooldownSeconds: 5,
      jwks: async () => {
        calls++;
        if (calls > 1) await gate;
        return jwks(calls === 1 ? 0 : 1);
      },
    });
    await expect(validator.validate(token())).resolves.toHaveProperty("id", "user");
    current += 5;
    const requests = Array.from({ length: 12 }, () => validator.validate(token({}, 1)));
    release();
    const principals = await Promise.all(requests);
    expect(principals.map((principal) => principal.id)).toEqual(Array(12).fill("user"));
    expect(calls).toBe(2);
    await expect(validator.validate(token({}, 1))).resolves.toHaveProperty("id", "user");
    expect(calls).toBe(2);
  });

  it("propagates a failed refresh and retries without poisoning the cached key", async () => {
    const unavailable = new Error("JWKS unavailable");
    let current = now;
    let calls = 0;
    const validator = createJwtValidator({
      issuer,
      clock: () => current,
      jwksRefreshCooldownSeconds: 5,
      jwks: async () => {
        calls++;
        if (calls === 2) throw unavailable;
        return jwks(calls === 1 ? 0 : 1);
      },
    });
    await validator.validate(token());
    current += 5;
    await expect(validator.validate(token({}, 1))).rejects.toBe(unavailable);
    await expect(validator.validate(token())).resolves.toHaveProperty("id", "user");
    await expect(validator.validate(token({}, 1))).resolves.toHaveProperty("id", "user");
    expect(calls).toBe(3);
  });
});

const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
function hotp(counter: bigint): string {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(counter);
  const digest = createHmac("sha1", "12345678901234567890").update(bytes).digest();
  const offset = digest[digest.length - 1]! & 15;
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}
describe("TOTP timestamp boundaries", () => {
  it.each([NaN, Infinity, -Infinity, -1, new Date(NaN), Number.MAX_VALUE])(
    "gives malformed-input for invalid time %s",
    async (at) => {
      await expect(verifyTotpCode({ secret, code: "000000", at })).rejects.toMatchObject({
        code: "malformed-input",
      });
    },
  );
  it("does not wrap a pre-epoch drift step into the maximum unsigned counter", async () => {
    await expect(
      verifyTotpCode({ secret, code: hotp(0xffffffffffffffffn), at: 0, window: 1 }),
    ).resolves.toEqual({ valid: false });
    await expect(verifyTotpCode({ secret, code: hotp(0n), at: 0, window: 1 })).resolves.toEqual({
      valid: true,
      counter: 0,
      drift: 0,
    });
  });
  it("accepts the next period exactly at its boundary and returns replay ownership to the caller", async () => {
    const code = hotp(2n);
    await expect(verifyTotpCode({ secret, code, at: 59_999, window: 0 })).resolves.toEqual({
      valid: false,
    });
    for (let attempt = 0; attempt < 2; attempt++)
      await expect(verifyTotpCode({ secret, code, at: 60_000, window: 0 })).resolves.toEqual({
        valid: true,
        counter: 2,
        drift: 0,
      });
  });
});

const bytes = (value: string) => new TextEncoder().encode(value);
async function assertion(
  overrides: {
    origin?: string;
    challenge?: string;
    crossOrigin?: boolean;
    flags?: number;
    type?: string;
    rpId?: string;
    der?: boolean;
  } = {},
) {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const publicKeyJwk = { ...(await crypto.subtle.exportKey("jwk", pair.publicKey)), alg: "ES256" };
  const authenticatorData = new Uint8Array(37);
  authenticatorData.set(
    new Uint8Array(await crypto.subtle.digest("SHA-256", bytes(overrides.rpId ?? "example.test"))),
  );
  authenticatorData[32] = overrides.flags ?? 5;
  new DataView(authenticatorData.buffer).setUint32(33, 2);
  const clientDataJSON = bytes(
    JSON.stringify({
      type: overrides.type ?? "webauthn.get",
      challenge: overrides.challenge ?? "BAUG",
      origin: overrides.origin ?? "https://example.test",
      crossOrigin: overrides.crossOrigin ?? false,
    }),
  );
  const signed = new Uint8Array(69);
  signed.set(authenticatorData);
  signed.set(new Uint8Array(await crypto.subtle.digest("SHA-256", clientDataJSON)), 37);
  const signature = overrides.der
    ? new Uint8Array(
        sign(
          "sha256",
          signed,
          createPrivateKey({
            key: await crypto.subtle.exportKey("jwk", pair.privateKey),
            format: "jwk",
          }),
        ),
      )
    : new Uint8Array(
        await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, signed),
      );
  return {
    credentialId: Uint8Array.of(1, 2, 3),
    storedCredentialId: Uint8Array.of(1, 2, 3),
    publicKeyJwk,
    authenticatorData,
    clientDataJSON,
    signature,
    expectedChallenge: Uint8Array.of(4, 5, 6),
    allowedOrigins: ["https://example.test"],
    rpId: "example.test",
    signCount: 1,
  };
}
describe("WebAuthn signed assertion bindings", () => {
  it("accepts an independent DER ECDSA signature and rejects a truncated encoding", async () => {
    const valid = await assertion({ der: true });
    expect(valid.signature[0]).toBe(0x30);
    await expect(verifyWebAuthnAuthentication(valid)).resolves.toHaveProperty("signCount", 2);
    await expect(
      verifyWebAuthnAuthentication({ ...valid, signature: valid.signature.slice(0, 20) }),
    ).rejects.toMatchObject({ code: "invalid-signature" });
  });
  it.each([
    { overrides: { origin: "https://evil.test" }, code: "invalid-origin" },
    { overrides: { challenge: "AQID" }, code: "invalid-challenge" },
    { overrides: { crossOrigin: true }, code: "invalid-origin" },
    { overrides: { rpId: "evil.test" }, code: "invalid-rp-id" },
    { overrides: { flags: 4 }, code: "user-presence-required" },
    { overrides: { flags: 1 }, code: "user-verification-required" },
    { overrides: { flags: 0x15 }, code: "malformed-input" },
    { overrides: { type: "webauthn.create" }, code: "malformed-input" },
  ])("rejects signed assertion $overrides with $code", async ({ overrides, code }) => {
    await expect(verifyWebAuthnAuthentication(await assertion(overrides))).rejects.toMatchObject({
      code,
    });
  });
  it("rejects credential substitution and signature tampering, then accepts the original", async () => {
    const valid = await assertion();
    await expect(
      verifyWebAuthnAuthentication({ ...valid, storedCredentialId: Uint8Array.of(9) }),
    ).rejects.toMatchObject({ code: "credential-mismatch" });
    const corrupt = valid.signature.slice();
    corrupt[0] = corrupt[0]! ^ 1;
    await expect(
      verifyWebAuthnAuthentication({ ...valid, signature: corrupt }),
    ).rejects.toMatchObject({ code: "invalid-signature" });
    await expect(verifyWebAuthnAuthentication(valid)).resolves.toEqual({
      signCount: 2,
      backupEligible: false,
      backedUp: false,
    });
  });
});
