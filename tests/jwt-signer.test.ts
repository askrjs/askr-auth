import { afterEach, describe, expect, it, vi } from "vitest";
import { createJwtSigner, issueTimedJwt } from "../src/jwt";

const decode = (value: string) => JSON.parse(Buffer.from(value, "base64url").toString()) as Record<string, unknown>;

async function keyPair(kind: "RS256" | "ES256") {
  const pair = (await crypto.subtle.generateKey(
    kind === "RS256"
      ? { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }
      : { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  return {
    privateKey: await crypto.subtle.exportKey("jwk", pair.privateKey),
    publicKey: pair.publicKey,
    verification: kind === "RS256" ? { name: "RSASSA-PKCS1-v1_5" } : { name: "ECDSA", hash: "SHA-256" },
  };
}

afterEach(() => vi.restoreAllMocks());

describe("JWT signer", () => {
  it.each(["RS256", "ES256"] as const)("should sign arbitrary claims with %s", async (kind) => {
    const pair = await keyPair(kind);
    const token = await createJwtSigner({ privateKey: pair.privateKey, kid: "service-key" }).sign({
      protectedHeader: { typ: "service+jwt", purpose: "events" },
      claims: { realm: "auth", scope: ["events:write"] },
    });
    const [header, payload, signature] = token.split(".");
    expect(decode(header!)).toEqual({ typ: "service+jwt", purpose: "events", alg: kind, kid: "service-key" });
    expect(decode(payload!)).toEqual({ realm: "auth", scope: ["events:write"] });
    await expect(
      crypto.subtle.verify(pair.verification, pair.publicKey, Buffer.from(signature!, "base64url"), new TextEncoder().encode(`${header}.${payload}`)),
    ).resolves.toBe(true);
    const tampered = new TextEncoder().encode(`${header}.${payload}x`);
    await expect(
      crypto.subtle.verify(pair.verification, pair.publicKey, Buffer.from(signature!, "base64url"), tampered),
    ).resolves.toBe(false);
  });

  it.each(["alg", "kid", "crit", "b64"])("should reject protected header %s", async (name) => {
    const pair = await keyPair("ES256");
    const signer = createJwtSigner({ privateKey: pair.privateKey, kid: "key" });
    await expect(signer.sign({ claims: {}, protectedHeader: { [name]: "value" } })).rejects.toThrow(TypeError);
  });

  it("should issue exact timed claims while preserving array audiences and unique jti values", async () => {
    const pair = await keyPair("ES256");
    const signer = createJwtSigner({ privateKey: pair.privateKey, kid: "key" });
    const input = {
      issuer: "https://issuer.test",
      subject: "service-1",
      audience: ["fitz", "audit"] as const,
      ttlSeconds: 60,
      typ: "service+jwt",
      claims: { realm: "auth", scope: ["events:write"], nbf: 90 },
      clock: () => 100,
    };
    const first = await issueTimedJwt(signer, input);
    const second = await issueTimedJwt(signer, input);
    expect(decode(first.split(".")[0]!)).toEqual({ typ: "service+jwt", alg: "ES256", kid: "key" });
    expect(decode(first.split(".")[1]!)).toMatchObject({
      iss: "https://issuer.test", sub: "service-1", aud: ["fitz", "audit"], iat: 100,
      exp: 160, realm: "auth", scope: ["events:write"], nbf: 90,
    });
    expect(decode(first.split(".")[1]!).jti).not.toBe(decode(second.split(".")[1]!).jti);
  });

  it.each(["iss", "sub", "aud", "iat", "exp", "jti"])("should reject timed claim collision %s", async (name) => {
    const pair = await keyPair("ES256");
    const signer = createJwtSigner({ privateKey: pair.privateKey, kid: "key" });
    await expect(issueTimedJwt(signer, {
      issuer: "issuer", subject: "subject", audience: "audience", ttlSeconds: 1, typ: "type",
      claims: { [name]: "collision" },
    })).rejects.toThrow(TypeError);
  });
});
