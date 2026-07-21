import { describe, expect, it } from "vitest";
import {
  createTotpProvisioningUri,
  decodeCbor,
  decodeCborFirst,
  generateTotpSecret,
  verifyTotpCode,
  verifyWebAuthnAuthentication,
  verifyWebAuthnRegistration,
} from "../src/mfa";

const bytes = (value: string) => new TextEncoder().encode(value);
function cbor(value: unknown): Uint8Array {
  const prefix = (major: number, length: number) => length < 24 ? Uint8Array.of((major << 5) | length) : Uint8Array.of((major << 5) | 24, length);
  const join = (...parts: Uint8Array[]) => { const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0)); let offset = 0; for (const part of parts) { result.set(part, offset); offset += part.length; } return result; };
  if (typeof value === "number") return value >= 0 ? prefix(0, value) : prefix(1, -1 - value);
  if (typeof value === "string") { const encoded = bytes(value); return join(prefix(3, encoded.length), encoded); }
  if (value instanceof Uint8Array) return join(prefix(2, value.length), value);
  if (value instanceof Map) return join(prefix(5, value.size), ...Array.from(value).flatMap(([key, item]) => [cbor(key), cbor(item)]));
  throw new Error("unsupported test CBOR");
}
const fromB64 = (value: string) => Uint8Array.from(atob(value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=")), (char) => char.charCodeAt(0));

describe("TOTP", () => {
  it.each([
    ["SHA-1", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "94287082"],
    ["SHA-256", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA", "46119246"],
    ["SHA-512", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA", "90693936"],
  ] as const)("should give a valid RFC 6238 code when %s is selected", async (algorithm, secret, code) => {
    await expect(verifyTotpCode({ secret, code, algorithm, digits: 8, at: new Date(59_000), window: 0 })).resolves.toEqual({ valid: true, counter: 1, drift: 0 });
  });

  it("should give the matching counter and drift when a neighboring step is valid", async () => {
    await expect(verifyTotpCode({ secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", code: "94287082", digits: 8, at: new Date(89_000) })).resolves.toEqual({ valid: true, counter: 1, drift: -1 });
  });

  it("should give an encoded otpauth URI when issuer and account contain reserved characters", () => {
    const uri = createTotpProvisioningUri({ secret: "GEZDGNBVGY3TQOJQ", issuer: "Acme & Co", account: "a+b@example.com" });
    expect(uri).toBe("otpauth://totp/Acme%20%26%20Co:a%2Bb%40example.com?secret=GEZDGNBVGY3TQOJQ&issuer=Acme+%26+Co&algorithm=SHA1&digits=6&period=30");
  });

  it("should give at least 128 bits of entropy when a default secret is generated", () => {
    expect(generateTotpSecret()).toHaveLength(32);
  });

  it("should give malformed-input when a Base32 secret is invalid", async () => {
    await expect(verifyTotpCode({ secret: "not-a-secret!", code: "123456" })).rejects.toMatchObject({ code: "malformed-input" });
  });
});

describe("CBOR", () => {
  it("should give the decoded subset when a bounded value is valid", () => {
    expect(decodeCbor(Uint8Array.of(0xa2, 0x01, 0x42, 0xaa, 0xbb, 0x61, 0x61, 0x83, 0x01, 0xf5, 0xf6))).toEqual(new Map([[1, Uint8Array.of(0xaa, 0xbb)], ["a", [1, true, null]]]));
  });

  it("should give consumed bytes when the first CBOR item is requested", () => {
    expect(decodeCborFirst(Uint8Array.of(0x01, 0x02))).toEqual({ value: 1, bytesRead: 1 });
  });

  it.each([
    ["trailing data", Uint8Array.of(0x01, 0x02)],
    ["duplicate keys", Uint8Array.of(0xa2, 0x01, 0x01, 0x01, 0x02)],
    ["indefinite length", Uint8Array.of(0x9f, 0xff)],
    ["floating point", Uint8Array.of(0xf9, 0x00, 0x00)],
  ])("should give malformed-input when CBOR contains %s", (_label, input) => {
    expect(() => decodeCbor(input)).toThrow(expect.objectContaining({ code: "malformed-input" }));
  });
});

describe("WebAuthn", () => {
  it("should give a stored ES256 credential when none attestation is valid", async () => {
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, fromB64(jwk.x!)], [-3, fromB64(jwk.y!)]]));
    const rpId = "example.test"; const credentialId = Uint8Array.of(1, 2, 3); const challenge = Uint8Array.of(4, 5, 6);
    const authData = new Uint8Array(37 + 16 + 2 + credentialId.length + cose.length);
    authData.set(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes(rpId)))); authData[32] = 0x45;
    authData.set(credentialId, 55); authData[54] = credentialId.length; authData.set(cose, 55 + credentialId.length);
    const clientDataJSON = bytes(JSON.stringify({ type: "webauthn.create", challenge: "BAUG", origin: "https://example.test", crossOrigin: false }));
    const attestationObject = cbor(new Map([["fmt", "none"], ["authData", authData], ["attStmt", new Map()]]));
    await expect(verifyWebAuthnRegistration({ credentialId, clientDataJSON, attestationObject, expectedChallenge: challenge, allowedOrigins: ["https://example.test"], rpId })).resolves.toMatchObject({ credentialId, algorithm: -7, signCount: 0, backupEligible: false, backedUp: false });
  });

  it("should give the new counter when an ES256 assertion is valid", async () => {
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const publicKeyJwk = await crypto.subtle.exportKey("jwk", pair.publicKey); publicKeyJwk.alg = "ES256";
    const rpId = "example.test"; const credentialId = Uint8Array.of(1, 2, 3); const challenge = Uint8Array.of(4, 5, 6);
    const authenticatorData = new Uint8Array(37); authenticatorData.set(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes(rpId)))); authenticatorData[32] = 0x05; new DataView(authenticatorData.buffer).setUint32(33, 2);
    const clientDataJSON = bytes(JSON.stringify({ type: "webauthn.get", challenge: "BAUG", origin: "https://example.test" }));
    const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", clientDataJSON)); const signed = new Uint8Array(69); signed.set(authenticatorData); signed.set(hash, 37);
    const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, signed));
    await expect(verifyWebAuthnAuthentication({ credentialId, storedCredentialId: credentialId, publicKeyJwk, authenticatorData, clientDataJSON, signature, expectedChallenge: challenge, allowedOrigins: ["https://example.test"], rpId, signCount: 1 })).resolves.toEqual({ signCount: 2, backupEligible: false, backedUp: false });
  });
});
