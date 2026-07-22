import { afterEach, describe, expect, it, vi } from "vitest";
import { createPasskey, decodeBase64Url, encodeBase64Url, getPasskeyAssertion } from "../src/webauthn-client";

const buffer = (...values: number[]) => new Uint8Array(values).buffer;
const encoded = (...values: number[]) => encodeBase64Url(buffer(...values));

afterEach(() => vi.unstubAllGlobals());

describe("WebAuthn client", () => {
  it("should round-trip canonical base64url", () => {
    expect(new Uint8Array(decodeBase64Url(encoded(0, 255, 126)))).toEqual(new Uint8Array([0, 255, 126]));
  });

  it.each(["=", "AA==", "A", "a b", "é"])("should reject malformed base64url %s", (value) => {
    expect(() => decodeBase64Url(value)).toThrow(TypeError);
  });

  it("should create a discoverable passkey with secure defaults and server-aligned output", async () => {
    const create = vi.fn(async () => ({
      type: "public-key", rawId: buffer(1, 2),
      response: { clientDataJSON: buffer(3), attestationObject: buffer(4) },
    }));
    vi.stubGlobal("navigator", { credentials: { create } });
    await expect(createPasskey({
      challenge: encoded(9), rpId: "example.test", rpName: "Example", userId: encoded(8),
      userName: "ada", userDisplayName: "Ada",
    })).resolves.toEqual({ credentialId: encoded(1, 2), clientDataJSON: encoded(3), attestationObject: encoded(4) });
    expect(create).toHaveBeenCalledWith({ publicKey: {
      challenge: buffer(9), rp: { id: "example.test", name: "Example" },
      user: { id: buffer(8), name: "ada", displayName: "Ada" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -8 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
      attestation: "none",
    } });
  });

  it.each([undefined, []] as const)("should omit allowCredentials for discoverable authentication", async (allowCredentials) => {
    const get = vi.fn(async () => ({
      type: "public-key", rawId: buffer(1),
      response: { clientDataJSON: buffer(2), authenticatorData: buffer(3), signature: buffer(4) },
    }));
    vi.stubGlobal("navigator", { credentials: { get } });
    await expect(getPasskeyAssertion({ challenge: encoded(9), rpId: "example.test", allowCredentials })).resolves.toEqual({
      credentialId: encoded(1), clientDataJSON: encoded(2), authenticatorData: encoded(3), signature: encoded(4),
    });
    expect(get.mock.calls[0]![0].publicKey).not.toHaveProperty("allowCredentials");
    expect(get.mock.calls[0]![0].publicKey.userVerification).toBe("required");
  });

  it("should decode an authentication allow list", async () => {
    const get = vi.fn(async () => ({ type: "public-key", rawId: buffer(1), response: {
      clientDataJSON: buffer(2), authenticatorData: buffer(3), signature: buffer(4),
    } }));
    vi.stubGlobal("navigator", { credentials: { get } });
    await getPasskeyAssertion({ challenge: encoded(9), rpId: "example.test", allowCredentials: [encoded(5)] });
    expect(get.mock.calls[0]![0].publicKey.allowCredentials).toEqual([{ type: "public-key", id: buffer(5) }]);
  });

  it("should reject unavailable APIs and invalid credential shapes with TypeError", async () => {
    vi.stubGlobal("navigator", {});
    await expect(getPasskeyAssertion({ challenge: encoded(9), rpId: "example.test" })).rejects.toThrow(TypeError);
    vi.stubGlobal("navigator", { credentials: { get: async () => ({ type: "password" }) } });
    await expect(getPasskeyAssertion({ challenge: encoded(9), rpId: "example.test" })).rejects.toThrow(TypeError);
  });

  it("should preserve native DOMException rejections", async () => {
    const error = new DOMException("cancelled", "NotAllowedError");
    vi.stubGlobal("navigator", { credentials: { create: async () => { throw error; } } });
    await expect(createPasskey({
      challenge: encoded(9), rpId: "example.test", rpName: "Example", userId: encoded(8),
      userName: "ada", userDisplayName: "Ada",
    })).rejects.toBe(error);
  });
});
