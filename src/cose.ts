import { decodeCbor } from "./cbor";
import { MfaValidationError } from "./mfa-error";

export type CoseAlgorithm = -7 | -257 | -8;
export interface DecodedCosePublicKey {
  algorithm: CoseAlgorithm;
  publicKeyJwk: JsonWebKey;
}

const bytes = (value: unknown, size?: number): Uint8Array => {
  if (!(value instanceof Uint8Array) || (size !== undefined && value.length !== size))
    throw new MfaValidationError("malformed-input", "COSE key member has an invalid shape.");
  return value;
};
const b64 = (value: Uint8Array) => btoa(String.fromCharCode(...value)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");

export function decodeCosePublicKey(input: Uint8Array): DecodedCosePublicKey {
  const value = decodeCbor(input);
  if (!(value instanceof Map)) throw new MfaValidationError("malformed-input", "COSE key must be a map.");
  const kty = value.get(1);
  const algorithm = value.get(3);
  if (algorithm === -7 && kty === 2 && value.get(-1) === 1) {
    return { algorithm, publicKeyJwk: { kty: "EC", crv: "P-256", x: b64(bytes(value.get(-2), 32)), y: b64(bytes(value.get(-3), 32)), alg: "ES256", ext: true } };
  }
  if (algorithm === -257 && kty === 3) {
    const n = bytes(value.get(-1));
    const e = bytes(value.get(-2));
    if (n.length < 256 || e.length < 3) throw new MfaValidationError("unsupported-algorithm", "RS256 keys must use RSA with at least 2048 bits.");
    return { algorithm, publicKeyJwk: { kty: "RSA", n: b64(n), e: b64(e), alg: "RS256", ext: true } };
  }
  if (algorithm === -8 && kty === 1 && value.get(-1) === 6) {
    return { algorithm, publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: b64(bytes(value.get(-2), 32)), alg: "EdDSA", ext: true } };
  }
  throw new MfaValidationError("unsupported-algorithm", "COSE key profile is unsupported.");
}
