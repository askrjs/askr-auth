import { decodeCbor, decodeCborFirst } from "./cbor";
import { decodeCosePublicKey, type CoseAlgorithm } from "./cose";
import { MfaValidationError, type MfaValidationErrorCode } from "./mfa-error";

export interface WebAuthnRegistrationInput {
  credentialId: Uint8Array;
  clientDataJSON: Uint8Array;
  attestationObject: Uint8Array;
  expectedChallenge: Uint8Array;
  allowedOrigins: readonly string[];
  rpId: string;
  requireUserVerification?: boolean;
}
export interface WebAuthnAuthenticationInput {
  credentialId: Uint8Array;
  storedCredentialId: Uint8Array;
  publicKeyJwk: JsonWebKey;
  authenticatorData: Uint8Array;
  clientDataJSON: Uint8Array;
  signature: Uint8Array;
  expectedChallenge: Uint8Array;
  allowedOrigins: readonly string[];
  rpId: string;
  signCount: number;
  requireUserVerification?: boolean;
}
export interface WebAuthnRegistrationResult {
  credentialId: Uint8Array; publicKeyJwk: JsonWebKey; algorithm: CoseAlgorithm; signCount: number;
  aaguid: Uint8Array; backupEligible: boolean; backedUp: boolean;
}

const fail = (code: MfaValidationErrorCode, message: string): never => { throw new MfaValidationError(code, message); };
const equal = (left: Uint8Array, right: Uint8Array) => left.length === right.length && left.every((value, index) => value === right[index]);
const sha256 = async (value: Uint8Array | string) => new Uint8Array(await crypto.subtle.digest("SHA-256", typeof value === "string" ? new TextEncoder().encode(value) : new Uint8Array(value)));
function base64url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/u.test(value) || value.length % 4 === 1) fail("malformed-input", "Client data contains invalid base64url.");
  let binary: string;
  try { binary = atob(value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=")); }
  catch { return fail("malformed-input", "Client data contains invalid base64url."); }
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  const canonical = btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
  if (canonical !== value) fail("malformed-input", "Client data contains non-canonical base64url.");
  return bytes;
}
function clientData(input: Uint8Array, type: string, challenge: Uint8Array, origins: readonly string[]) {
  let value: unknown;
  try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(input)); } catch { fail("malformed-input", "Client data JSON is invalid."); }
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("malformed-input", "Client data must be an object.");
  const data = value as Record<string, unknown>;
  if (data.type !== type) fail("malformed-input", "Client data type is invalid.");
  if (typeof data.challenge !== "string" || !equal(base64url(data.challenge), challenge)) fail("invalid-challenge", "WebAuthn challenge does not match.");
  if (typeof data.origin !== "string" || !origins.includes(data.origin)) fail("invalid-origin", "WebAuthn origin is not allowed.");
  if (data.crossOrigin === true || (data.crossOrigin !== undefined && data.crossOrigin !== false)) fail("invalid-origin", "Cross-origin WebAuthn ceremonies are not allowed.");
}
interface AuthData { flags: number; signCount: number; backupEligible: boolean; backedUp: boolean; aaguid?: Uint8Array; credentialId?: Uint8Array; cose?: Uint8Array }
async function parseAuthData(input: Uint8Array, rpId: string, uv: boolean, registration: boolean): Promise<AuthData> {
  if (input.length < 37) fail("malformed-input", "Authenticator data is truncated.");
  if (!equal(input.subarray(0, 32), await sha256(rpId))) fail("invalid-rp-id", "RP ID hash does not match.");
  const flags = input[32];
  if (flags & 0x22) fail("malformed-input", "Authenticator data uses reserved flags.");
  if (!(flags & 1)) fail("user-presence-required", "User presence is required.");
  if (uv && !(flags & 4)) fail("user-verification-required", "User verification is required.");
  const backupEligible = Boolean(flags & 8), backedUp = Boolean(flags & 16);
  if (backedUp && !backupEligible) fail("malformed-input", "Backup state requires backup eligibility.");
  const signCount = new DataView(input.buffer, input.byteOffset + 33, 4).getUint32(0);
  let offset = 37; const result: AuthData = { flags, signCount, backupEligible, backedUp };
  if (registration) {
    if (!(flags & 64) || input.length < 55) fail("malformed-input", "Attested credential data is required.");
    result.aaguid = input.slice(offset, offset + 16); offset += 16;
    const length = new DataView(input.buffer, input.byteOffset + offset, 2).getUint16(0); offset += 2;
    if (!length || offset + length > input.length) fail("malformed-input", "Credential ID is invalid.");
    result.credentialId = input.slice(offset, offset + length); offset += length;
    const decoded = decodeCborFirst(input.subarray(offset)); result.cose = input.slice(offset, offset + decoded.bytesRead); offset += decoded.bytesRead;
  } else if (flags & 64) fail("malformed-input", "Authentication data unexpectedly contains attested credential data.");
  if (flags & 128) { const extension = decodeCborFirst(input.subarray(offset)); offset += extension.bytesRead; }
  if (offset !== input.length) fail("malformed-input", "Authenticator data contains trailing bytes.");
  return result;
}
function algorithmFor(key: JsonWebKey): { import: AlgorithmIdentifier | EcKeyImportParams | RsaHashedImportParams; verify: AlgorithmIdentifier | EcdsaParams } {
  if (key.kty === "EC" && key.crv === "P-256" && key.alg === "ES256") return { import: { name: "ECDSA", namedCurve: "P-256" }, verify: { name: "ECDSA", hash: "SHA-256" } };
  if (key.kty === "RSA" && key.alg === "RS256" && typeof key.n === "string" && base64url(key.n).length >= 256) return { import: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, verify: { name: "RSASSA-PKCS1-v1_5" } };
  if (key.kty === "OKP" && key.crv === "Ed25519" && key.alg === "EdDSA") return { import: { name: "Ed25519" }, verify: { name: "Ed25519" } };
  return fail("unsupported-algorithm", "Stored public key profile is unsupported.");
}
async function verify(key: JsonWebKey, signature: Uint8Array, data: Uint8Array) {
  const algorithm = algorithmFor(key);
  try {
    const imported = await crypto.subtle.importKey("jwk", key, algorithm.import, false, ["verify"]);
    const normalized = key.kty === "EC" ? derEcdsa(signature) : signature;
    return await crypto.subtle.verify(algorithm.verify, imported, new Uint8Array(normalized), new Uint8Array(data));
  } catch { return false; }
}

function derEcdsa(signature: Uint8Array): Uint8Array {
  if (signature.length === 64) return signature;
  if (signature.length < 8 || signature[0] !== 0x30 || signature[1] !== signature.length - 2 || signature[2] !== 0x02) fail("malformed-input", "ECDSA signature is not strict DER.");
  const rLength = signature[3]; const rStart = 4; const sMarker = rStart + rLength;
  if (rLength < 1 || sMarker + 2 > signature.length || signature[sMarker] !== 0x02) fail("malformed-input", "ECDSA signature is not strict DER.");
  const sLength = signature[sMarker + 1]; const sStart = sMarker + 2;
  if (sLength < 1 || sStart + sLength !== signature.length) fail("malformed-input", "ECDSA signature is not strict DER.");
  const integer = (start: number, length: number) => {
    const part = signature.subarray(start, start + length);
    if ((part[0] & 0x80) || (part.length > 1 && part[0] === 0 && !(part[1] & 0x80))) fail("malformed-input", "ECDSA signature integer is not minimally encoded.");
    const unsigned = part[0] === 0 ? part.subarray(1) : part;
    if (unsigned.length > 32) fail("malformed-input", "ECDSA signature integer is too large.");
    const output = new Uint8Array(32); output.set(unsigned, 32 - unsigned.length); return output;
  };
  const output = new Uint8Array(64); output.set(integer(rStart, rLength)); output.set(integer(sStart, sLength), 32); return output;
}

export async function verifyWebAuthnRegistration(input: WebAuthnRegistrationInput): Promise<WebAuthnRegistrationResult> {
  clientData(input.clientDataJSON, "webauthn.create", input.expectedChallenge, input.allowedOrigins);
  const decodedObject = decodeCbor(input.attestationObject);
  if (!(decodedObject instanceof Map) || typeof decodedObject.get("fmt") !== "string" || !(decodedObject.get("authData") instanceof Uint8Array) || !(decodedObject.get("attStmt") instanceof Map)) fail("malformed-input", "Attestation object is invalid.");
  const object = decodedObject as Map<unknown, unknown>;
  const authBytes = object.get("authData") as Uint8Array;
  const auth = await parseAuthData(authBytes, input.rpId, input.requireUserVerification ?? true, true);
  if (!equal(auth.credentialId!, input.credentialId)) fail("credential-mismatch", "Credential ID does not match attested data.");
  const decoded = decodeCosePublicKey(auth.cose!); const statement = object.get("attStmt") as Map<unknown, unknown>;
  const format = object.get("fmt");
  if (format === "none") { if (statement.size) fail("invalid-attestation", "None attestation must have an empty statement."); }
  else if (format === "packed") {
    if (statement.has("x5c") || statement.get("alg") !== decoded.algorithm || !(statement.get("sig") instanceof Uint8Array)) fail("invalid-attestation", "Only packed self-attestation is accepted.");
    const signed = new Uint8Array(authBytes.length + 32); signed.set(authBytes); signed.set(await sha256(input.clientDataJSON), authBytes.length);
    if (!(await verify(decoded.publicKeyJwk, statement.get("sig") as Uint8Array, signed))) fail("invalid-attestation", "Packed self-attestation signature is invalid.");
  } else fail("invalid-attestation", "Attestation format is unsupported.");
  return { credentialId: auth.credentialId!, publicKeyJwk: decoded.publicKeyJwk, algorithm: decoded.algorithm, signCount: auth.signCount, aaguid: auth.aaguid!, backupEligible: auth.backupEligible, backedUp: auth.backedUp };
}

export async function verifyWebAuthnAuthentication(input: WebAuthnAuthenticationInput): Promise<{ signCount: number; backupEligible: boolean; backedUp: boolean }> {
  if (!equal(input.credentialId, input.storedCredentialId)) fail("credential-mismatch", "Credential ID does not match stored credential.");
  clientData(input.clientDataJSON, "webauthn.get", input.expectedChallenge, input.allowedOrigins);
  const auth = await parseAuthData(input.authenticatorData, input.rpId, input.requireUserVerification ?? true, false);
  if (input.signCount && auth.signCount && auth.signCount <= input.signCount) fail("counter-rollback", "Authenticator counter did not increase.");
  const signed = new Uint8Array(input.authenticatorData.length + 32); signed.set(input.authenticatorData); signed.set(await sha256(input.clientDataJSON), input.authenticatorData.length);
  if (!(await verify(input.publicKeyJwk, input.signature, signed))) fail("invalid-signature", "Assertion signature is invalid.");
  return { signCount: auth.signCount, backupEligible: auth.backupEligible, backedUp: auth.backedUp };
}
