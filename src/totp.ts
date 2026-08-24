import { MfaValidationError } from "./mfa-error";

/** Hash algorithms supported by TOTP. */
export type TotpAlgorithm = "SHA-1" | "SHA-256" | "SHA-512";
/** Shared TOTP generation and verification settings. */
export interface TotpOptions {
  /** HMAC hash algorithm. Defaults to SHA-1. */
  algorithm?: TotpAlgorithm;
  /** Number of digits in generated codes. */
  digits?: 6 | 8;
  /** Validity period in seconds. */
  periodSeconds?: number;
}
/** Input required to verify one TOTP code. */
export interface VerifyTotpOptions extends TotpOptions {
  /** Base32-encoded shared secret. */
  secret: string;
  /** User-entered one-time code. */
  code: string;
  /** Verification time; defaults to the current time. */
  at?: number | Date;
  /** Number of adjacent periods accepted on either side. */
  window?: number;
}

/** Result of verifying a TOTP code. */
export type TotpVerificationResult =
  | {
      valid: true;
      /**
       * Accepted moving counter. The application must atomically reject an already-consumed
       * counter and persist a newly accepted counter to provide replay protection.
       */
      counter: number;
      /** Matched offset from the current counter; useful for application-owned clock-drift policy. */
      drift: number;
    }
  | { valid: false; counter?: never; drift?: never };

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function decodeSecret(secret: string): Uint8Array {
  const normalized = secret.toUpperCase().replace(/=+$/u, "");
  if (!normalized || !/^[A-Z2-7]+$/u.test(normalized))
    throw new MfaValidationError("malformed-input", "TOTP secret is not valid Base32.");
  let bits = 0,
    value = 0;
  const output: number[] = [];
  for (const char of normalized) {
    value = value * 32 + alphabet.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      output.push((value >>> bits) & 255);
      value &= (1 << bits) - 1;
    }
  }
  if (bits && value !== 0)
    throw new MfaValidationError("malformed-input", "TOTP secret has non-zero padding bits.");
  return Uint8Array.from(output);
}
function encodeSecret(input: Uint8Array): string {
  let bits = 0,
    value = 0,
    result = "";
  for (const byte of input) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      result += alphabet[(value >>> bits) & 31];
    }
    value &= (1 << bits) - 1;
  }
  if (bits) result += alphabet[(value << (5 - bits)) & 31];
  return result;
}
function parameters(options: TotpOptions) {
  const algorithm = options.algorithm ?? "SHA-1";
  const digits = options.digits ?? 6;
  const period = options.periodSeconds ?? 30;
  if (
    !["SHA-1", "SHA-256", "SHA-512"].includes(algorithm) ||
    ![6, 8].includes(digits) ||
    !Number.isInteger(period) ||
    period <= 0
  )
    throw new MfaValidationError("malformed-input", "TOTP parameters are invalid.");
  return { algorithm, digits, period };
}
async function codeAt(
  secret: Uint8Array,
  counter: number,
  algorithm: TotpAlgorithm,
  digits: number,
) {
  const input = new Uint8Array(8);
  new DataView(input.buffer).setBigUint64(0, BigInt(counter));
  const key = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(secret),
    { name: "HMAC", hash: algorithm },
    false,
    ["sign"],
  );
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, input));
  const offset = digest.at(-1)! & 15;
  const value =
    (((digest[offset] & 127) << 24) |
      (digest[offset + 1] << 16) |
      (digest[offset + 2] << 8) |
      digest[offset + 3]) %
    10 ** digits;
  return String(value).padStart(digits, "0");
}

/** Generate a cryptographically random Base32 TOTP secret. @param options Secret byte length, from 16 through 128. @returns Base32-encoded secret. */
export function generateTotpSecret(options: { byteLength?: number } = {}): string {
  const length = options.byteLength ?? 20;
  if (!Number.isInteger(length) || length < 16 || length > 128)
    throw new MfaValidationError(
      "malformed-input",
      "TOTP secret length must be between 16 and 128 bytes.",
    );
  return encodeSecret(crypto.getRandomValues(new Uint8Array(length)));
}

/** Build an `otpauth://` URI for authenticator enrollment. @param input Secret, issuer, account, and TOTP settings. @returns Authenticator provisioning URI. */
export function createTotpProvisioningUri(
  input: { secret: string; issuer: string; account: string } & TotpOptions,
): string {
  decodeSecret(input.secret);
  const { algorithm, digits, period } = parameters(input);
  if (!input.issuer || !input.account)
    throw new MfaValidationError("malformed-input", "TOTP issuer and account are required.");
  const url = new URL(
    `otpauth://totp/${encodeURIComponent(input.issuer)}:${encodeURIComponent(input.account)}`,
  );
  url.searchParams.set("secret", input.secret.toUpperCase().replace(/=+$/u, ""));
  url.searchParams.set("issuer", input.issuer);
  url.searchParams.set("algorithm", algorithm.replace("-", ""));
  url.searchParams.set("digits", String(digits));
  url.searchParams.set("period", String(period));
  return url.toString();
}

/**
 * Verify a TOTP code with a bounded clock-drift window.
 *
 * The window is scanned from `-window` through `+window`. If the same code matches more than one
 * counter, the last match wins, so the greatest drift is returned.
 *
 * A valid cryptographic result alone does not prevent replay. The caller must atomically consume
 * and persist the returned `counter` before granting access:
 *
 * ```ts
 * const result = await verifyTotpCode({ secret, code });
 * if (result.valid && await counters.consume(result.counter)) grantAccess();
 * ```
 *
 * @param input Verification input and settings.
 * @returns The validation result and matched counter/drift when valid.
 */
export async function verifyTotpCode(input: VerifyTotpOptions): Promise<TotpVerificationResult> {
  const secret = decodeSecret(input.secret);
  const { algorithm, digits, period } = parameters(input);
  if (!new RegExp(`^\\d{${digits}}$`, "u").test(input.code))
    throw new MfaValidationError("malformed-input", "TOTP code has an invalid shape.");
  const window = input.window ?? 1;
  if (!Number.isInteger(window) || window < 0 || window > 10)
    throw new MfaValidationError("malformed-input", "TOTP window is invalid.");
  const timestamp = input.at instanceof Date ? input.at.getTime() : (input.at ?? Date.now());
  const counter = Math.floor(timestamp / 1000 / period);
  let matched: { counter: number; drift: number } | undefined;
  for (let drift = -window; drift <= window; drift++) {
    const candidate = await codeAt(secret, counter + drift, algorithm, digits);
    let difference = 0;
    for (let i = 0; i < digits; i++)
      difference |= candidate.charCodeAt(i) ^ input.code.charCodeAt(i);
    if (difference === 0) matched = { counter: counter + drift, drift: drift === 0 ? 0 : drift };
  }
  return matched ? { valid: true, ...matched } : { valid: false };
}
