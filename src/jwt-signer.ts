import { resolveJwtAlgorithm } from "./jwt-algorithm";
import type { AskrJsonWebKey } from "./jwt-types";

/** Private-key configuration for a JWT signer. */
export interface JwtSignerOptions {
  /** Private signing key in Web Crypto JWK form. */
  readonly privateKey: JsonWebKey;
  /** JOSE key identifier included in protected headers. */
  readonly kid: string;
}

/** Claims and optional protected headers for one JWT. */
export interface JwtSignInput {
  /** Payload claims to encode. */
  readonly claims: Readonly<Record<string, unknown>>;
  /** Additional protected headers; `alg` and `kid` are managed by Askr. */
  readonly protectedHeader?: Readonly<Record<string, unknown>>;
}

/** Signs JWT payloads with a configured private key. */
export interface JwtSigner {
  /** Sign claims with the configured key. @param input Claims and headers to sign. @returns Compact serialized JWT. */
  sign(input: JwtSignInput): Promise<string>;
}

/** Standard claims used to issue a short-lived JWT. */
export interface TimedJwtInput {
  /** Issuer claim. */
  readonly issuer: string;
  /** Subject claim. */
  readonly subject: string;
  /** Audience claim or claims. */
  readonly audience: string | readonly string[];
  /** Lifetime in seconds. */
  readonly ttlSeconds: number;
  /** Protected JOSE type header. */
  readonly typ: string;
  /** Additional application claims. */
  readonly claims?: Readonly<Record<string, unknown>>;
  /** Clock returning Unix time in seconds. */
  readonly clock?: () => number;
}

const bytes = (value: string) => new TextEncoder().encode(value);
const encodeBytes = (value: Uint8Array) =>
  btoa(String.fromCharCode(...value))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
const encodeJson = (value: unknown) => encodeBytes(bytes(JSON.stringify(value)));
const ownedHeaders = new Set(["alg", "kid"]);
const unsupportedHeaders = new Set(["crit", "b64"]);
const timedClaims = new Set(["iss", "sub", "aud", "iat", "exp", "jti"]);

/** Create a signer that enforces Askr-owned JWT headers. @param options Signer key configuration. @returns A JWT signer. */
export function createJwtSigner(options: JwtSignerOptions): JwtSigner {
  if (!options.kid) throw new TypeError("JWT signer requires a non-empty kid.");
  const algorithm = resolveJwtAlgorithm(options.privateKey as AskrJsonWebKey);
  const imported = crypto.subtle.importKey("jwk", options.privateKey, algorithm.import, false, [
    "sign",
  ]);
  return Object.freeze({
    async sign(input: JwtSignInput): Promise<string> {
      const protectedHeader = input.protectedHeader ?? {};
      for (const key of Object.keys(protectedHeader)) {
        if (ownedHeaders.has(key)) throw new TypeError(`JWT header ${key} is framework-owned.`);
        if (unsupportedHeaders.has(key)) throw new TypeError(`JWT header ${key} is unsupported.`);
      }
      const header = encodeJson({ ...protectedHeader, alg: algorithm.jwt, kid: options.kid });
      const payload = encodeJson(input.claims);
      const signature = await crypto.subtle.sign(
        algorithm.operation,
        await imported,
        bytes(`${header}.${payload}`),
      );
      return `${header}.${payload}.${encodeBytes(new Uint8Array(signature))}`;
    },
  });
}

/** Issue a JWT with validated time, issuer, subject, and audience claims. @param signer JWT signer. @param input Timed token claims. @returns Compact serialized JWT. */
export async function issueTimedJwt(signer: JwtSigner, input: TimedJwtInput): Promise<string> {
  if (!input.issuer || !input.subject || !input.typ)
    throw new TypeError("Timed JWT issuer, subject, and typ must be non-empty.");
  if (
    (typeof input.audience === "string" && !input.audience) ||
    (Array.isArray(input.audience) && input.audience.length === 0)
  )
    throw new TypeError("Timed JWT audience must be non-empty.");
  if (!Number.isSafeInteger(input.ttlSeconds) || input.ttlSeconds <= 0)
    throw new TypeError("Timed JWT TTL must be a positive integer.");
  for (const key of Object.keys(input.claims ?? {}))
    if (timedClaims.has(key)) throw new TypeError(`JWT claim ${key} is framework-owned.`);
  const now = (input.clock ?? (() => Math.floor(Date.now() / 1000)))();
  return signer.sign({
    protectedHeader: { typ: input.typ },
    claims: {
      ...input.claims,
      iss: input.issuer,
      sub: input.subject,
      aud: input.audience,
      iat: now,
      exp: now + input.ttlSeconds,
      jti: crypto.randomUUID(),
    },
  });
}
