import { resolveJwtAlgorithm } from "./jwt-algorithm";
import type { AskrJsonWebKey } from "./jwt-types";

export interface JwtSignerOptions {
  readonly privateKey: JsonWebKey;
  readonly kid: string;
}

export interface JwtSignInput {
  readonly claims: Readonly<Record<string, unknown>>;
  readonly protectedHeader?: Readonly<Record<string, unknown>>;
}

export interface JwtSigner {
  sign(input: JwtSignInput): Promise<string>;
}

export interface TimedJwtInput {
  readonly issuer: string;
  readonly subject: string;
  readonly audience: string | readonly string[];
  readonly ttlSeconds: number;
  readonly typ: string;
  readonly claims?: Readonly<Record<string, unknown>>;
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

export function createJwtSigner(options: JwtSignerOptions): JwtSigner {
  if (!options.kid) throw new TypeError("JWT signer requires a non-empty kid.");
  const algorithm = resolveJwtAlgorithm(options.privateKey as AskrJsonWebKey);
  const imported = crypto.subtle.importKey(
    "jwk",
    options.privateKey,
    algorithm.import,
    false,
    ["sign"],
  );
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
