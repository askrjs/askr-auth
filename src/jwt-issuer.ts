import { createJwtValidator } from "./jwt-validator";
import type { AskrJsonWebKey, JwtIssuer, JwtIssuerOptions } from "./jwt-types";

const reserved = new Set(["id", "sub", "iss", "aud", "iat", "exp", "jti", "nbf", "alg", "kid"]);
const bytes = (value: string) => new TextEncoder().encode(value);
const encodeBytes = (value: Uint8Array) =>
  btoa(String.fromCharCode(...value))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
const encodeBase64Url = (value: string) => encodeBytes(bytes(value));

export function createJwtIssuer(options: JwtIssuerOptions): JwtIssuer {
  if (!options.kid || !options.issuer || options.ttlSeconds <= 0)
    throw new TypeError("JWT issuer configuration is invalid.");
  const publicKey: AskrJsonWebKey = { ...options.privateKey };
  delete publicKey.d;
  delete publicKey.p;
  delete publicKey.q;
  delete publicKey.dp;
  delete publicKey.dq;
  delete publicKey.qi;
  publicKey.kid = options.kid;
  publicKey.alg = "RS256";
  publicKey.use = "sig";
  const validator = createJwtValidator({
    issuer: options.issuer,
    audience: options.audience,
    jwks: { keys: [publicKey] },
    clock: options.clock,
  });
  return {
    validator,
    async issue(input) {
      const { subject, id: _id, ...claims } = input;
      for (const key of Object.keys(claims))
        if (reserved.has(key)) throw new TypeError(`JWT claim ${key} is framework-owned.`);
      const now = (options.clock ?? (() => Math.floor(Date.now() / 1000)))();
      const header = encodeBase64Url(
        JSON.stringify({ alg: "RS256", typ: "JWT", kid: options.kid }),
      );
      const payload = encodeBase64Url(
        JSON.stringify({
          ...claims,
          sub: subject,
          iss: options.issuer,
          aud: options.audience,
          iat: now,
          exp: now + options.ttlSeconds,
          jti: crypto.randomUUID(),
        }),
      );
      const key = await crypto.subtle.importKey(
        "jwk",
        options.privateKey,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["sign"],
      );
      const signature = await crypto.subtle.sign(
        "RSASSA-PKCS1-v1_5",
        key,
        bytes(`${header}.${payload}`),
      );
      return `${header}.${payload}.${encodeBytes(new Uint8Array(signature))}`;
    },
  };
}
