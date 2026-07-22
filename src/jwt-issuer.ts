import { createJwtValidator } from "./jwt-validator";
import { createJwtSigner, issueTimedJwt } from "./jwt-signer";
import { resolveJwtAlgorithm } from "./jwt-algorithm";
import type { AskrJsonWebKey, JwtIssuer, JwtIssuerOptions } from "./jwt-types";

const reserved = new Set(["id", "sub", "iss", "aud", "iat", "exp", "jti", "nbf", "alg", "kid"]);
export function createJwtIssuer(options: JwtIssuerOptions): JwtIssuer {
  if (!options.kid || !options.issuer || options.ttlSeconds <= 0)
    throw new TypeError("JWT issuer configuration is invalid.");
  const signer = createJwtSigner({ privateKey: options.privateKey, kid: options.kid });
  const algorithm = resolveJwtAlgorithm(options.privateKey);
  const publicKey: AskrJsonWebKey = { ...options.privateKey };
  delete publicKey.d;
  delete publicKey.p;
  delete publicKey.q;
  delete publicKey.dp;
  delete publicKey.dq;
  delete publicKey.qi;
  delete publicKey.oth;
  publicKey.key_ops = ["verify"];
  publicKey.kid = options.kid;
  publicKey.alg = algorithm.jwt;
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
      return issueTimedJwt(signer, {
        issuer: options.issuer,
        subject,
        audience: options.audience,
        ttlSeconds: options.ttlSeconds,
        typ: "JWT",
        claims,
        clock: options.clock,
      });
    },
  };
}
