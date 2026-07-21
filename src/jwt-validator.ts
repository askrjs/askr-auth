import { audienceMatches, claimTime, normalizePrincipal } from "./jwt-claims";
import { decodeBase64Url, decodeJson } from "./jwt-encoding";
import { JwtValidationError } from "./jwt-error";
import { resolveJwtAlgorithm } from "./jwt-algorithm";
import type { Principal } from "./model";
import type {
  JwtValidator,
  JwtValidatorOptions,
  JsonWebKeySet,
  OidcIdTokenOptions,
} from "./jwt-types";

export function createJwtValidator(options: JwtValidatorOptions): JwtValidator {
  const clock = options.clock ?? (() => Math.floor(Date.now() / 1000));
  const skew = options.clockSkewSeconds ?? 0;
  let cachedKeys: JsonWebKeySet | undefined;
  return {
    async validate(token) {
      const parts = token.split(".");
      if (parts.length !== 3 || !parts[0] || !parts[1])
        throw new JwtValidationError("malformed_token", "JWT must have three segments.");
      const header = decodeJson(parts[0]);
      const payload = decodeJson(parts[1]);
      if (header.alg !== "RS256" && header.alg !== "ES256")
        throw new JwtValidationError(
          "unsupported_algorithm",
          "Only RS256 and ES256 JWTs are accepted.",
        );
      if (typeof header.kid !== "string" || !header.kid)
        throw new JwtValidationError("unknown_key", "JWT kid header is required.");
      if (!cachedKeys) {
        const provider = options.jwks;
        cachedKeys = typeof provider === "function" ? await provider() : provider;
      }
      const key = cachedKeys.keys.find((candidate) => candidate.kid === header.kid);
      if (!key) throw new JwtValidationError("unknown_key", "JWT signing key was not found.");
      let algorithm;
      try {
        algorithm = resolveJwtAlgorithm(key);
      } catch {
        throw new JwtValidationError(
          "unsupported_algorithm",
          "JWT signing key uses an unsupported algorithm.",
        );
      }
      if (header.alg !== algorithm.jwt)
        throw new JwtValidationError(
          "unsupported_algorithm",
          "JWT header algorithm does not match its signing key.",
        );
      let valid = false;
      try {
        const imported = await globalThis.crypto.subtle.importKey(
          "jwk",
          key,
          algorithm.import,
          false,
          ["verify"],
        );
        valid = await globalThis.crypto.subtle.verify(
          algorithm.operation,
          imported,
          Uint8Array.from(decodeBase64Url(parts[2]), (char) => char.charCodeAt(0)),
          new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
        );
      } catch {
        valid = false;
      }
      if (!valid) throw new JwtValidationError("invalid_signature", "JWT signature is invalid.");
      if (payload.iss !== options.issuer)
        throw new JwtValidationError("invalid_claim", "JWT issuer is invalid.");
      if (options.audience !== undefined && !audienceMatches(payload.aud, options.audience))
        throw new JwtValidationError("invalid_claim", "JWT audience is invalid.");
      const current = clock();
      const exp = claimTime(payload.exp, "exp");
      const nbf = claimTime(payload.nbf, "nbf");
      const iat = claimTime(payload.iat, "iat");
      if (exp === undefined || current >= exp + skew)
        throw new JwtValidationError("invalid_claim", "JWT is expired.");
      if (nbf !== undefined && current + skew < nbf)
        throw new JwtValidationError("invalid_claim", "JWT is not active yet.");
      if (iat !== undefined && iat > current + skew)
        throw new JwtValidationError("invalid_claim", "JWT was issued in the future.");
      return normalizePrincipal(payload);
    },
  };
}

export async function validateOidcIdToken(
  token: string,
  options: OidcIdTokenOptions,
): Promise<Principal> {
  const { nonce, ...jwtOptions } = options;
  const principal = await createJwtValidator(jwtOptions).validate(token);
  if (principal.nonce !== nonce)
    throw new JwtValidationError("invalid_claim", "OIDC ID token nonce is invalid.");
  return principal;
}
