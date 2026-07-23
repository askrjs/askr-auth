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
  if (!Number.isFinite(skew) || skew < 0)
    throw new TypeError("JWT clockSkewSeconds must be a non-negative number.");
  const refreshCooldown = options.jwksRefreshCooldownSeconds ?? 30;
  const negativeTtl = options.unknownKeyCacheSeconds ?? 30;
  if (!Number.isFinite(refreshCooldown) || refreshCooldown < 0)
    throw new TypeError("JWT jwksRefreshCooldownSeconds must be non-negative.");
  if (!Number.isFinite(negativeTtl) || negativeTtl < 0)
    throw new TypeError("JWT unknownKeyCacheSeconds must be non-negative.");
  let cachedKeys: JsonWebKeySet | undefined;
  let refreshPromise: Promise<JsonWebKeySet> | undefined;
  let lastRefresh = Number.NEGATIVE_INFINITY;
  const unknownKeys = new Map<string, number>();
  const provider = options.jwks;
  const refresh = async (): Promise<JsonWebKeySet> => {
    if (typeof provider !== "function") return provider;
    if (!refreshPromise) {
      refreshPromise = Promise.resolve(provider()).finally(() => {
        refreshPromise = undefined;
      });
    }
    const keys = await refreshPromise;
    cachedKeys = keys;
    lastRefresh = clock();
    return keys;
  };
  return {
    async validate(token) {
      if (token.length > 65_536)
        throw new JwtValidationError("malformed_token", "JWT exceeds the 64 KiB size limit.");
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
      if (header.crit !== undefined || header.b64 !== undefined)
        throw new JwtValidationError(
          "unsupported_algorithm",
          "JWT crit and b64 protected headers are not supported.",
        );
      const allowedTypes =
        typeof options.typ === "string" ? [options.typ] : options.typ;
      if (
        (options.requireTyp || allowedTypes) &&
        (typeof header.typ !== "string" ||
          !header.typ ||
          (allowedTypes !== undefined && !allowedTypes.includes(header.typ)))
      )
        throw new JwtValidationError("invalid_claim", "JWT typ header is invalid.");
      if (typeof header.kid !== "string" || !header.kid)
        throw new JwtValidationError("unknown_key", "JWT kid header is required.");
      if (!cachedKeys) {
        cachedKeys = typeof provider === "function" ? await provider() : provider;
      }
      let key = cachedKeys.keys.find((candidate) => candidate.kid === header.kid);
      if (!key && typeof options.jwks === "function") {
        const current = clock();
        const negativeUntil = unknownKeys.get(header.kid) ?? Number.NEGATIVE_INFINITY;
        if (current >= negativeUntil && current - lastRefresh >= refreshCooldown) {
          cachedKeys = await refresh();
          key = cachedKeys.keys.find((candidate) => candidate.kid === header.kid);
          if (!key) unknownKeys.set(header.kid, current + negativeTtl);
        }
      }
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
      const verifyWith = async (candidate: typeof key, operation: typeof algorithm) => {
        try {
          const imported = await globalThis.crypto.subtle.importKey("jwk", candidate, operation.import, false, ["verify"]);
          return await globalThis.crypto.subtle.verify(operation.operation, imported, Uint8Array.from(decodeBase64Url(parts[2]), (char) => char.charCodeAt(0)), new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
        } catch { return false; }
      };
      const valid = await verifyWith(key, algorithm);
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
  const payload = principal as Record<string, unknown>;
  const audience = payload.aud;
  if (Array.isArray(audience) && audience.length > 1 && payload.azp !== options.audience)
    throw new JwtValidationError("invalid_claim", "OIDC ID token authorized party is invalid.");
  return principal;
}
