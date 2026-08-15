import type { Principal } from "./model";

/** JSON Web Key with the metadata used by Askr token validation. */
export interface AskrJsonWebKey extends JsonWebKey {
  /** Key identifier advertised by the issuer. */
  kid?: string;
  /** JOSE algorithm identifier. */
  alg?: string;
  /** Intended key use, such as signing. */
  use?: string;
}
/** Set of public keys used to validate JWT signatures. */
export interface JsonWebKeySet {
  /** Public keys indexed by their JOSE metadata. */
  keys: readonly AskrJsonWebKey[];
}
/** Static or asynchronously refreshed JSON Web Key provider. */
export type JwksProvider = JsonWebKeySet | (() => JsonWebKeySet | PromiseLike<JsonWebKeySet>);
/** Validation policy for signed JWTs. */
export interface JwtValidatorOptions {
  /** Expected issuer claim. */
  issuer: string;
  /** Expected audience claim or accepted audience values. */
  audience?: string | readonly string[];
  /** Public keys used to verify signatures. */
  jwks: JwksProvider;
  /** Clock returning Unix time in seconds. */
  clock?: () => number;
  /** Allowed clock skew in seconds. */
  clockSkewSeconds?: number;
  /** Require a protected typ value and restrict it to these values. */
  typ?: string | readonly string[];
  /** Require a non-empty protected typ value without restricting its value. */
  requireTyp?: boolean;
  /** Minimum interval between refreshes after an unknown key. */
  jwksRefreshCooldownSeconds?: number;
  /** Duration for caching unknown-key failures. */
  unknownKeyCacheSeconds?: number;
}
/** OIDC-specific JWT validation options. */
export interface OidcIdTokenOptions extends JwtValidatorOptions {
  /** Expected OIDC nonce claim. */
  nonce: string;
}
/** Stable failure codes returned by JWT validation. */
export type JwtValidationErrorCode =
  | "malformed_token"
  | "unsupported_algorithm"
  | "unknown_key"
  | "invalid_signature"
  | "invalid_claim";
/** Verifies a JWT and returns its typed principal claims. */
export interface JwtValidator<P extends Principal = Principal> {
  /** Validate a compact JWT. @param token Compact serialized JWT. @returns Validated principal claims. */
  validate(token: string): Promise<P>;
}
/** Configuration for issuing signed JWTs. */
export interface JwtIssuerOptions {
  /** Private signing key. */
  privateKey: JsonWebKey;
  /** JOSE key identifier. */
  kid: string;
  /** Issuer claim. */
  issuer: string;
  /** Audience claim or claims. */
  audience: string | readonly string[];
  /** Token lifetime in seconds. */
  ttlSeconds: number;
  /** Clock returning Unix time in seconds. */
  clock?: () => number;
}
/** Principal claims and subject used to issue a JWT. */
export interface JwtIssueInput extends Omit<Principal, "id" | "subject"> {
  /** Subject claim to encode. */
  subject: string;
}
/** JWT issuer and its matching validator. */
export interface JwtIssuer<P extends Principal = Principal> {
  /** Issue a compact JWT. @param principal Subject and claims to encode. @returns Compact serialized JWT. */
  issue(principal: JwtIssueInput): Promise<string>;
  /** Validator configured with this issuer's public-key policy. */
  readonly validator: JwtValidator<P>;
}
