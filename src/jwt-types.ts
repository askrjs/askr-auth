import type { Principal } from "./model";

export interface AskrJsonWebKey extends JsonWebKey { kid?: string; alg?: string; use?: string; }
export interface JsonWebKeySet { keys: readonly AskrJsonWebKey[]; }
export type JwksProvider = JsonWebKeySet | (() => JsonWebKeySet | PromiseLike<JsonWebKeySet>);
export interface JwtValidatorOptions {
  issuer: string; audience?: string | readonly string[]; jwks: JwksProvider;
  clock?: () => number; clockSkewSeconds?: number;
}
export interface OidcIdTokenOptions extends JwtValidatorOptions { nonce: string; }
export type JwtValidationErrorCode = "malformed_token" | "unsupported_algorithm" | "unknown_key" | "invalid_signature" | "invalid_claim";
export interface JwtValidator<P extends Principal = Principal> { validate(token: string): Promise<P>; }
