import { createJwtValidator } from "./jwt-validator";
import { JwtValidationError } from "./jwt-error";
import type { JwtValidatorOptions } from "./jwt-types";
import type { Principal } from "./model";

/** OIDC-specific JWT validation options. */
export interface OidcIdTokenOptions extends JwtValidatorOptions {
  /** OIDC has one relying-party client ID, rather than an audience allow-list. */
  audience: string;
  /** Expected OIDC nonce claim. */
  nonce: string;
}
/** Validate an OIDC ID token, including its nonce claim. @param token Compact serialized ID token. @param options OIDC validation policy. @returns Validated principal claims. */
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
  // This client configures trust for one client ID; it has no additional-audience trust policy.
  if (Array.isArray(audience) && audience.some((value) => value !== options.audience))
    throw new JwtValidationError(
      "invalid_claim",
      "OIDC ID token has an untrusted additional audience.",
    );
  if (
    ((Array.isArray(audience) && audience.length > 1) || payload.azp !== undefined) &&
    payload.azp !== options.audience
  )
    throw new JwtValidationError("invalid_claim", "OIDC ID token authorized party is invalid.");
  return principal;
}
