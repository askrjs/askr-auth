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
  return validateIdentityToken(token, options, true);
}

/** Private server renewal validation keeps code-exchange nonce requirements unchanged. */
export async function validateOidcRefreshIdToken(
  token: string,
  options: OidcIdTokenOptions & { subject: string },
): Promise<Principal> {
  const principal = await validateIdentityToken(token, options, false);
  if (principal.subject !== options.subject)
    throw new JwtValidationError("invalid_claim", "OIDC refreshed account is invalid.");
  return principal;
}

async function validateIdentityToken(
  token: string,
  options: OidcIdTokenOptions,
  requireNonce: boolean,
): Promise<Principal> {
  const { nonce, ...jwtOptions } = options;
  const principal = await createJwtValidator(jwtOptions).validate(token);
  if ((requireNonce || principal.nonce !== undefined) && principal.nonce !== nonce)
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
