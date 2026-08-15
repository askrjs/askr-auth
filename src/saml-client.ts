import { createMetadata } from "./saml-metadata";
import { createRequest } from "./saml-request";
import { validate } from "./saml-response";
import type { SamlServiceProvider, SamlServiceProviderOptions } from "./saml-types";

/** Create a SAML service provider for metadata, login requests, and response validation. @param options Service-provider configuration. @returns Configured SAML service provider. */
export function createSamlServiceProvider(
  options: SamlServiceProviderOptions,
): SamlServiceProvider {
  if (
    !options.entityId ||
    !options.acsUrl ||
    !options.idp.entityId ||
    !options.idp.ssoUrl ||
    !options.idp.certificates.length
  ) {
    throw new TypeError("SAML entity IDs, URLs, and at least one IdP certificate are required");
  }
  return {
    metadata: () => createMetadata(options),
    createAuthnRequest: (request) => createRequest(options, request?.relayState),
    validateResponse: (input) => validate(input, options),
  };
}
