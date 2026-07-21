import { createMetadata } from "./saml-metadata";
import { createRequest } from "./saml-request";
import { validate } from "./saml-response";
import type { SamlServiceProvider, SamlServiceProviderOptions } from "./saml-types";

export function createSamlServiceProvider(options: SamlServiceProviderOptions): SamlServiceProvider {
  if (!options.entityId || !options.acsUrl || !options.idp.entityId || !options.idp.ssoUrl || !options.idp.certificates.length) {
    throw new TypeError("SAML entity IDs, URLs, and at least one IdP certificate are required");
  }
  return {
    metadata: () => createMetadata(options),
    createAuthnRequest: (request) => createRequest(options, request?.relayState),
    validateResponse: (input) => validate(input, options),
  };
}
