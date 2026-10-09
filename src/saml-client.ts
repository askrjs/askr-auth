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
  for (const [name, seconds, positive] of [
    ["clockSkewSeconds", options.clockSkewSeconds ?? 60, false],
    ["maxAssertionAgeSeconds", options.maxAssertionAgeSeconds ?? 300, false],
    ["requestTtlSeconds", options.requestTtlSeconds ?? 600, true],
  ] as const) {
    if (
      !Number.isFinite(seconds) ||
      !Number.isFinite(seconds * 1000) ||
      seconds < 0 ||
      (positive && seconds === 0)
    )
      throw new TypeError(
        `SAML ${name} must be a finite ${positive ? "positive" : "non-negative"} number.`,
      );
  }
  const policy = {
    ...options,
    clock: () => {
      const time = (options.clock ?? Date.now)();
      if (!Number.isFinite(time) || !Number.isFinite(new Date(time).getTime()))
        throw new TypeError(
          "SAML clock must return finite Unix time in milliseconds within the Date range.",
        );
      return time;
    },
  };
  return {
    metadata: () => createMetadata(policy),
    createAuthnRequest: (request) => createRequest(policy, request?.relayState),
    validateResponse: (input) => validate(input, policy),
  };
}
