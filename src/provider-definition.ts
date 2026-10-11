import { providerAuthorizationParams } from "./oidc-parameters";
import { configurationError } from "./provider-session-error";
import type {
  OidcProviderOptions,
  ProviderDefinition,
  ProviderCapabilities,
} from "./provider-session-types";
import type { Principal } from "./model";

export interface ProviderPolicy {
  readonly aliases: readonly string[];
  readonly version: string;
  readonly endpoints: NonNullable<OidcProviderOptions["endpoints"]>;
  readonly discoveryLogout: boolean;
  readonly discoveryRevocation: boolean;
  readonly authorizationResourceParameter: string;
  readonly validateClaims?: (claims: Principal) => void;
  readonly fingerprint: string;
}
const policies = new WeakMap<ProviderDefinition, ProviderPolicy>();
export function providerPolicy(provider: ProviderDefinition): ProviderPolicy {
  const policy = policies.get(provider);
  if (!policy) throw configurationError();
  return policy;
}
export function httpsEndpoint(value: string, issuer = false): string {
  try {
    const url = new URL(value);
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.hash ||
      (issuer && url.search)
    )
      throw new Error();
    return value;
  } catch {
    throw configurationError();
  }
}
export function scopeList(value: readonly string[]): readonly string[] {
  if (
    !Array.isArray(value) ||
    value.length > 64 ||
    Array.from(value).some(
      (s) => typeof s !== "string" || !/^[\x21\x23-\x5b\x5d-\x7e]{1,256}$/u.test(s),
    )
  )
    throw configurationError();
  return Object.freeze([...new Set(value)].sort());
}
export function resourceName(value: string): string {
  if (typeof value !== "string" || !value || value.length > 2048 || /\s/u.test(value))
    throw configurationError();
  return value;
}
export function defineProvider(
  options: OidcProviderOptions,
  policy: Omit<ProviderPolicy, "fingerprint" | "endpoints"> & {
    readonly endpoints?: ProviderPolicy["endpoints"];
  },
): ProviderDefinition {
  if (
    !options ||
    typeof options.id !== "string" ||
    !/^[a-z][a-z0-9-]{0,31}$/u.test(options.id) ||
    typeof options.clientId !== "string" ||
    !options.clientId ||
    options.clientId.length > 1024
  )
    throw configurationError();
  httpsEndpoint(options.issuer, true);
  const authentication = options.clientAuthentication;
  if (
    !authentication ||
    !["client_secret_post", "client_secret_basic"].includes(authentication.method) ||
    (typeof authentication.secret !== "function" &&
      (typeof authentication.secret !== "string" ||
        !authentication.secret ||
        authentication.secret.length > 8192))
  )
    throw configurationError();
  const responseMode = options.responseMode ?? "query";
  if (!["query", "form_post"].includes(responseMode)) throw configurationError();
  const identityScopes = scopeList(options.identityScopes ?? ["openid", "profile", "email"]);
  if (!identityScopes.includes("openid")) throw configurationError();
  const capabilities: ProviderCapabilities = {
    renewal: "none",
    incrementalConsent: false,
    providerLogout: false,
    revocation: false,
    resources: [],
    ...options.capabilities,
  };
  if (
    !Object.keys(capabilities).every((k) =>
      ["renewal", "incrementalConsent", "providerLogout", "revocation", "resources"].includes(k),
    ) ||
    !["refresh", "account-check", "none"].includes(capabilities.renewal) ||
    [capabilities.incrementalConsent, capabilities.providerLogout, capabilities.revocation].some(
      (v) => typeof v !== "boolean",
    ) ||
    !Array.isArray(capabilities.resources) ||
    capabilities.resources.length > 32
  )
    throw configurationError();
  const resources = Array.from(capabilities.resources, (r) => {
    if (!r || typeof r !== "object") throw configurationError();
    return Object.freeze({ resource: resourceName(r.resource), scopes: scopeList(r.scopes) });
  });
  if (new Set(resources.map((r) => r.resource)).size !== resources.length)
    throw configurationError();
  const endpoints = Object.freeze({ ...policy.endpoints, ...options.endpoints });
  for (const [name, value] of Object.entries(endpoints)) {
    if (!["authorization", "token", "jwks", "logout", "revocation"].includes(name))
      throw configurationError();
    httpsEndpoint(value);
  }
  if (
    (capabilities.providerLogout && !endpoints.logout && !policy.discoveryLogout) ||
    (capabilities.revocation && !endpoints.revocation && !policy.discoveryRevocation)
  )
    throw configurationError();
  let authorizationParams: Readonly<Record<string, string>>;
  try {
    authorizationParams = providerAuthorizationParams(options.authorizationParams);
  } catch {
    throw configurationError();
  }
  const definition = Object.freeze({
    id: options.id,
    issuer: options.issuer,
    clientId: options.clientId,
    clientAuthentication: Object.freeze({ ...authentication }),
    responseMode,
    identityScopes,
    capabilities: Object.freeze({ ...capabilities, resources: Object.freeze(resources) }),
    authorizationParams,
  }) as ProviderDefinition;
  const fingerprint = JSON.stringify([
    definition.id,
    definition.issuer,
    policy.aliases,
    definition.clientId,
    authentication.method,
    definition.responseMode,
    identityScopes,
    definition.capabilities,
    authorizationParams,
    endpoints,
    policy.version,
  ]);
  policies.set(definition, Object.freeze({ ...policy, endpoints, fingerprint }));
  return definition;
}
export function createOidcProvider(options: OidcProviderOptions): ProviderDefinition {
  if (!options || typeof options !== "object") throw configurationError();
  return defineProvider(options, {
    aliases: [options.issuer],
    version: "oidc-1",
    discoveryLogout: false,
    discoveryRevocation: false,
    authorizationResourceParameter: "resource",
  });
}
