import { defineProvider, scopeList } from "../provider-definition";
import { configurationError } from "../provider-session-error";
import type {
  ProviderCapabilities,
  ProviderClientAuthentication,
  ProviderDefinition,
} from "../provider-session-types";

/** Confidential Auth0 web-application configuration; app/session transport belongs to the shared engine. */
export interface Auth0ProviderOptions {
  readonly id: string;
  readonly domain: string;
  readonly clientId: string;
  readonly clientSecret: ProviderClientAuthentication["secret"];
  readonly identityScopes?: readonly ("openid" | "profile" | "email" | "offline_access")[];
  readonly resources?: ProviderCapabilities["resources"];
  /** Expected org_id; organization names cannot substitute for this identifier. */
  readonly organization?: string;
  /** Expected org_name, when returned; requires an explicit organization ID. */
  readonly organizationName?: string;
  readonly connection?: string;
}

const identityScopes = ["openid", "profile", "email", "offline_access"] as const;

/** Create an Auth0 definition using the shared signed OIDC/session engine. */
export function createAuth0Provider(options: Auth0ProviderOptions): ProviderDefinition {
  if (!options || typeof options !== "object" || Array.isArray(options)) throw configurationError();
  if (typeof options.domain !== "string" || options.domain.length > 253) throw configurationError();
  const domain = options.domain.toLowerCase();
  const labels = domain.split(".");
  if (
    labels.length < 2 ||
    labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label))
  )
    throw configurationError();
  if (
    options.organization !== undefined &&
    (typeof options.organization !== "string" ||
      !/^org_[A-Za-z0-9]{1,128}$/u.test(options.organization))
  )
    throw configurationError();
  if (
    options.organizationName !== undefined &&
    (options.organization === undefined ||
      typeof options.organizationName !== "string" ||
      !/^[a-z0-9][a-z0-9_-]{0,49}$/u.test(options.organizationName))
  )
    throw configurationError();
  if (
    options.connection !== undefined &&
    (typeof options.connection !== "string" || !/^[\x20-\x7e]{1,128}$/u.test(options.connection))
  )
    throw configurationError();
  const scopes = scopeList(options.identityScopes ?? identityScopes);
  if (scopes.some((scope) => !identityScopes.some((allowed) => allowed === scope)))
    throw configurationError();
  const issuer = `https://${domain}/`;
  const organization = options.organization;
  const organizationName = options.organizationName;
  return defineProvider(
    {
      id: options.id,
      issuer,
      clientId: options.clientId,
      clientAuthentication: { method: "client_secret_post", secret: options.clientSecret },
      identityScopes: scopes,
      authorizationParams: {
        ...(organization === undefined ? {} : { organization }),
        ...(options.connection === undefined ? {} : { connection: options.connection }),
      },
      capabilities: {
        renewal: "refresh",
        incrementalConsent: true,
        providerLogout: true,
        revocation: true,
        resources: options.resources ?? [],
      },
    },
    {
      aliases: [issuer],
      version: JSON.stringify(["auth0-1", organization ?? null, organizationName ?? null]),
      discoveryLogout: false,
      discoveryRevocation: false,
      endpoints: { logout: `${issuer}oidc/logout`, revocation: `${issuer}oauth/revoke` },
      authorizationResourceParameter: "audience",
      validateClaims(principal) {
        if (organization === undefined) {
          if (principal.org_id !== undefined || principal.org_name !== undefined) throw new Error();
        } else if (
          principal.org_id !== organization ||
          (principal.org_name !== undefined && principal.org_name !== organizationName)
        )
          throw new Error();
      },
    },
  );
}
