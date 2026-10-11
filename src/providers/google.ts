import { defineProvider } from "../provider-definition";
import { configurationError } from "../provider-session-error";
import type {
  ProviderCapabilities,
  ProviderClientAuthentication,
  ProviderDefinition,
} from "../provider-session-types";

export interface GoogleProviderOptions {
  readonly id: string;
  readonly clientId: string;
  readonly clientSecret: ProviderClientAuthentication["secret"];
  readonly identityScopes?: readonly ("openid" | "profile" | "email")[];
  readonly resources?: ProviderCapabilities["resources"];
  readonly hostedDomain?: string;
}
const issuer = "https://accounts.google.com";
const identityScopes = ["openid", "profile", "email"] as const;
/** Confidential Google Web OAuth, exact signed hosted-domain policy, and explicit API grants. */
export function createGoogleProvider(options: GoogleProviderOptions): ProviderDefinition {
  if (!options || typeof options !== "object" || Array.isArray(options)) throw configurationError();
  const hostedDomain = options.hostedDomain;
  if (
    hostedDomain !== undefined &&
    (typeof hostedDomain !== "string" ||
      hostedDomain.length > 253 ||
      !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/u.test(
        hostedDomain,
      ))
  )
    throw configurationError();
  const provider = defineProvider(
    {
      id: options.id,
      issuer,
      clientId: options.clientId,
      clientAuthentication: { method: "client_secret_post", secret: options.clientSecret },
      identityScopes: options.identityScopes ?? identityScopes,
      capabilities: {
        renewal: "refresh",
        incrementalConsent: true,
        providerLogout: false,
        revocation: true,
        resources: options.resources ?? [],
      },
      authorizationParams: {
        access_type: "offline",
        include_granted_scopes: "true",
        ...(hostedDomain === undefined ? {} : { hd: hostedDomain }),
      },
    },
    {
      aliases: [issuer, "accounts.google.com"],
      version: JSON.stringify(["google-1", hostedDomain ?? null]),
      endpoints: {
        authorization: "https://accounts.google.com/o/oauth2/v2/auth",
        token: "https://oauth2.googleapis.com/token",
        jwks: "https://www.googleapis.com/oauth2/v3/certs",
        revocation: "https://oauth2.googleapis.com/revoke",
      },
      discoveryLogout: false,
      discoveryRevocation: false,
      authorizationResourceParameter: null,
      tokenScopePolicy: "google",
      validateClaims(principal) {
        if (hostedDomain !== undefined && principal.hd !== hostedDomain) throw new Error();
      },
    },
  );
  if (provider.identityScopes.some((scope) => !identityScopes.some((allowed) => allowed === scope)))
    throw configurationError();
  return provider;
}
