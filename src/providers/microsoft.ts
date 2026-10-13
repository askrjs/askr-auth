import { defineProvider } from "../provider-definition";
import { configurationError } from "../provider-session-error";
import type {
  ProviderCapabilities,
  ProviderClientAuthentication,
  ProviderDefinition,
} from "../provider-session-types";

interface MicrosoftProviderOptions {
  readonly id: string;
  readonly tenantId: string;
  readonly clientId: string;
  readonly clientSecret: ProviderClientAuthentication["secret"];
  readonly identityScopes?: readonly ("openid" | "profile" | "email" | "offline_access")[];
  readonly resources?: ProviderCapabilities["resources"];
}
const identityScopes = ["openid", "profile", "email", "offline_access"] as const;
/** One explicit Entra tenant, confidential Web credentials, and qualified delegated API scopes. */
function createMicrosoftProvider(options: MicrosoftProviderOptions): ProviderDefinition {
  if (
    !options ||
    typeof options !== "object" ||
    Array.isArray(options) ||
    typeof options.tenantId !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(options.tenantId)
  )
    throw configurationError();
  const tenantId = options.tenantId.toLowerCase();
  const issuer = `https://login.microsoftonline.com/${tenantId}/v2.0`;
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
        providerLogout: true,
        revocation: false,
        resources: options.resources ?? [],
      },
    },
    {
      aliases: [issuer],
      version: "microsoft-1",
      discoveryLogout: true,
      discoveryRevocation: false,
      authorizationResourceParameter: null,
      tokenScopePolicy: "microsoft",
      validateClaims(principal) {
        if (principal.tid !== tenantId) throw new Error();
      },
    },
  );
  if (provider.identityScopes.some((scope) => !identityScopes.some((allowed) => allowed === scope)))
    throw configurationError();
  try {
    for (const target of provider.capabilities.resources) {
      const resource = new URL(target.resource);
      if (
        !["https:", "api:"].includes(resource.protocol) ||
        resource.username ||
        resource.password ||
        resource.search ||
        resource.hash ||
        target.resource.includes("\\")
      )
        throw new Error();
      for (const scope of target.scopes) {
        const permission = new URL(scope);
        if (
          !scope.startsWith(target.resource.replace(/\/$/u, "") + "/") ||
          scope.endsWith("/") ||
          permission.search ||
          permission.hash ||
          scope.includes("\\")
        )
          throw new Error();
      }
    }
  } catch {
    throw configurationError();
  }
  return provider;
}

export { createMicrosoftProvider };
