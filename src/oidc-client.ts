import { codeChallenge, randomString } from "./oidc-crypto";
import { discoverOidcProvider } from "./oidc-discovery";
import { exchangeOidcCode } from "./oidc-token";
import { OidcClientError } from "./oidc-error";
import { validateOidcIdToken } from "./jwt-validator";
import type { JsonWebKeySet } from "./jwt-types";
import type {
  OidcAuthorizationRequestOptions,
  OidcClient,
  OidcClientOptions,
  OidcProviderMetadata,
  OidcCodeExchange,
  OidcAuthorizationRequest,
} from "./oidc-types";

export * from "./oidc-types";

export function createOidcClient(options: OidcClientOptions): OidcClient {
  const issuer = options.issuer;
  const request = options.fetch ?? globalThis.fetch.bind(globalThis);
  let metadata: OidcProviderMetadata | undefined;
  let jwksCache: JsonWebKeySet | undefined;
  return {
    discover: async () => (metadata ??= await discoverOidcProvider(request, issuer)),
    async createAuthorizationRequest(
      input: OidcAuthorizationRequestOptions = {},
    ): Promise<OidcAuthorizationRequest> {
      const discovered = await this.discover();
      const state = input.state ?? randomString();
      const nonce = input.nonce ?? randomString();
      const verifier = input.codeVerifier ?? randomString(48);
      const url = new URL(discovered.authorization_endpoint);
      url.searchParams.set("response_type", "code");
      url.searchParams.set("client_id", options.clientId);
      url.searchParams.set("redirect_uri", options.redirectUri);
      url.searchParams.set("scope", (options.scopes ?? ["openid", "profile", "email"]).join(" "));
      url.searchParams.set("state", state);
      url.searchParams.set("nonce", nonce);
      url.searchParams.set("code_challenge", await codeChallenge(verifier));
      url.searchParams.set("code_challenge_method", "S256");
      if (input.loginHint) url.searchParams.set("login_hint", input.loginHint);
      return { url: url.toString(), state, nonce, codeVerifier: verifier };
    },
    async exchangeCode(input: OidcCodeExchange) {
      if (input.state !== input.request.state)
        throw new OidcClientError("state-mismatch", "OIDC callback state does not match the stored request.");
      const discovered = await this.discover();
      const tokens = await exchangeOidcCode(request, discovered, options, input);
      let jwksCalls = 0;
      const jwks = async () => {
        jwksCalls++;
        if (jwksCalls === 1 && jwksCache) return jwksCache;
        const response = await request(discovered.jwks_uri);
        if (!response.ok) throw new Error(`JWKS request failed with HTTP ${response.status}.`);
        const value: unknown = await response.json();
        if (!value || typeof value !== "object" || !Array.isArray((value as JsonWebKeySet).keys)) throw new Error("JWKS response is invalid.");
        return (jwksCache = value as JsonWebKeySet);
      };
      try {
        const principal = await validateOidcIdToken(tokens.id_token!, {
          issuer: discovered.issuer, audience: options.clientId, nonce: input.request.nonce, jwks,
        });
        return { tokens, principal };
      } catch (cause) {
        throw new OidcClientError("invalid-id-token", "OIDC ID token validation failed.", { cause });
      }
    },
  };
}

export * from "./oidc-error";
