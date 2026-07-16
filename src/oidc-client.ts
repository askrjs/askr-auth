import { codeChallenge, randomString } from "./oidc-crypto";
import { discoverOidcProvider } from "./oidc-discovery";
import { exchangeOidcCode } from "./oidc-token";
import type {
  OidcAuthorizationRequestOptions,
  OidcClient,
  OidcClientOptions,
  OidcProviderMetadata,
  OidcTokenResponse,
  OidcCodeExchange,
  OidcAuthorizationRequest,
} from "./oidc-types";

export * from "./oidc-types";

export function createOidcClient(options: OidcClientOptions): OidcClient {
  const issuer = options.issuer.replace(/\/$/, "");
  const request = options.fetch ?? globalThis.fetch.bind(globalThis);
  let metadata: OidcProviderMetadata | undefined;
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
    async exchangeCode(input: OidcCodeExchange): Promise<OidcTokenResponse> {
      return exchangeOidcCode(request, await this.discover(), options, input);
    },
  };
}
