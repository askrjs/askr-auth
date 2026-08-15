/** Discovery metadata published by an OpenID Connect provider. */
export interface OidcProviderMetadata extends Record<string, unknown> {
  /** Provider issuer URL. */
  issuer: string;
  /** Authorization endpoint URL. */
  authorization_endpoint: string;
  /** Token endpoint URL. */
  token_endpoint: string;
  /** JWKS endpoint URL. */
  jwks_uri: string;
  /** Optional user-info endpoint URL. */
  userinfo_endpoint?: string;
  /** Optional end-session endpoint URL. */
  end_session_endpoint?: string;
}
/** Client credentials and callback settings for OIDC. */
export interface OidcClientOptions {
  /** Provider issuer URL. */
  issuer: string;
  /** Registered client identifier. */
  clientId: string;
  /** Optional confidential-client secret. */
  clientSecret?: string;
  /** Registered redirect URI. */
  redirectUri: string;
  /** Requested scopes. */
  scopes?: readonly string[];
  /** Fetch implementation for provider requests. */
  fetch?: typeof fetch;
}
/** Optional state, nonce, and PKCE values for an authorization request. */
export interface OidcAuthorizationRequestOptions {
  /** CSRF state value. */
  state?: string;
  /** Replay-protection nonce. */
  nonce?: string;
  /** PKCE verifier. */
  codeVerifier?: string;
  /** Optional provider login hint. */
  loginHint?: string;
}
/** Generated authorization URL and callback values. */
export interface OidcAuthorizationRequest {
  /** Provider authorization URL. */
  url: string;
  /** CSRF state value. */
  state: string;
  /** Replay-protection nonce. */
  nonce: string;
  /** PKCE verifier retained for callback exchange. */
  codeVerifier: string;
}
/** Token response returned by an OIDC provider. */
export interface OidcTokenResponse extends Record<string, unknown> {
  /** Access token. */
  access_token: string;
  /** Token type, normally Bearer. */
  token_type: string;
  /** Optional ID token. */
  id_token?: string;
  /** Optional refresh token. */
  refresh_token?: string;
  /** Optional lifetime in seconds. */
  expires_in?: number;
}
/** Callback code and original authorization request values. */
export interface OidcCodeExchange {
  /** Authorization code. */
  code: string;
  /** Returned CSRF state. */
  state: string;
  /** Stored authorization request values. */
  request: Pick<OidcAuthorizationRequest, "state" | "nonce" | "codeVerifier">;
}
/** Result of exchanging an authorization code. */
export interface OidcCodeExchangeResult {
  /** Provider tokens. */
  tokens: OidcTokenResponse;
  /** Principal derived from the validated ID token. */
  principal: import("./model").Principal;
}
/** High-level OIDC discovery, authorization, and callback client. */
export interface OidcClient {
  /** Discover and cache provider metadata. @returns Provider discovery metadata. */
  discover(): Promise<OidcProviderMetadata>;
  /** Build an authorization URL and callback state. @param options Optional state, nonce, and PKCE overrides. @returns Authorization request details. */
  createAuthorizationRequest(
    options?: OidcAuthorizationRequestOptions,
  ): Promise<OidcAuthorizationRequest>;
  /** Exchange an authorization code and validate its ID token. @param input Authorization code and stored request. @returns Tokens and validated principal. */
  exchangeCode(input: OidcCodeExchange): Promise<OidcCodeExchangeResult>;
}
