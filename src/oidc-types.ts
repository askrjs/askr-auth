export interface OidcProviderMetadata extends Record<string, unknown> {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  userinfo_endpoint?: string;
  end_session_endpoint?: string;
}
export interface OidcClientOptions {
  issuer: string;
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
  scopes?: readonly string[];
  fetch?: typeof fetch;
}
export interface OidcAuthorizationRequestOptions {
  state?: string;
  nonce?: string;
  codeVerifier?: string;
  loginHint?: string;
}
export interface OidcAuthorizationRequest {
  url: string;
  state: string;
  nonce: string;
  codeVerifier: string;
}
export interface OidcTokenResponse extends Record<string, unknown> {
  access_token: string;
  token_type: string;
  id_token?: string;
  refresh_token?: string;
  expires_in?: number;
}
export interface OidcCodeExchange {
  code: string;
  state: string;
  request: Pick<OidcAuthorizationRequest, "state" | "nonce" | "codeVerifier">;
}
export interface OidcCodeExchangeResult {
  tokens: OidcTokenResponse;
  principal: import("./model").Principal;
}
export interface OidcClient {
  discover(): Promise<OidcProviderMetadata>;
  createAuthorizationRequest(
    options?: OidcAuthorizationRequestOptions,
  ): Promise<OidcAuthorizationRequest>;
  exchangeCode(input: OidcCodeExchange): Promise<OidcCodeExchangeResult>;
}
