import type {
  OidcClientOptions,
  OidcCodeExchange,
  OidcProviderMetadata,
  OidcTokenResponse,
} from "./oidc-types";

export async function exchangeOidcCode(
  request: typeof fetch,
  metadata: OidcProviderMetadata,
  options: OidcClientOptions,
  input: OidcCodeExchange,
): Promise<OidcTokenResponse> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: input.code,
    redirect_uri: options.redirectUri,
    client_id: options.clientId,
    code_verifier: input.codeVerifier,
  });
  const response = await request(metadata.token_endpoint, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...(options.clientSecret
        ? { authorization: `Basic ${btoa(`${options.clientId}:${options.clientSecret}`)}` }
        : {}),
    },
    body,
  });
  const value: unknown = await response.json();
  if (!response.ok) throw new Error(`OIDC token exchange failed with HTTP ${response.status}.`);
  if (
    !value ||
    typeof value !== "object" ||
    typeof (value as { access_token?: unknown }).access_token !== "string"
  )
    throw new Error("OIDC token response is invalid.");
  return value as OidcTokenResponse;
}
