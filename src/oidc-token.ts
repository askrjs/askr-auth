import type {
  OidcClientOptions,
  OidcCodeExchange,
  OidcProviderMetadata,
  OidcTokenResponse,
} from "./oidc-types";
import { OidcClientError } from "./oidc-error";

export async function exchangeOidcCode(
  request: typeof fetch,
  metadata: OidcProviderMetadata,
  options: OidcClientOptions,
  input: OidcCodeExchange,
): Promise<OidcTokenResponse> {
  const formEncode = (value: string) => new URLSearchParams({ value }).toString().slice("value=".length);
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: input.code,
    redirect_uri: options.redirectUri,
    client_id: options.clientId,
    code_verifier: input.request.codeVerifier,
  });
  const response = await request(metadata.token_endpoint, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...(options.clientSecret
        ? { authorization: `Basic ${btoa(`${formEncode(options.clientId)}:${formEncode(options.clientSecret)}`)}` }
        : {}),
    },
    body,
  });
  let value: unknown;
  try { value = await response.json(); } catch (cause) { throw new OidcClientError("invalid-token-response", "OIDC token response is not valid JSON.", { cause }); }
  if (!response.ok) throw new OidcClientError("exchange-failed", `OIDC token exchange failed with HTTP ${response.status}.`);
  if (
    !value ||
    typeof value !== "object" ||
    typeof (value as { access_token?: unknown }).access_token !== "string"
  )
    throw new OidcClientError("invalid-token-response", "OIDC token response is invalid.");
  const tokens = value as Partial<OidcTokenResponse>;
  if (typeof tokens.token_type !== "string" || typeof tokens.id_token !== "string" || !tokens.id_token)
    throw new OidcClientError("invalid-token-response", "OIDC token response must contain token_type and id_token.");
  return value as OidcTokenResponse;
}
