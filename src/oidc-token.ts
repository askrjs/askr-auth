import type {
  OidcClientOptions,
  OidcCodeExchange,
  OidcProviderMetadata,
  OidcTokenResponse,
} from "./oidc-types";
import { OidcClientError } from "./oidc-error";

/** Shared confidential-client request construction; token policy remains with its owner. */
export async function requestOidcToken(
  request: typeof fetch,
  endpoint: string,
  clientId: string,
  body: URLSearchParams,
  authentication?: { method: "client_secret_basic" | "client_secret_post"; secret: string },
  signal?: AbortSignal,
): Promise<Response> {
  const formEncode = (value: string) =>
    new URLSearchParams({ value }).toString().slice("value=".length);
  body.set("client_id", clientId);
  const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded" };
  if (authentication?.method === "client_secret_post")
    body.set("client_secret", authentication.secret);
  else if (authentication)
    headers.authorization = `Basic ${btoa(`${formEncode(clientId)}:${formEncode(authentication.secret)}`)}`;
  return request(endpoint, { method: "POST", headers, body, ...(signal ? { signal } : {}) });
}

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
    code_verifier: input.request.codeVerifier,
  });
  const response = await requestOidcToken(
    request,
    metadata.token_endpoint,
    options.clientId,
    body,
    options.clientSecret
      ? { method: "client_secret_basic", secret: options.clientSecret }
      : undefined,
  );
  let value: unknown;
  try {
    value = await response.json();
  } catch (cause) {
    throw new OidcClientError("invalid-token-response", "OIDC token response is not valid JSON.", {
      cause,
    });
  }
  if (!response.ok)
    throw new OidcClientError(
      "exchange-failed",
      `OIDC token exchange failed with HTTP ${response.status}.`,
    );
  if (
    !value ||
    typeof value !== "object" ||
    typeof (value as { access_token?: unknown }).access_token !== "string"
  )
    throw new OidcClientError("invalid-token-response", "OIDC token response is invalid.");
  const tokens = value as Partial<OidcTokenResponse>;
  if (
    typeof tokens.token_type !== "string" ||
    typeof tokens.id_token !== "string" ||
    !tokens.id_token
  )
    throw new OidcClientError(
      "invalid-token-response",
      "OIDC token response must contain token_type and id_token.",
    );
  return value as OidcTokenResponse;
}
