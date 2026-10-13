import type { OidcProviderMetadata } from "./oidc-types";
import { OidcClientError } from "./oidc-error";
import { cancelResponseBody, parseBoundedJsonResponse } from "./oidc-response";

function cancellationError(): DOMException {
  return new DOMException("OIDC discovery was cancelled.", "AbortError");
}

export async function discoverOidcProvider(
  request: typeof fetch,
  issuer: string,
  signal?: AbortSignal,
): Promise<OidcProviderMetadata> {
  try {
    const url = new URL(issuer);
    if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash)
      throw new Error();
  } catch {
    throw new OidcClientError(
      "invalid-metadata",
      "OIDC issuer must be an absolute HTTPS URL without credentials, query, or fragment.",
    );
  }
  let response: Response;
  try {
    response = await request(
      `${issuer.replace(/\/$/u, "")}/.well-known/openid-configuration`,
      signal ? { signal } : undefined,
    );
  } catch (cause) {
    if (signal?.aborted) throw cancellationError();
    throw new OidcClientError("discovery-failed", "OIDC discovery request failed.", { cause });
  }
  if (signal?.aborted) {
    cancelResponseBody(response);
    throw cancellationError();
  }
  if (!response.ok) {
    cancelResponseBody(response);
    throw new OidcClientError(
      "discovery-failed",
      `OIDC discovery failed with HTTP ${response.status}.`,
    );
  }
  let value: unknown;
  try {
    value = await parseBoundedJsonResponse(response, { signal });
  } catch (cause) {
    if (signal?.aborted) throw cancellationError();
    throw new OidcClientError("invalid-metadata", "OIDC discovery returned invalid JSON.", {
      cause,
    });
  }
  if (!value || typeof value !== "object")
    throw new OidcClientError("invalid-metadata", "OIDC discovery returned invalid metadata.");
  const metadata = value as Partial<OidcProviderMetadata>;
  if (
    !metadata.issuer ||
    !metadata.authorization_endpoint ||
    !metadata.token_endpoint ||
    !metadata.jwks_uri
  )
    throw new OidcClientError("invalid-metadata", "OIDC discovery metadata is incomplete.");
  if (metadata.issuer !== issuer)
    throw new OidcClientError(
      "invalid-metadata",
      "OIDC discovery issuer does not exactly match the configured issuer.",
    );
  for (const endpoint of [
    metadata.authorization_endpoint,
    metadata.token_endpoint,
    metadata.jwks_uri,
  ]) {
    try {
      if (new URL(endpoint).protocol !== "https:") throw new Error();
    } catch {
      throw new OidcClientError(
        "invalid-metadata",
        "OIDC metadata contains an invalid endpoint URL.",
      );
    }
  }
  return metadata as OidcProviderMetadata;
}
