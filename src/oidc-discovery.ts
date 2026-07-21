import type { OidcProviderMetadata } from "./oidc-types";
import { OidcClientError } from "./oidc-error";

export async function discoverOidcProvider(
  request: typeof fetch,
  issuer: string,
): Promise<OidcProviderMetadata> {
  let response: Response;
  try { response = await request(`${issuer.replace(/\/$/u, "")}/.well-known/openid-configuration`); }
  catch (cause) { throw new OidcClientError("discovery-failed", "OIDC discovery request failed.", { cause }); }
  if (!response.ok) throw new OidcClientError("discovery-failed", `OIDC discovery failed with HTTP ${response.status}.`);
  let value: unknown;
  try { value = await response.json(); } catch (cause) { throw new OidcClientError("invalid-metadata", "OIDC discovery returned invalid JSON.", { cause }); }
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
    throw new OidcClientError("invalid-metadata", "OIDC discovery issuer does not exactly match the configured issuer.");
  for (const endpoint of [metadata.authorization_endpoint, metadata.token_endpoint, metadata.jwks_uri]) {
    try { if (new URL(endpoint).protocol !== "https:") throw new Error(); }
    catch { throw new OidcClientError("invalid-metadata", "OIDC metadata contains an invalid endpoint URL."); }
  }
  return metadata as OidcProviderMetadata;
}
