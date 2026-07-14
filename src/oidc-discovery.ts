import type { OidcProviderMetadata } from "./oidc-types";

export async function discoverOidcProvider(request: typeof fetch, issuer: string): Promise<OidcProviderMetadata> {
  const response = await request(`${issuer}/.well-known/openid-configuration`);
  if (!response.ok) throw new Error(`OIDC discovery failed with HTTP ${response.status}.`);
  const value: unknown = await response.json();
  if (!value || typeof value !== "object") throw new Error("OIDC discovery returned invalid metadata.");
  const metadata = value as Partial<OidcProviderMetadata>;
  if (!metadata.issuer || !metadata.authorization_endpoint || !metadata.token_endpoint || !metadata.jwks_uri) throw new Error("OIDC discovery metadata is incomplete.");
  return metadata as OidcProviderMetadata;
}
