import { discoverOidcProvider } from "./oidc-discovery";
import { validateOidcIdToken, validateOidcRefreshIdToken } from "./oidc-id-token";
import { requestOidcToken } from "./oidc-token";
import { decodeJson } from "./jwt-encoding";
import { httpsEndpoint, providerPolicy } from "./provider-definition";
import {
  configurationError,
  InteractionRequiredError,
  ProviderSessionError,
} from "./provider-session-error";
import { checkCancellation, waitFor } from "./provider-session-storage";
import type { ProviderDefinition } from "./provider-session-types";
import type { Principal } from "./model";
import type { JsonWebKeySet } from "./jwt-types";

export interface ValidatedProviderTokens {
  accessToken: string;
  refreshToken?: string;
  expiresIn: number;
  scopes: readonly string[];
  idToken?: string;
}
export function providerTransport(
  request: typeof fetch,
  signal: AbortSignal,
  current: () => Promise<void>,
): typeof fetch {
  return async (input, init) => {
    checkCancellation(signal);
    await current();
    try {
      const response = await waitFor(
        request(input, { ...init, redirect: "error", signal }),
        signal,
      );
      await current();
      return response;
    } catch (error) {
      checkCancellation(signal);
      if (error instanceof ProviderSessionError || error instanceof InteractionRequiredError)
        throw error;
      throw new ProviderSessionError("provider-unavailable");
    }
  };
}
export async function providerMetadata(
  provider: ProviderDefinition,
  request: typeof fetch,
  current: () => Promise<void> = async () => {},
) {
  const policy = providerPolicy(provider);
  let metadata;
  try {
    metadata = await discoverOidcProvider(request, provider.issuer);
  } catch (error) {
    await current();
    if (
      error instanceof ProviderSessionError ||
      (error instanceof Error && error.name === "AbortError")
    )
      throw error;
    throw new ProviderSessionError("provider-unavailable");
  }
  await current();
  const result = {
    ...metadata,
    authorization_endpoint: policy.endpoints.authorization ?? metadata.authorization_endpoint,
    token_endpoint: policy.endpoints.token ?? metadata.token_endpoint,
    jwks_uri: policy.endpoints.jwks ?? metadata.jwks_uri,
    end_session_endpoint:
      policy.endpoints.logout ??
      (policy.discoveryLogout ? metadata.end_session_endpoint : undefined),
    revocation_endpoint:
      policy.endpoints.revocation ??
      (policy.discoveryRevocation && typeof metadata.revocation_endpoint === "string"
        ? metadata.revocation_endpoint
        : undefined),
  };
  try {
    for (const endpoint of [result.authorization_endpoint, result.token_endpoint, result.jwks_uri])
      httpsEndpoint(endpoint);
  } catch {
    throw new ProviderSessionError("provider-unavailable");
  }
  if (provider.capabilities.providerLogout && typeof result.end_session_endpoint !== "string")
    throw configurationError();
  if (provider.capabilities.revocation && typeof result.revocation_endpoint !== "string")
    throw configurationError();
  for (const endpoint of [result.end_session_endpoint, result.revocation_endpoint])
    if (endpoint !== undefined) httpsEndpoint(String(endpoint));
  return result;
}
export async function confidentialAuthentication(
  provider: ProviderDefinition,
  now: number,
  signal: AbortSignal,
) {
  const auth = provider.clientAuthentication;
  checkCancellation(signal);
  let secret: unknown;
  try {
    secret =
      typeof auth.secret === "function"
        ? await waitFor(Promise.resolve(auth.secret({ now, signal })), signal)
        : auth.secret;
  } catch (error) {
    checkCancellation(signal);
    if (error instanceof ProviderSessionError) throw error;
    throw configurationError();
  }
  checkCancellation(signal);
  if (typeof secret !== "string" || !secret || secret.length > 8192) throw configurationError();
  return { method: auth.method, secret };
}
export async function exchangeProviderTokens(
  provider: ProviderDefinition,
  request: typeof fetch,
  endpoint: string,
  body: URLSearchParams,
  scopes: readonly string[],
  now: number,
  signal: AbortSignal,
  resource?: string,
): Promise<ValidatedProviderTokens> {
  const authentication = await confidentialAuthentication(provider, now, signal);
  const response = await requestOidcToken(
    request,
    endpoint,
    provider.clientId,
    body,
    authentication,
    signal,
  );
  let value: unknown;
  try {
    const text = await waitFor(response.text(), signal);
    if (text.length > 131_072) throw new Error();
    value = JSON.parse(text);
  } catch {
    checkCancellation(signal);
    throw new ProviderSessionError("provider-unavailable");
  }
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new ProviderSessionError("provider-unavailable");
  const data = value as Record<string, unknown>;
  if (!response.ok || data.error !== undefined) {
    if (["invalid_grant", "login_required", "consent_required"].includes(String(data.error)))
      throw new InteractionRequiredError({
        provider: provider.id,
        reason: data.error === "consent_required" ? "consent" : "login",
        resource,
        scopes,
      });
    throw new ProviderSessionError("provider-unavailable");
  }
  if (
    typeof data.access_token !== "string" ||
    !data.access_token ||
    data.access_token.length > 65_536 ||
    typeof data.token_type !== "string" ||
    data.token_type.toLowerCase() !== "bearer" ||
    typeof data.expires_in !== "number" ||
    !Number.isFinite(data.expires_in) ||
    data.expires_in <= 0 ||
    data.expires_in > 2_592_000 ||
    (data.refresh_token !== undefined &&
      (typeof data.refresh_token !== "string" ||
        !data.refresh_token ||
        data.refresh_token.length > 65_536))
  )
    throw new ProviderSessionError("provider-unavailable");
  const granted =
    data.scope === undefined
      ? scopes
      : typeof data.scope === "string"
        ? data.scope.split(" ").filter(Boolean)
        : [];
  if (!scopes.every((scope) => granted.includes(scope)))
    throw new InteractionRequiredError({
      provider: provider.id,
      reason: "consent",
      resource,
      scopes,
    });
  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token as string | undefined,
    expiresIn: data.expires_in,
    scopes: [...scopes],
    idToken: typeof data.id_token === "string" ? data.id_token : undefined,
  };
}
export async function validateProviderIdentity(
  provider: ProviderDefinition,
  idToken: string | undefined,
  nonce: string,
  jwksUri: string,
  request: typeof fetch,
  now: number,
  previousSubject?: string,
): Promise<Principal> {
  try {
    if (!idToken) throw new Error();
    const claimedIssuer = decodeJson(idToken.split(".")[1]!).iss;
    const policy = providerPolicy(provider);
    if (typeof claimedIssuer !== "string" || !policy.aliases.includes(claimedIssuer))
      throw new Error();
    const validation = {
      issuer: claimedIssuer,
      audience: provider.clientId,
      nonce,
      clock: () => now / 1000,
      clockSkewSeconds: 0,
      jwks: async () => {
        const response = await request(jwksUri);
        if (!response.ok) throw new ProviderSessionError("provider-unavailable");
        const value: unknown = await response.json();
        if (!value || typeof value !== "object" || !Array.isArray((value as JsonWebKeySet).keys))
          throw new ProviderSessionError("provider-unavailable");
        return value as JsonWebKeySet;
      },
    };
    const principal =
      previousSubject === undefined
        ? await validateOidcIdToken(idToken, validation)
        : await validateOidcRefreshIdToken(idToken, { ...validation, subject: previousSubject });
    policy.validateClaims?.(principal);
    if (typeof principal.subject !== "string" || !principal.subject) throw new Error();
    return Object.freeze({
      id: JSON.stringify([provider.issuer, principal.subject]),
      subject: principal.subject,
    });
  } catch (error) {
    if (
      error instanceof ProviderSessionError ||
      error instanceof InteractionRequiredError ||
      (error instanceof Error && error.name === "AbortError")
    )
      throw error;
    throw new ProviderSessionError("invalid-callback");
  }
}
