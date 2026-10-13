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
import {
  cancelResponseBody,
  OidcResponseTooLargeError,
  parseBoundedJsonResponse,
} from "./oidc-response";

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
    let response: Response | undefined;
    try {
      const pending = Promise.resolve()
        .then(() => {
          checkCancellation(signal);
          return request(input, { ...init, redirect: "error", signal });
        })
        .then((received) => {
          if (signal.aborted) cancelResponseBody(received);
          return received;
        });
      response = await waitFor(pending, signal);
      await current();
      return response;
    } catch (error) {
      if (response) cancelResponseBody(response);
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
  signal?: AbortSignal,
) {
  const policy = providerPolicy(provider);
  let metadata;
  try {
    metadata = await discoverOidcProvider(request, provider.issuer, signal);
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
    value = await parseBoundedJsonResponse(response, {
      // Preserve the previous Response.text().length boundary while enforcing it during reads.
      maxBytes: 131_072 * 3,
      maxCharacters: 131_072,
      signal,
    });
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
  if (providerPolicy(provider).tokenScopePolicy === "apple") {
    // Apple's response has no scope field. Signed identity establishes openid separately.
    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token as string | undefined,
      expiresIn: data.expires_in,
      scopes: [],
      idToken: typeof data.id_token === "string" ? data.id_token : undefined,
    };
  }
  if (providerPolicy(provider).tokenScopePolicy === "google") {
    if (typeof data.scope !== "string") throw new ProviderSessionError("provider-unavailable");
    const granted = data.scope.split(" ").filter(Boolean);
    const target = provider.capabilities.resources.find(
      (candidate) => candidate.resource === resource,
    );
    const required =
      resource === undefined ? [] : scopes.filter((scope) => target?.scopes.includes(scope));
    if (!required.every((scope) => granted.includes(scope)))
      throw new InteractionRequiredError({
        provider: provider.id,
        reason: "consent",
        resource,
        scopes: required,
      });
    const identity = new Set<string>();
    for (const scope of granted) {
      const normalized =
        scope === "https://www.googleapis.com/auth/userinfo.profile"
          ? "profile"
          : scope === "https://www.googleapis.com/auth/userinfo.email"
            ? "email"
            : scope;
      if (provider.identityScopes.includes(normalized)) identity.add(normalized);
    }
    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token as string | undefined,
      expiresIn: data.expires_in,
      scopes: [...identity].sort(),
      idToken: typeof data.id_token === "string" ? data.id_token : undefined,
    };
  }
  if (providerPolicy(provider).tokenScopePolicy === "microsoft") {
    const target = provider.capabilities.resources.find((entry) => entry.resource === resource);
    const required = target ? scopes.filter((scope) => target.scopes.includes(scope)) : [];
    const omitted = !Object.hasOwn(data, "scope");
    if (!omitted && typeof data.scope !== "string")
      throw new ProviderSessionError("provider-unavailable");
    const granted = typeof data.scope === "string" ? data.scope.split(" ").filter(Boolean) : [];
    const permits = (permission: string) => {
      if (resource !== "https://graph.microsoft.com") return granted.includes(permission);
      const prefix = "https://graph.microsoft.com/";
      const requiredSuffix = permission.slice(prefix.length).toLowerCase();
      return granted.some((scope) => {
        const suffix = scope.startsWith(prefix) ? scope.slice(prefix.length) : scope;
        // Fold only an ASCII Graph permission suffix, never a foreign URL/prefix.
        return /^[A-Za-z0-9._-]+$/u.test(suffix) && suffix.toLowerCase() === requiredSuffix;
      });
    };
    // Microsoft's absent scope property means the exact current exchange request.
    // It never authorizes an earlier/broader grant or an identity/offline snapshot scope.
    if (!omitted && !required.every(permits))
      throw new InteractionRequiredError({
        provider: provider.id,
        reason: "consent",
        resource,
        scopes: required,
      });
    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token as string | undefined,
      expiresIn: data.expires_in,
      scopes: granted.filter(
        (scope) => scope !== "offline_access" && provider.identityScopes.includes(scope),
      ),
      idToken: typeof data.id_token === "string" ? data.id_token : undefined,
    };
  }
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
export interface ValidatedProviderIdentity {
  readonly principal: Principal;
  readonly signInPrincipal?: Principal;
}
export async function validateProviderIdentity(
  provider: ProviderDefinition,
  idToken: string | undefined,
  nonce: string,
  jwksUri: string,
  request: typeof fetch,
  clock: () => number,
  previousSubject?: string,
  signal?: AbortSignal,
): Promise<ValidatedProviderIdentity> {
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
      clock: () => clock() / 1000,
      clockSkewSeconds: 0,
      jwks: async () => {
        const response = await request(jwksUri);
        if (!response.ok) {
          cancelResponseBody(response);
          throw new ProviderSessionError("provider-unavailable");
        }
        let value: unknown;
        try {
          value = await parseBoundedJsonResponse(response, { signal });
        } catch (error) {
          if (error instanceof OidcResponseTooLargeError)
            throw new ProviderSessionError("provider-unavailable");
          throw error;
        }
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
    const minimal = Object.freeze({
      id: JSON.stringify([provider.issuer, principal.subject]),
      subject: principal.subject,
    });
    return { principal: minimal, signInPrincipal: policy.signInPrincipal?.(principal, minimal) };
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
