import type { AuthResolver } from "./auth-types";
import type { AuthContext, Principal } from "./model";

export interface ProviderTokenRequest {
  readonly resource?: string;
  readonly scopes: readonly string[];
  readonly signal?: AbortSignal;
}
export interface ProviderLoginRequest {
  readonly provider: string;
  readonly returnTo: string;
  readonly resource?: string;
  readonly scopes?: readonly string[];
}
export interface ProviderLogoutRequest {
  readonly provider?: string;
  readonly providerLogout?: boolean;
  readonly returnTo?: string;
  readonly revoke?: boolean;
}
export type ProviderClientAuthentication = {
  readonly method: "client_secret_post" | "client_secret_basic";
  readonly secret:
    | string
    | ((context: {
        readonly now: number;
        readonly signal: AbortSignal;
      }) => string | PromiseLike<string>);
};
export interface ProviderCapabilities {
  readonly renewal: "refresh" | "account-check" | "none";
  readonly incrementalConsent: boolean;
  readonly providerLogout: boolean;
  readonly revocation: boolean;
  readonly resources: readonly { readonly resource: string; readonly scopes: readonly string[] }[];
}
declare const providerDefinitionBrand: unique symbol;
export interface ProviderDefinition {
  readonly [providerDefinitionBrand]: true;
  readonly id: string;
  readonly issuer: string;
  readonly clientId: string;
  readonly clientAuthentication: ProviderClientAuthentication;
  readonly responseMode: "query" | "form_post";
  readonly identityScopes: readonly string[];
  readonly capabilities: ProviderCapabilities;
  readonly authorizationParams?: Readonly<Record<string, string>>;
}
export interface OidcProviderOptions {
  readonly id: string;
  readonly issuer: string;
  readonly clientId: string;
  readonly clientAuthentication: ProviderClientAuthentication;
  readonly identityScopes?: readonly string[];
  readonly responseMode?: "query" | "form_post";
  readonly capabilities?: Partial<ProviderCapabilities>;
  readonly authorizationParams?: Readonly<Record<string, string>>;
  readonly endpoints?: {
    readonly authorization?: string;
    readonly token?: string;
    readonly jwks?: string;
    readonly logout?: string;
    readonly revocation?: string;
  };
}
export interface ProviderSessionRecord {
  readonly revision: number;
  readonly expiresAt: number;
  readonly retired: boolean;
  readonly value: string | null;
}
export interface ProviderSessionStore {
  read(id: string, options: { signal: AbortSignal }): Promise<ProviderSessionRecord | null>;
  compareAndSwap(
    id: string,
    expectedRevision: number | null,
    next: ProviderSessionRecord,
    options: { signal: AbortSignal },
  ): Promise<boolean>;
  withLock<T>(
    key: string,
    operation: () => Promise<T>,
    options: { signal: AbortSignal },
  ): Promise<T>;
}
export interface ProviderSessionOptions {
  readonly origin: string;
  readonly providers: readonly ProviderDefinition[];
  readonly session: {
    readonly secrets: readonly string[];
    readonly store?: ProviderSessionStore;
    readonly maxAgeSeconds?: number;
    readonly leewaySeconds?: number;
    readonly maxEntries?: number;
  };
  readonly onSignIn?: (context: {
    readonly provider: string;
    readonly principal: Readonly<Principal>;
    readonly profileHint?: { readonly givenName?: string; readonly familyName?: string };
    readonly signal: AbortSignal;
  }) => void | PromiseLike<void>;
  readonly postLogoutRedirects?: readonly string[];
  readonly transactionTtlSeconds?: number;
  readonly fetch?: typeof fetch;
  readonly clock?: () => number;
}
export interface ProviderSession extends AuthResolver {
  resolve(request: Request, options?: { signal?: AbortSignal }): Promise<AuthContext>;
  login(request: Request, options: ProviderLoginRequest): Promise<Response>;
  callback(request: Request, options: { readonly provider: string }): Promise<Response>;
  logout(request: Request, options?: ProviderLogoutRequest): Promise<Response>;
  token(request: Request, provider: string, options: ProviderTokenRequest): Promise<string>;
  finalize(request: Request, response: Response): Promise<Response>;
  close(): Promise<void>;
}
