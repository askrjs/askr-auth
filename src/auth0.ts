import {
  Auth0Client,
  InMemoryCache,
  type ICache,
  type GetTokenSilentlyVerboseResponse,
  type WrappedCacheEntry,
} from "@auth0/auth0-spa-js";
import {
  BrowserOidcSessionError,
  type BrowserOidcSession,
  type BrowserOidcSessionResult,
} from "./browser-types";
import type { Principal } from "./model";
import { providerAuthorizationParams } from "./oidc-parameters";

/** Optional Auth0 SDK configuration; the SDK owns a fresh memory-only token cache. */
export interface Auth0SessionOptions {
  /** Auth0 tenant/custom domain, optionally including https://. */
  domain: string;
  /** Registered public application client ID. */
  clientId: string;
  /** Registered query-mode callback URL. Application owns navigation. */
  redirectUri: string;
  /** Explicit token issuer, when different from the configured domain. */
  issuer?: string;
  /** Requested scopes; the SDK also requires openid. */
  scopes?: readonly string[];
  /** Bounded provider parameters such as audience, organization and connection. */
  authorizationParams?: Readonly<Record<string, string>>;
  /** Dedicated login hint; extension parameters cannot overwrite it. */
  loginHint?: string;
  /** SDK iframe timeout in seconds, from greater than zero through 120. Defaults to 15. */
  authorizationTimeoutSeconds?: number;
  /** SDK identity-claim clock leeway in seconds, from greater than zero through 300. Defaults to 60. */
  leewaySeconds?: number;
  /** Explicitly enable SDK refresh-token renewal in the memory cache. Defaults to false. */
  useRefreshTokens?: boolean;
  /** Permit SDK iframe fallback when refresh renewal cannot run; requires useRefreshTokens. */
  useRefreshTokensFallback?: boolean;
}

interface Owner {
  readonly client: Auth0Client;
  readonly cache: ICache;
  readonly controller: AbortController;
}

const interactionErrors = new Set([
  "login_required",
  "consent_required",
  "interaction_required",
  "account_selection_required",
]);

/** Implement the existing browser session contract through the optional official SDK. */
export function createAuth0Session(options: Auth0SessionOptions): BrowserOidcSession {
  const invalid = (message: string): never => {
    throw new BrowserOidcSessionError("invalid-options", message);
  };
  const allowed = new Set([
    "domain",
    "clientId",
    "redirectUri",
    "issuer",
    "scopes",
    "authorizationParams",
    "loginHint",
    "authorizationTimeoutSeconds",
    "leewaySeconds",
    "useRefreshTokens",
    "useRefreshTokensFallback",
  ]);
  if (
    !options ||
    typeof options !== "object" ||
    Object.keys(options).some((key) => !allowed.has(key)) ||
    typeof options.clientId !== "string" ||
    !options.clientId.trim()
  )
    invalid(
      "Auth0 sessions require explicit public client options; client secrets and custom persistent caches are unsupported.",
    );
  const timeout = options.authorizationTimeoutSeconds ?? 15;
  const leeway = options.leewaySeconds ?? 60;
  if (
    !Number.isFinite(timeout) ||
    timeout <= 0 ||
    timeout > 120 ||
    !Number.isFinite(leeway) ||
    leeway <= 0 ||
    leeway > 300 ||
    [options.useRefreshTokens, options.useRefreshTokensFallback].some(
      (value) => value !== undefined && typeof value !== "boolean",
    ) ||
    (options.useRefreshTokensFallback && !options.useRefreshTokens)
  )
    invalid(
      "Auth0 timeout/leeway must be finite and bounded; refresh-token fallback requires explicit refresh-token renewal.",
    );
  const absolute = (value: string, domain = false): URL => {
    if (typeof value !== "string" || !value)
      return invalid("Auth0 domain, issuer and callback require nonempty strings.");
    let url: URL;
    try {
      url = new URL(domain && !value.includes("://") ? `https://${value}` : value);
    } catch {
      return invalid("Auth0 domain, issuer and callback must be absolute URLs.");
    }
    if (
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      (domain ? url.protocol !== "https:" : !["https:", "http:"].includes(url.protocol))
    )
      invalid(
        "Auth0 provider URLs require HTTPS and callback URLs require HTTP(S), without credentials, query or fragment.",
      );
    return url;
  };
  if (
    typeof options.domain !== "string" ||
    !options.domain ||
    typeof options.redirectUri !== "string" ||
    !options.redirectUri
  )
    invalid("Auth0 domain and callback are required.");
  const domain = absolute(options.domain, true).href.replace(/\/$/u, "");
  const redirect = absolute(options.redirectUri);
  const issuer = options.issuer === undefined ? undefined : absolute(options.issuer, true).href;
  const authorizationParams = providerAuthorizationParams(options.authorizationParams);
  if (options.scopes !== undefined && !Array.isArray(options.scopes))
    invalid("Auth0 scopes must be an array of scope names.");
  const scopes = options.scopes ? [...options.scopes] : ["openid", "profile", "email"];
  if (
    scopes.length > 32 ||
    scopes.some(
      (scope) => typeof scope !== "string" || !scope || scope.length > 128 || /\s/u.test(scope),
    ) ||
    (options.loginHint !== undefined &&
      (typeof options.loginHint !== "string" || options.loginHint.length > 2048))
  )
    invalid(
      "Auth0 scopes require bounded nonempty scope names, and loginHint must be a bounded string.",
    );
  const clientId = options.clientId;
  const useRefreshTokens = options.useRefreshTokens ?? false;
  const useRefreshTokensFallback = options.useRefreshTokensFallback ?? false;
  const loginHint = options.loginHint;
  let disposed = false;
  let current: Owner | undefined;
  let redirecting = false;
  let callbackAllowed = true;
  let restoring: Promise<BrowserOidcSessionResult> | undefined;
  // The SDK owns one clientId-scoped redirect transaction. Only redirect
  // preparation writers are ordered; SDK token locking/renewal stays delegated.
  let redirectWrites: Promise<void> = Promise.resolve();

  const assertLive = () => {
    if (disposed)
      throw new BrowserOidcSessionError("disposed", "The Auth0 browser session is disposed.");
  };
  const check = (owner: Owner) => {
    if (disposed || current !== owner || owner.controller.signal.aborted)
      throw new BrowserOidcSessionError(
        "cancelled",
        "The Auth0 operation no longer owns this session.",
      );
  };
  const clear = async (owner: Owner) => {
    for (const key of await owner.cache.allKeys!()) await owner.cache.remove(key);
  };
  const retire = () => {
    const previous = current;
    current = undefined;
    restoring = undefined;
    redirecting = false;
    if (!previous) return;
    previous.controller.abort();
    void clear(previous).catch(() => {});
    void previous.client.logout({ openUrl: false }).catch(() => {});
  };
  const owner = (): Owner => {
    assertLive();
    if (!current) {
      const cache = new InMemoryCache().enclosedCache;
      current = {
        cache,
        controller: new AbortController(),
        client: new Auth0Client({
          domain,
          clientId,
          issuer,
          cache,
          authorizationParams: {
            ...authorizationParams,
            redirect_uri: redirect.href,
            scope: scopes.join(" "),
            ...(loginHint === undefined ? {} : { login_hint: loginHint }),
          },
          authorizeTimeoutInSeconds: timeout,
          leeway,
          useRefreshTokens,
          useRefreshTokensFallback,
        }),
      };
    }
    return current;
  };
  const own = <T>(owned: Owner, run: () => Promise<T>): Promise<T> => {
    const signal = owned.controller.signal;
    return new Promise((resolve, reject) => {
      const abort = () =>
        reject(
          new BrowserOidcSessionError(
            "cancelled",
            "The Auth0 operation no longer owns this session.",
          ),
        );
      signal.addEventListener("abort", abort, { once: true });
      if (signal.aborted) {
        abort();
        signal.removeEventListener("abort", abort);
        return;
      }
      Promise.resolve()
        .then(() => {
          check(owned);
          return run();
        })
        .then(
          (value) => {
            check(owned);
            resolve(value);
          },
          (error: unknown) => {
            check(owned);
            reject(error);
          },
        )
        .catch(reject)
        .finally(() => {
          signal.removeEventListener("abort", abort);
          if (current !== owned || signal.aborted) void clear(owned).catch(() => {});
        });
    });
  };
  const outcome = async (
    run: () => Promise<BrowserOidcSessionResult>,
  ): Promise<BrowserOidcSessionResult> => {
    try {
      return await run();
    } catch (cause) {
      if (cause instanceof BrowserOidcSessionError) throw cause;
      const failure = cause && typeof cause === "object" ? cause : undefined;
      const error =
        failure && "error" in failure && typeof failure.error === "string"
          ? failure.error
          : undefined;
      if (error && interactionErrors.has(error))
        return {
          status: "interaction-required",
          error,
          description:
            failure &&
            "error_description" in failure &&
            typeof failure.error_description === "string"
              ? failure.error_description
              : undefined,
        };
      throw new BrowserOidcSessionError(
        error === "missing_transaction" || error === "state_mismatch"
          ? "invalid-transaction"
          : "authorization-error",
        `Auth0 authentication failed${error ? `: ${error}` : cause instanceof Error ? `: ${cause.message}` : ""}.`,
        { cause },
      );
    }
  };
  const normalize = async (
    owned: Owner,
    token: GetTokenSilentlyVerboseResponse | undefined,
  ): Promise<BrowserOidcSessionResult> => {
    check(owned);
    if (
      !token ||
      typeof token.access_token !== "string" ||
      !token.access_token ||
      token.token_type?.toLowerCase() !== "bearer"
    )
      throw new BrowserOidcSessionError(
        "invalid-token-response",
        "The SDK must return a nonempty Bearer access token.",
      );
    const user = await owned.client.getUser();
    check(owned);
    if (!user || typeof user.sub !== "string" || !user.sub)
      throw new BrowserOidcSessionError(
        "invalid-token-response",
        "The SDK must return its validated subject with the access token.",
      );
    let expiresAt = Infinity;
    for (const key of await owned.cache.allKeys!()) {
      const entry = await owned.cache.get<WrappedCacheEntry>(key);
      if (
        entry?.body?.access_token === token.access_token &&
        entry.body.client_id === clientId &&
        entry.body.audience === (authorizationParams.audience ?? "default") &&
        Number.isFinite(entry.expiresAt)
      )
        expiresAt = Math.min(expiresAt, entry.expiresAt * 1000);
    }
    check(owned);
    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now())
      throw new BrowserOidcSessionError(
        "invalid-token-response",
        "The SDK token requires a matching, fresh absolute expiry in its memory cache.",
      );
    const principal: Principal = { id: user.sub, subject: user.sub };
    for (const claim of ["name", "nickname", "given_name", "family_name", "email", "picture"])
      if (typeof user[claim] === "string") principal[claim] = user[claim];
    if (typeof user.email_verified === "boolean") principal.email_verified = user.email_verified;
    return { status: "authenticated", principal, accessToken: token.access_token, expiresAt };
  };
  const token = (owned: Owner) =>
    outcome(async () =>
      normalize(owned, await owned.client.getTokenSilently({ detailedResponse: true })),
    );
  const session: BrowserOidcSession = {
    async login() {
      assertLive();
      retire();
      const owned = owner();
      redirecting = true;
      callbackAllowed = true;
      const preparing = redirectWrites.then(async () => {
        check(owned);
        let url: string | undefined;
        await owned.client.loginWithRedirect({
          openUrl: (value) => {
            check(owned);
            url = value;
          },
        });
        check(owned);
        if (!url)
          throw new BrowserOidcSessionError(
            "authorization-error",
            "The SDK did not produce an authorization URL.",
          );
        return url;
      });
      redirectWrites = preparing.then(
        () => {},
        () => {},
      );
      return own(owned, () => preparing);
    },
    restore(callbackUrl) {
      assertLive();
      let url: URL;
      try {
        url = new URL(callbackUrl ?? window.location.href);
      } catch (cause) {
        throw new BrowserOidcSessionError("invalid-callback", "Callback must be an absolute URL.", {
          cause,
        });
      }
      if (!["code", "error", "state"].some((name) => url.searchParams.has(name)))
        return session.getToken();
      if (!callbackAllowed)
        return Promise.reject(
          new BrowserOidcSessionError(
            "invalid-transaction",
            "Local logout retired the callback; begin a new login.",
          ),
        );
      retire();
      const owned = owner();
      callbackAllowed = false;
      const pending = own(owned, () =>
        outcome(async () => {
          if (
            url.origin !== redirect.origin ||
            url.pathname !== redirect.pathname ||
            url.hash ||
            ["state", "code", "error"].some((name) => url.searchParams.getAll(name).length > 1) ||
            !url.searchParams.get("state") ||
            Boolean(url.searchParams.get("code")) === Boolean(url.searchParams.get("error"))
          )
            throw new BrowserOidcSessionError(
              "invalid-callback",
              "Auth0 callback requires the registered query-mode URL, state and exactly one code or error.",
            );
          await owned.client.handleRedirectCallback(url.href);
          check(owned);
          return token(owned);
        }),
      );
      restoring = pending;
      void pending
        .finally(() => {
          if (restoring === pending) restoring = undefined;
        })
        .catch(() => {});
      return pending;
    },
    getToken() {
      assertLive();
      if (redirecting)
        return Promise.resolve({ status: "interaction-required", error: "login_required" });
      if (restoring) return restoring;
      const owned = owner();
      return own(owned, () => token(owned));
    },
    logout() {
      assertLive();
      callbackAllowed = false;
      retire();
    },
    dispose() {
      if (disposed) return;
      disposed = true;
      callbackAllowed = false;
      retire();
    },
  };
  return session;
}
