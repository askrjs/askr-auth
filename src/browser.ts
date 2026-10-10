import { createOidcClient } from "./oidc-client";
import { authorizeWithWebMessage, type BrowserAuthorizationResponse } from "./browser-transport";
import {
  BrowserOidcSessionError,
  type BrowserOidcSession,
  type BrowserOidcSessionOptions,
  type BrowserOidcSessionResult,
} from "./browser-types";
import type { OidcAuthorizationRequest, OidcCodeExchangeResult } from "./oidc-types";
import { providerAuthorizationParams } from "./oidc-parameters";

export * from "./browser-types";

interface Transaction {
  request: Pick<OidcAuthorizationRequest, "state" | "nonce" | "codeVerifier">;
  createdAt: number;
  expiresAt: number;
}

const interactionErrors = new Set([
  "login_required",
  "consent_required",
  "interaction_required",
  "account_selection_required",
]);

/** Create browser session ownership without storing tokens or changing server imports. */
export function createBrowserOidcSession(options: BrowserOidcSessionOptions): BrowserOidcSession {
  if (
    !options ||
    typeof options !== "object" ||
    typeof options.clientId !== "string" ||
    !options.clientId.trim()
  )
    throw new BrowserOidcSessionError(
      "invalid-options",
      "Browser OIDC requires an options object and public clientId.",
    );
  const ttl = options.transactionTtlMs ?? 300_000;
  const leeway = (options.clockLeewaySeconds ?? 30) * 1000;
  const timeout = options.silent ? (options.silent.timeoutMs ?? 15_000) : 15_000;
  const responseFormat = options.silent ? (options.silent.responseFormat ?? "flat") : "flat";
  const authorizationParams = providerAuthorizationParams(options.authorizationParams);
  if (
    "clientSecret" in options ||
    !Number.isFinite(ttl) ||
    ttl <= 0 ||
    ttl > 600_000 ||
    !Number.isFinite(leeway) ||
    leeway < 0 ||
    !Number.isFinite(timeout) ||
    timeout <= 0 ||
    timeout > 120_000 ||
    (responseFormat !== "flat" && responseFormat !== "auth0")
  )
    throw new BrowserOidcSessionError(
      "invalid-options",
      "Browser OIDC requires a public client and finite, bounded lifetimes.",
    );
  let redirect: URL;
  let silentRedirect: URL;
  try {
    redirect = new URL(options.redirectUri);
    silentRedirect = new URL(
      options.silent ? (options.silent.redirectUri ?? options.redirectUri) : options.redirectUri,
    );
  } catch (cause) {
    throw new BrowserOidcSessionError("invalid-options", "Redirect URIs must be absolute URLs.", {
      cause,
    });
  }
  if (
    redirect.search ||
    redirect.hash ||
    silentRedirect.search ||
    silentRedirect.hash ||
    silentRedirect.origin !== redirect.origin ||
    !["http:", "https:"].includes(redirect.protocol) ||
    redirect.username ||
    redirect.password ||
    silentRedirect.username ||
    silentRedirect.password
  ) {
    throw new BrowserOidcSessionError(
      "invalid-options",
      "Redirect URIs must share an origin and contain no query or fragment.",
    );
  }
  const key = `askr:oidc:${encodeURIComponent(JSON.stringify([options.issuer, options.clientId, redirect.href]))}`;
  const request = options.fetch ?? globalThis.fetch.bind(globalThis);
  const now = () => {
    const time = (options.now ?? Date.now)();
    if (!Number.isFinite(time))
      throw new BrowserOidcSessionError(
        "invalid-options",
        "The session clock must return finite milliseconds.",
      );
    return time;
  };
  let generation = 0;
  let disposed = false;
  let controller: AbortController | undefined;
  let pending: Promise<BrowserOidcSessionResult> | undefined;
  let current: Extract<BrowserOidcSessionResult, { status: "authenticated" }> | undefined;
  let redirecting = false;

  const assertLive = () => {
    if (disposed)
      throw new BrowserOidcSessionError("disposed", "The browser OIDC session is disposed.");
  };
  const storage = <T>(
    action: (store: Pick<Storage, "getItem" | "setItem" | "removeItem">) => T,
  ): T => {
    try {
      return action(options.transactionStorage ?? window.sessionStorage);
    } catch (cause) {
      throw new BrowserOidcSessionError(
        "storage-unavailable",
        "Redirect transaction storage is unavailable; supply an application-owned transaction store.",
        { cause },
      );
    }
  };
  const replace = () => {
    generation += 1;
    const previous = controller;
    controller = undefined;
    pending = undefined;
    current = undefined;
    redirecting = false;
    previous?.abort();
  };
  const begin = (redirectUri: string) => {
    assertLive();
    replace();
    const ownedGeneration = generation;
    const ownedController = new AbortController();
    controller = ownedController;
    const check = () => {
      if (disposed || generation !== ownedGeneration || ownedController.signal.aborted) {
        throw new BrowserOidcSessionError(
          "cancelled",
          "The browser OIDC operation no longer owns this session.",
        );
      }
    };
    const client = createOidcClient({
      issuer: options.issuer,
      clientId: options.clientId,
      redirectUri,
      scopes: options.scopes,
      authorizationParams,
      fetch: (input, init) =>
        request(input, {
          ...init,
          signal: init?.signal
            ? AbortSignal.any([init.signal, ownedController.signal])
            : ownedController.signal,
        }),
    });
    return { check, client, signal: ownedController.signal };
  };
  const accept = (
    result: OidcCodeExchangeResult,
    exchangeStartedAt: number,
  ): BrowserOidcSessionResult => {
    const { access_token, token_type, expires_in } = result.tokens;
    if (
      typeof access_token !== "string" ||
      !access_token ||
      typeof token_type !== "string" ||
      token_type.toLowerCase() !== "bearer" ||
      typeof expires_in !== "number" ||
      !Number.isFinite(expires_in) ||
      expires_in <= 0
    ) {
      throw new BrowserOidcSessionError(
        "invalid-token-response",
        "Session access tokens require Bearer token_type and a positive finite expires_in.",
      );
    }
    const expiresAt = exchangeStartedAt + expires_in * 1000;
    if (!Number.isFinite(expiresAt) || expiresAt <= now())
      throw new BrowserOidcSessionError(
        "invalid-token-response",
        "Access-token expiry overflowed or elapsed during validation.",
      );
    current = {
      status: "authenticated",
      principal: result.principal,
      accessToken: access_token,
      expiresAt,
    };
    return { ...current, principal: { ...current.principal } };
  };
  const authorize = (response: BrowserAuthorizationResponse) => {
    if (!response.error) return undefined;
    if (interactionErrors.has(response.error)) {
      return {
        status: "interaction-required" as const,
        error: response.error,
        description: response.error_description,
      };
    }
    throw new BrowserOidcSessionError(
      "authorization-error",
      `OIDC authorization failed: ${response.error}.`,
    );
  };
  const own = (
    operation: ReturnType<typeof begin>,
    run: () => Promise<BrowserOidcSessionResult>,
  ) => {
    const work = run()
      .catch((error: unknown) => {
        operation.check();
        throw error;
      })
      .finally(() => {
        if (pending === work) {
          pending = undefined;
          controller = undefined;
        }
      });
    pending = work;
    return work;
  };

  const session: BrowserOidcSession = {
    async login() {
      const operation = begin(redirect.href);
      redirecting = true;
      storage((store) => store.removeItem(key));
      try {
        const authorization = await operation.client.createAuthorizationRequest();
        operation.check();
        const time = now();
        const transaction: Transaction = {
          request: {
            state: authorization.state,
            nonce: authorization.nonce,
            codeVerifier: authorization.codeVerifier,
          },
          createdAt: time,
          expiresAt: time + ttl,
        };
        storage((store) => store.setItem(key, JSON.stringify(transaction)));
        return authorization.url;
      } catch (error) {
        operation.check();
        throw error;
      }
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
      if (
        !url.searchParams.has("code") &&
        !url.searchParams.has("error") &&
        !url.searchParams.has("state")
      )
        return session.getToken();
      const operation = begin(redirect.href);
      return own(operation, async () => {
        if (
          url.origin !== redirect.origin ||
          url.pathname !== redirect.pathname ||
          url.hash ||
          ["state", "code", "error"].some((name) => url.searchParams.getAll(name).length > 1)
        ) {
          throw new BrowserOidcSessionError(
            "invalid-callback",
            "OIDC callback URL does not match the registered query-mode redirect.",
          );
        }
        const encoded = storage((store) => {
          const value = store.getItem(key);
          store.removeItem(key);
          return value;
        });
        let transaction: Transaction;
        try {
          transaction = JSON.parse(encoded ?? "null") as Transaction;
        } catch (cause) {
          throw new BrowserOidcSessionError(
            "invalid-transaction",
            "OIDC redirect transaction is malformed.",
            { cause },
          );
        }
        if (
          !transaction ||
          !transaction.request ||
          ![
            transaction.request.state,
            transaction.request.nonce,
            transaction.request.codeVerifier,
          ].every((value) => typeof value === "string" && value.length > 0) ||
          !Number.isFinite(transaction.createdAt) ||
          !Number.isFinite(transaction.expiresAt) ||
          transaction.expiresAt - transaction.createdAt <= 0 ||
          transaction.expiresAt - transaction.createdAt > ttl ||
          now() < transaction.createdAt ||
          url.searchParams.get("state") !== transaction.request.state
        ) {
          throw new BrowserOidcSessionError(
            "invalid-transaction",
            "OIDC callback requires a matching, unused redirect transaction.",
          );
        }
        if (now() >= transaction.expiresAt)
          throw new BrowserOidcSessionError(
            "expired-transaction",
            "OIDC redirect transaction expired; begin a new login.",
          );
        const code = url.searchParams.get("code") ?? undefined;
        const error = url.searchParams.get("error") ?? undefined;
        if ((!code && !error) || (code && error))
          throw new BrowserOidcSessionError(
            "invalid-callback",
            "OIDC callback requires exactly one code or error.",
          );
        const interaction = authorize({
          state: transaction.request.state,
          code,
          error,
          error_description: url.searchParams.get("error_description") ?? undefined,
        });
        if (interaction) return interaction;
        const exchangeStartedAt = now();
        const result = await operation.client.exchangeCode({
          code: code!,
          state: transaction.request.state,
          request: transaction.request,
        });
        operation.check();
        return accept(result, exchangeStartedAt);
      });
    },
    getToken() {
      assertLive();
      if (redirecting)
        return Promise.resolve({ status: "interaction-required", error: "login_required" });
      if (current && now() + leeway < current.expiresAt)
        return Promise.resolve({ ...current, principal: { ...current.principal } });
      if (pending) return pending;
      if (!options.silent) {
        current = undefined;
        return Promise.resolve({ status: "interaction-required", error: "login_required" });
      }
      const operation = begin(silentRedirect.href);
      return own(operation, async () => {
        const authorization = await operation.client.createAuthorizationRequest();
        operation.check();
        const response = await authorizeWithWebMessage(
          authorization,
          timeout,
          operation.signal,
          responseFormat,
        );
        operation.check();
        const interaction = authorize(response);
        if (interaction) return interaction;
        const exchangeStartedAt = now();
        const result = await operation.client.exchangeCode({
          code: response.code!,
          state: response.state,
          request: authorization,
        });
        operation.check();
        return accept(result, exchangeStartedAt);
      });
    },
    logout() {
      assertLive();
      replace();
      storage((store) => store.removeItem(key));
    },
    dispose() {
      if (disposed) return;
      disposed = true;
      replace();
      storage((store) => store.removeItem(key));
    },
  };
  return session;
}
