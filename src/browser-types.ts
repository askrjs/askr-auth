import type { Principal } from "./model";
import type { OidcClientOptions } from "./oidc-types";

/** Browser-only orchestration; confidential-client secrets are never accepted. */
export interface BrowserOidcSessionOptions extends Omit<OidcClientOptions, "clientSecret"> {
  /** Redirect transactions only. Defaults to sessionStorage; tokens stay in memory. */
  transactionStorage?: Pick<Storage, "getItem" | "setItem" | "removeItem">;
  /** Transaction lifetime in milliseconds, at most ten minutes. Defaults to five minutes. */
  transactionTtlMs?: number;
  /** Access-token expiry leeway in seconds. Defaults to 30. */
  clockLeewaySeconds?: number;
  /** Millisecond clock for transaction and access-token expiry. Defaults to Date.now. */
  now?: () => number;
  /** Explicitly enable provider web_message support. Disabled by default. */
  silent?:
    | false
    | {
        /** Registered redirect URI for silent authorization. Defaults to redirectUri. */
        redirectUri?: string;
        /** Bounded iframe response timeout; at most two minutes. Defaults to 15 seconds. */
        timeoutMs?: number;
        /** Explicit web-message envelope. Defaults to the generic flat response. */
        responseFormat?: "flat" | "auth0";
      };
}

/** Validated identity and an in-memory access token. ID/refresh tokens are discarded. */
export type BrowserOidcSessionResult =
  | { status: "authenticated"; principal: Principal; accessToken: string; expiresAt: number }
  | { status: "interaction-required"; error: string; description?: string };

/** Optional SPA session ownership around the independent OIDC protocol client. */
export interface BrowserOidcSession {
  /** Begin a replacement identity and return a URL for application-owned navigation. */
  login(): Promise<string>;
  /** Consume a query-mode redirect callback, or try configured silent restoration. */
  restore(callbackUrl?: string | URL): Promise<BrowserOidcSessionResult>;
  /** Reuse a fresh token, or share a single silent authorization when expired. */
  getToken(): Promise<BrowserOidcSessionResult>;
  /** Clear local identity and cancel work. Provider logout/navigation belongs to the app. */
  logout(): void;
  /** Cancel work and permanently retire this session. */
  dispose(): void;
}

export type BrowserOidcSessionErrorCode =
  | "invalid-options"
  | "invalid-callback"
  | "invalid-transaction"
  | "expired-transaction"
  | "storage-unavailable"
  | "authorization-error"
  | "invalid-token-response"
  | "silent-timeout"
  | "cancelled"
  | "disposed";

/** Failed browser-session contract; protocol validation keeps its OidcClientError. */
export class BrowserOidcSessionError extends Error {
  constructor(
    readonly code: BrowserOidcSessionErrorCode,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "BrowserOidcSessionError";
  }
}
