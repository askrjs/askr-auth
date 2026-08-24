import type { JwtValidator } from "./jwt";
import type { AuthContext, AuthSession, Principal } from "./model";

/** Resolves a persisted session by its identifier. */
export interface SessionStore<S extends AuthSession = AuthSession> {
  /** Return the session, or null when it does not exist. */
  /** Load a session by identifier. @param id Session identifier. @param options Request context and cancellation signal. @returns The matching session or null. */
  get(
    id: string,
    options?: { request: Request; signal: AbortSignal },
  ): S | null | PromiseLike<S | null>;
}
/** Resolves an authenticated principal by subject. */
export interface PrincipalStore<P extends Principal = Principal> {
  /** Return the principal, or null when it does not exist. */
  /** Load a principal by subject. @param subject Principal subject. @param options Request context and cancellation signal. @returns The matching principal or null. */
  get(
    subject: string,
    options?: { request: Request; signal: AbortSignal },
  ): P | null | PromiseLike<P | null>;
}
/** Supplies the tenant identifier for an incoming request. */
export type TenantResolver =
  | string
  | ((
      request: Request,
      options: { signal: AbortSignal },
    ) => string | null | PromiseLike<string | null>);
/** Dependencies and policies used by the request authentication resolver. */
export interface AuthOptions<P extends Principal = Principal, S extends AuthSession = AuthSession> {
  /** Session lookup implementation. */
  sessions?: SessionStore<S>;
  /** Principal lookup implementation. */
  principals?: PrincipalStore<P>;
  /** Validator for bearer JWTs. */
  jwt?: JwtValidator<P>;
  /** Optional cookie name and validator for browser sessions. */
  jwtCookie?: { name: string; validator: JwtValidator<P> };
  /** Resolves the tenant associated with a request. */
  tenant?: TenantResolver;
  /** Cookie name used to identify a session. */
  sessionCookie?: string;
  /** Clock returning Unix time in milliseconds. */
  clock?: () => number;
}
/** Resolves authentication context from an incoming request. */
export interface AuthResolver<
  P extends Principal = Principal,
  S extends AuthSession = AuthSession,
> {
  /**
   * Resolve the principal, session, tenant, and authorization state.
   * Invalid bearer and cookie JWTs fall through as unauthenticated; tenant and store failures propagate.
   * @param request Incoming request.
   * @param options Optional cancellation signal.
   * @returns Resolved authentication context.
   */
  resolve(request: Request, options?: { signal?: AbortSignal }): Promise<AuthContext<P, S>>;
}
