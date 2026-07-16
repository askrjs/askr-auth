import type { JwtValidator } from "./jwt";
import type { AuthContext, AuthSession, Principal } from "./model";

export interface SessionStore<S extends AuthSession = AuthSession> {
  get(
    id: string,
    options?: { request: Request; signal: AbortSignal },
  ): S | null | PromiseLike<S | null>;
}
export interface PrincipalStore<P extends Principal = Principal> {
  get(
    subject: string,
    options?: { request: Request; signal: AbortSignal },
  ): P | null | PromiseLike<P | null>;
}
export type TenantResolver =
  | string
  | ((
      request: Request,
      options: { signal: AbortSignal },
    ) => string | null | PromiseLike<string | null>);
export interface AuthOptions<P extends Principal = Principal, S extends AuthSession = AuthSession> {
  sessions?: SessionStore<S>;
  principals?: PrincipalStore<P>;
  jwt?: JwtValidator<P>;
  jwtCookie?: { name: string; validator: JwtValidator<P> };
  tenant?: TenantResolver;
  sessionCookie?: string;
  clock?: () => number;
}
export interface AuthResolver<
  P extends Principal = Principal,
  S extends AuthSession = AuthSession,
> {
  resolve(request: Request, options?: { signal?: AbortSignal }): Promise<AuthContext<P, S>>;
}
