/** Additional application-defined claims carried by an authenticated principal or session. */
export type Claim = Record<string, unknown>;

/** Stable identity and authorization attributes for a caller. */
export interface Principal extends Claim {
  /** Application-specific principal identifier. */
  id: string;
  /** External subject identifier, when supplied by an identity provider. */
  subject?: string;
  /** Roles granted to the principal. */
  roles?: readonly string[];
  /** Fine-grained permissions granted to the principal. */
  permissions?: readonly string[];
}

/** Persisted login session associated with a principal. */
export interface AuthSession extends Claim {
  /** Stable session identifier. */
  id: string;
  /** Subject owning the session. */
  subject: string;
  /** Expiration time as Unix milliseconds. */
  expiresAt?: number;
  /** Revocation time as Unix milliseconds. */
  revokedAt?: number;
}

/** Authentication state resolved for one request. */
export interface AuthContext<P extends Principal = Principal, S extends AuthSession = AuthSession> {
  /** Whether a valid principal was resolved. */
  authenticated: boolean;
  /** Resolved principal, or null for anonymous requests. */
  principal: P | null;
  /** Resolved session, or null when no session is active. */
  session: S | null;
  /** Resolved tenant identifier, or null when unavailable. */
  tenant: string | null;
  /** Optional scopes carried by the credential. */
  scopes?: readonly string[];
}

/** Result returned by an authorization requirement. */
export type AuthDecision =
  | { allowed: true }
  | {
      allowed: false;
      reason: "unauthenticated" | "forbidden" | "already_authenticated";
    };

/** Predicate that allows or rejects an authentication context. */
export type AuthRequirement<
  P extends Principal = Principal,
  S extends AuthSession = AuthSession,
> = (context: AuthContext<P, S>) => AuthDecision | PromiseLike<AuthDecision>;
