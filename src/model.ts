export type Claim = Record<string, unknown>;

export interface Principal extends Claim {
  id: string;
  subject?: string;
  roles?: readonly string[];
  permissions?: readonly string[];
}

export interface AuthSession extends Claim {
  id: string;
  subject: string;
  expiresAt?: number;
  revokedAt?: number;
}

export interface AuthContext<P extends Principal = Principal, S extends AuthSession = AuthSession> {
  authenticated: boolean;
  principal: P | null;
  session: S | null;
  tenant: string | null;
  scopes?: readonly string[];
}

export type AuthDecision =
  | { allowed: true }
  | {
      allowed: false;
      reason: "unauthenticated" | "forbidden" | "already_authenticated";
    };

export type AuthRequirement<P extends Principal = Principal, S extends AuthSession = AuthSession> =
  (context: AuthContext<P, S>) => AuthDecision | PromiseLike<AuthDecision>;
