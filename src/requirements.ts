import type { AuthDecision, AuthRequirement } from "./model";

const allowed: AuthDecision = Object.freeze({ allowed: true });
const denied = (reason: Exclude<AuthDecision, { allowed: true }>["reason"]): AuthDecision => ({
  allowed: false,
  reason,
});

function authenticated(context: Parameters<AuthRequirement>[0]): AuthDecision | undefined {
  return context.authenticated && context.principal !== null
    ? undefined
    : denied("unauthenticated");
}

/** Require an authenticated principal. @returns A reusable authorization requirement. */
export function requireUser(): AuthRequirement {
  return (context) => authenticated(context) ?? allowed;
}

/** Require that the request is not already authenticated. @returns A reusable authorization requirement. */
export function requireAnonymous(): AuthRequirement {
  return (context) => (context.authenticated ? denied("already_authenticated") : allowed);
}

function includes(value: unknown, expected: string): boolean {
  return Array.isArray(value) && value.includes(expected);
}

/** Require an authenticated principal carrying a specific scope. @param scope Required scope. @returns A reusable authorization requirement. */
export function requireScope(scope: string): AuthRequirement {
  return (context) =>
    authenticated(context) ?? (includes(context.scopes, scope) ? allowed : denied("forbidden"));
}

/** Require an authenticated principal carrying a specific role. @param role Required role. @returns A reusable authorization requirement. */
export function requireRole(role: string): AuthRequirement {
  return (context) =>
    authenticated(context) ??
    (includes(context.principal?.roles, role) ? allowed : denied("forbidden"));
}

/** Require an authenticated principal carrying a specific permission. @param permission Required permission. @returns A reusable authorization requirement. */
export function requirePermission(permission: string): AuthRequirement {
  return (context) =>
    authenticated(context) ??
    (includes(context.principal?.permissions, permission) ? allowed : denied("forbidden"));
}

/** Combine requirements so every requirement must allow the request. @param requirements Requirements evaluated in order. @returns A requirement that requires every input to allow. */
export function allOf(...requirements: readonly AuthRequirement[]): AuthRequirement {
  return async (context) => {
    for (const requirement of requirements) {
      const decision = await requirement(context);
      if (!decision.allowed) return decision;
    }
    return allowed;
  };
}

/** Combine requirements so at least one requirement must allow the request. @param requirements Requirements evaluated in order. @returns A requirement that requires one input to allow. */
export function anyOf(...requirements: readonly AuthRequirement[]): AuthRequirement {
  return async (context) => {
    let denial: AuthDecision = denied("forbidden");
    for (const requirement of requirements) {
      const decision = await requirement(context);
      if (decision.allowed) return decision;
      denial = decision;
    }
    return denial;
  };
}
