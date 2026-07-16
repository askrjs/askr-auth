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

export function requireUser(): AuthRequirement {
  return (context) => authenticated(context) ?? allowed;
}

export function requireAnonymous(): AuthRequirement {
  return (context) => (context.authenticated ? denied("already_authenticated") : allowed);
}

function includes(value: unknown, expected: string): boolean {
  return Array.isArray(value) && value.includes(expected);
}

export function requireScope(scope: string): AuthRequirement {
  return (context) =>
    authenticated(context) ?? (includes(context.scopes, scope) ? allowed : denied("forbidden"));
}

export function requireRole(role: string): AuthRequirement {
  return (context) =>
    authenticated(context) ??
    (includes(context.principal?.roles, role) ? allowed : denied("forbidden"));
}

export function requirePermission(permission: string): AuthRequirement {
  return (context) =>
    authenticated(context) ??
    (includes(context.principal?.permissions, permission) ? allowed : denied("forbidden"));
}

export function allOf(...requirements: readonly AuthRequirement[]): AuthRequirement {
  return async (context) => {
    for (const requirement of requirements) {
      const decision = await requirement(context);
      if (!decision.allowed) return decision;
    }
    return allowed;
  };
}

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
