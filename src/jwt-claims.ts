import { JwtValidationError } from "./jwt-error";
import type { Principal } from "./model";

export function claimTime(value: unknown, name: string): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isFinite(value)) throw new JwtValidationError("invalid_claim", `JWT ${name} claim must be a number.`);
  return value;
}

export function audienceMatches(value: unknown, expected: string | readonly string[]): boolean {
  const actual = typeof value === "string" ? [value] : Array.isArray(value) && value.every((entry) => typeof entry === "string") ? value : [];
  const required = typeof expected === "string" ? [expected] : expected;
  return required.some((entry) => actual.includes(entry));
}

export function normalizePrincipal(payload: Record<string, unknown>): Principal {
  if (typeof payload.sub !== "string" || payload.sub.length === 0) throw new JwtValidationError("invalid_claim", "JWT sub claim is required.");
  const roles = Array.isArray(payload.roles) ? payload.roles.filter((value): value is string => typeof value === "string") : undefined;
  const permissions = Array.isArray(payload.permissions) ? payload.permissions.filter((value): value is string => typeof value === "string") : undefined;
  return { ...payload, id: payload.sub, subject: payload.sub, ...(roles ? { roles } : {}), ...(permissions ? { permissions } : {}) };
}
