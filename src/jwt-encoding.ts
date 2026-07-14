import { JwtValidationError } from "./jwt-error";

export function decodeBase64Url(value: string): string {
  try {
    const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
    return atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="));
  } catch {
    throw new JwtValidationError("malformed_token", "JWT contains invalid base64url data.");
  }
}

export function decodeJson(value: string): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(decodeBase64Url(value));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error();
    return parsed as Record<string, unknown>;
  } catch {
    throw new JwtValidationError("malformed_token", "JWT contains invalid JSON.");
  }
}
