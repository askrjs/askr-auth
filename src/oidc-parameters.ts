import { OidcClientError } from "./oidc-error";

const owned = new Set([
  "state",
  "nonce",
  "code_challenge",
  "code_challenge_method",
  "code_verifier",
  "client_id",
  "client_secret",
  "response_type",
  "redirect_uri",
  "scope",
  "response_mode",
  "login_hint",
]);

/** Snapshot extension configuration before asynchronous authorization starts. */
export function providerAuthorizationParams(input: unknown): Readonly<Record<string, string>> {
  if (input === undefined) return {};
  const fail = (): never => {
    throw new OidcClientError(
      "invalid-authorization-params",
      "Provider authorization parameters require at most 32 string entries, 64-character parameter names, 2048-character values and 8192 total characters; protocol-owned parameters cannot be overridden.",
    );
  };
  if (
    !input ||
    typeof input !== "object" ||
    (Object.getPrototypeOf(input) !== Object.prototype && Object.getPrototypeOf(input) !== null)
  )
    return fail();
  const keys = Reflect.ownKeys(input);
  if (keys.length > 32) fail();
  const result: Record<string, string> = Object.create(null);
  let total = 0;
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (
      typeof key !== "string" ||
      !/^[A-Za-z][A-Za-z0-9_.-]{0,63}$/u.test(key) ||
      owned.has(key.toLowerCase()) ||
      !descriptor ||
      !("value" in descriptor) ||
      typeof descriptor.value !== "string" ||
      descriptor.value.length > 2048
    )
      return fail();
    total += key.length + descriptor.value.length;
    if (total > 8192) fail();
    result[key] = descriptor.value;
  }
  return Object.freeze(result);
}
