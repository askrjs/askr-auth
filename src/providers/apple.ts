import { defineProvider } from "../provider-definition";
import { configurationError, ProviderSessionError } from "../provider-session-error";
import { checkCancellation } from "../provider-session-storage";
import { createJwtSigner } from "../jwt-signer";
import { decodeBase64Url } from "../jwt-encoding";
import type { JwtSigner } from "../jwt-signer";
import type { ProviderDefinition } from "../provider-session-types";
import type { Principal } from "../model";

export interface AppleProviderOptions {
  readonly id: string;
  readonly servicesId: string;
  readonly teamId: string;
  readonly keyId: string;
  readonly privateKey: JsonWebKey;
}
const issuer = "https://appleid.apple.com";
function boundedText(value: unknown, limit: number): value is string {
  return typeof value === "string" && value.length <= limit && !/[\x00-\x1f\x7f]/u.test(value);
}
function signedView(claims: Principal, minimal: Principal): Principal {
  const view: Principal = { ...minimal };
  if (claims.email !== undefined) {
    if (!boundedText(claims.email, 1024)) throw new Error();
    view.email = claims.email;
  }
  for (const name of ["email_verified", "is_private_email"]) {
    const value = claims[name];
    if (value === undefined) continue;
    if (value !== true && value !== false && value !== "true" && value !== "false")
      throw new Error();
    view[name] = value === true || value === "true";
  }
  return Object.freeze(view);
}
function profileHint(user: string | null) {
  if (user === null) return undefined;
  try {
    if (new TextEncoder().encode(user).length > 4096) throw new Error();
    const parsed: unknown = JSON.parse(user);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error();
    const name = (parsed as Record<string, unknown>).name;
    if (name === undefined) return undefined;
    if (!name || typeof name !== "object" || Array.isArray(name)) throw new Error();
    const optionalName = (value: unknown) => {
      if (value === undefined) return undefined;
      if (!boundedText(value, 256)) throw new Error();
      return value;
    };
    const firstName = optionalName((name as Record<string, unknown>).firstName);
    const lastName = optionalName((name as Record<string, unknown>).lastName);
    if (firstName === undefined && lastName === undefined) return undefined;
    return Object.freeze({
      ...(firstName === undefined ? {} : { givenName: firstName }),
      ...(lastName === undefined ? {} : { familyName: lastName }),
    });
  } catch {
    throw new ProviderSessionError("invalid-callback");
  }
}
/** Confidential Apple Services ID with server-owned signing and daily account verification. */
export function createAppleProvider(options: AppleProviderOptions): ProviderDefinition {
  if (
    !options ||
    typeof options !== "object" ||
    Array.isArray(options) ||
    typeof options.servicesId !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/u.test(options.servicesId) ||
    typeof options.teamId !== "string" ||
    !/^[A-Z0-9]{10}$/u.test(options.teamId) ||
    typeof options.keyId !== "string" ||
    !/^[A-Z0-9]{10}$/u.test(options.keyId)
  )
    throw configurationError();
  const key = options.privateKey;
  if (
    !key ||
    typeof key !== "object" ||
    Array.isArray(key) ||
    key.kty !== "EC" ||
    key.crv !== "P-256" ||
    (key.alg !== undefined && key.alg !== "ES256") ||
    (key.use !== undefined && key.use !== "sig") ||
    (key.key_ops !== undefined &&
      (!Array.isArray(key.key_ops) || key.key_ops.length !== 1 || key.key_ops[0] !== "sign"))
  )
    throw configurationError();
  for (const value of [key.x, key.y, key.d]) {
    try {
      if (
        typeof value !== "string" ||
        !/^[A-Za-z0-9_-]{43}$/u.test(value) ||
        decodeBase64Url(value).length !== 32
      )
        throw new Error();
    } catch {
      throw configurationError();
    }
  }
  const ownedKey: JsonWebKey = Object.freeze({
    kty: "EC",
    crv: "P-256",
    x: key.x,
    y: key.y,
    d: key.d,
    alg: "ES256",
    use: "sig",
    key_ops: ["sign"],
  });
  const { id, servicesId, teamId, keyId } = options;
  let signer: JwtSigner | undefined;
  let cached: { token: string; issuedAt: number; expiresAt: number } | undefined;
  return defineProvider(
    {
      id,
      issuer,
      clientId: servicesId,
      responseMode: "form_post",
      clientAuthentication: {
        method: "client_secret_post",
        async secret({ now, signal }) {
          checkCancellation(signal);
          if (cached && now >= cached.issuedAt && now < cached.expiresAt - 30_000)
            return cached.token;
          // Defer asynchronous key import until an awaited operation owns its rejection.
          signer ??= createJwtSigner({ privateKey: ownedKey, kid: keyId });
          const issuedAt = Math.floor(now / 1000) * 1000;
          const expiresAt = issuedAt + 300_000;
          const token = await signer.sign({
            claims: {
              iss: teamId,
              sub: servicesId,
              aud: issuer,
              iat: issuedAt / 1000,
              exp: expiresAt / 1000,
            },
          });
          checkCancellation(signal);
          cached = { token, issuedAt, expiresAt };
          return token;
        },
      },
      identityScopes: ["openid", "email", "name"],
      capabilities: {
        renewal: "account-check",
        incrementalConsent: false,
        providerLogout: false,
        revocation: true,
        resources: [],
      },
    },
    {
      aliases: [issuer],
      version: JSON.stringify(["apple-1", teamId, keyId, ownedKey.x, ownedKey.y]),
      endpoints: {
        authorization: `${issuer}/auth/authorize`,
        token: `${issuer}/auth/token`,
        jwks: `${issuer}/auth/keys`,
        revocation: `${issuer}/auth/revoke`,
      },
      discoveryLogout: false,
      discoveryRevocation: false,
      authorizationResourceParameter: null,
      tokenScopePolicy: "apple",
      signInPrincipal: signedView,
      profileHint,
    },
  );
}
