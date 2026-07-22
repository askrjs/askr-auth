# Feature request: a lower-level JWS signing primitive for non-Principal tokens

Status: implemented in `@askrjs/auth@0.0.6`.

## Summary

`createJwtIssuer`/`JwtIssuerOptions`/`JwtIssueInput` are built specifically for the end-user
`Principal` token profile: `subject` plus arbitrary non-reserved Principal claims, a fixed
`typ: "JWT"`, and a generated `jti`. That's the right shape for access tokens and session cookies,
but it's the wrong tool for a *different* token profile a consumer legitimately needs to
mint: a short-lived service-to-service credential with its own `typ`, a `jti`, and claims that
have nothing to do with a `Principal` (a `scope`, a `realm`, whatever the receiving system's
authorization model expects).

Add a lower-level, unopinionated JWS signing primitive alongside the existing `Principal`-shaped
issuer, so a second, deliberately distinct token profile doesn't require hand-rolling ES256 JWS
against `node:crypto` from scratch.

## Motivation

`puma-auth` needed to authenticate its own connection to its event store (Fitz) with a
short-lived, self-issued service JWT — a completely separate trust chain from the end-user OIDC
tokens it also issues via `@askrjs/auth/jwt`. The requirements: a distinct `typ` header (so a
service token can never be confused with an end-user token even if both are otherwise valid
JWS), a `jti`, and a `scope`/`realm` claim describing exactly what the token is authorized for —
none of which fit `JwtIssueInput`'s `Principal`-shaped `{subject, roles?, permissions?}`.

Rather than force this into `createJwtIssuer`, `puma-auth` wrote its own ~40-line ES256 JWS
issuer directly against `node:crypto`
(`createPrivateKey({key, format:"jwk"})` + `crypto.sign(null, data, {key, dsaEncoding:
"ieee-p1363"})` for JWS's raw r‖s signature requirement). That was a deliberate, scoped decision —
this is genuinely simple for a single algorithm and a small, fixed claim set — but it's exactly
the kind of small-crypto-surface duplication this library exists to prevent consumers from
needing to do themselves, and every other consumer with a similar service-identity bootstrap need
will hit the same gap and either duplicate the same code or get it subtly wrong (most likely by
using DER instead of the raw r‖s encoding JWS requires, or by leaving `typ` unset entirely).

## Proposed shape

A Web Crypto implementation is exported through `@askrjs/auth/jwt`:

```ts
interface JwtSignerOptions {
  privateKey: JsonWebKey;
  kid: string;
}

interface JwtSignInput {
  protectedHeader?: Record<string, unknown>;
  claims: Record<string, unknown>;
}

declare function createJwtSigner(options: JwtSignerOptions): JwtSigner;

/** Optional convenience — fills iss/iat/exp/jti so callers don't hand-roll `Date.now()` math and
 * `randomUUID()` themselves, while leaving `sub`/`aud`/`typ`/every other claim fully caller-owned. */
declare function issueTimedJwt(
  signer: JwtSigner,
  input: { issuer: string; subject: string; audience: string | readonly string[]; ttlSeconds: number; typ: string; claims?: Record<string, unknown> },
): Promise<string>;
```

The signer infers RS256 or ES256 from the private JWK and caches its imported key. It owns
`alg`/`kid` and rejects collisions plus unsupported `crit`/`b64`. The timed helper owns
`iss/sub/aud/iat/exp/jti`; domain claims such as `realm`, `scope`, and `nbf` remain caller-owned.
`createJwtIssuer` is implemented on this signer without changing its Principal contract. There is
no validator counterpart for the general signing primitive.

`createJwtIssuer` stays exactly as-is for the `Principal` profile — this is a new, parallel,
lower-level primitive, not a replacement or an extension of it. `JwtIssuer.validator`'s
`JwtValidator` doesn't need a counterpart here: whoever receives this profile of token (in
`puma-auth`'s case, the Fitz server) is a separate system this library isn't responsible for
validating against.

## Non-goals

- A general "arbitrary JWT" builder with no opinions at all — the goal is removing the *crypto*
  duplication (correct r‖s signature encoding, JWK→KeyObject import, base64url JWS assembly), not
  making every claim-shape decision for the caller.
- Validation/verification of this profile — out of scope, this is issuer-only, mirroring how
  `puma-auth`'s own `issueServiceJwt` has no matching validator either (the relying party is a
  different system).

## Consumer impact once available

`puma-auth`'s `packages/shared-kernel/src/service-jwt.ts` — currently ~40 lines of hand-rolled JWS
assembly — would shrink to a thin wrapper over `createJwsSigner`/`issueTimedJws`, keeping its own
`SERVICE_JWT_TYPE`/`AUTH_SERVICE_REALM`/scope-list domain logic but dropping the raw
`node:crypto` signing code entirely.
