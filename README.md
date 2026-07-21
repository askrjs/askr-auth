# @askrjs/auth

[![CI](https://github.com/askrjs/askr-auth/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/askrjs/askr-auth/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/%40askrjs%2Fauth.svg)](https://www.npmjs.com/package/@askrjs/auth)

Framework-owned, domain-neutral authentication primitives for Askr. Requires Node.js 22 or newer.

## Feature matrix

| Entry | Owns | Does not own |
| --- | --- | --- |
| `@askrjs/auth` | `Principal`, auth contexts and requirements, bearer/cookie/session request resolution | Users, organizations, credential storage, password hashing |
| `@askrjs/auth/jwt` | RS256/ES256 issuance and validation, claims, JWKS rollover | Token persistence or revocation lists |
| `@askrjs/auth/oidc` | Discovery, authorization-code PKCE, callback correlation, verified ID-token-to-`Principal` exchange | Provider UI, account linking, refresh-token storage |
| `@askrjs/auth/saml` | SP metadata and requests, signed/encrypted response validation, request correlation | IdP operation, SLO, IdP-initiated SAML, external CA trust policy |
| `@askrjs/auth/mfa` | TOTP, bounded CBOR/COSE, WebAuthn registration and authentication verification | Credential storage, recovery policy, enrollment UI |

Replay prevention stays with the application’s durable storage boundary. SAML requires atomic
`requestStore.consume()`. TOTP returns the accepted counter so it can be atomically marked used.
WebAuthn returns the verified new signature counter so it can be atomically persisted.

## OIDC

`exchangeCode()` accepts the callback and the stored authorization request separately. It checks
state before network access, then validates the required ID token against discovery and JWKS before
returning `{ tokens, principal }`.

```ts
import { createOidcClient } from "@askrjs/auth/oidc";

const client = createOidcClient({ issuer, clientId, clientSecret, redirectUri });
const request = await client.createAuthorizationRequest();
const result = await client.exchangeCode({ code: callback.code, state: callback.state, request });
```

## MFA

```ts
import { generateTotpSecret, verifyTotpCode } from "@askrjs/auth/mfa";

const secret = generateTotpSecret();
const result = await verifyTotpCode({ secret, code });
if (result.valid) await counters.consume(result.counter); // application-owned atomic replay guard
```

TOTP defaults to SHA-1, six digits, 30-second periods, and a one-step window. SHA-256, SHA-512,
and eight-digit codes are supported. WebAuthn uses exact base64url challenges, exact origin
allowlists, one RP ID, and user verification by default. It accepts ES256, RS256 (RSA 2048-bit or
larger), and EdDSA/Ed25519 keys. Registration accepts `none` and cryptographically verified packed
self-attestation only; certificate-backed attestation is deliberately rejected.

## SAML

The server-only `@askrjs/auth/saml` entrypoint provides a narrow SP-initiated SAML 2.0 flow:
metadata generation, signed or unsigned HTTP-Redirect AuthnRequests, signed assertion validation,
optional signed responses, encrypted assertions, request correlation, and atomic replay protection.
It is intentionally separate from `createAuth()` and the package root.

```ts
import { createSamlServiceProvider } from "@askrjs/auth/saml";

const saml = createSamlServiceProvider({
  entityId: "https://app.example.com/saml/metadata",
  acsUrl: "https://app.example.com/saml/acs",
  idp: { entityId: "https://idp.example.com", ssoUrl: "https://idp.example.com/sso", certificates: [idpCertificate] },
  requestStore, // save/get plus an atomic consume operation
});

const { url } = await saml.createAuthnRequest({ relayState: "return-to" });
const principal = await saml.validateResponse({ samlResponse, relayState: "return-to" });
```

The request store is a security boundary: `consume(id)` must atomically return `false` for a
missing, expired, or previously consumed ID. The validator defaults to a 10-minute request TTL,
a five-minute assertion age, and 60 seconds of clock skew. Assertions are always signed;
`requireSignedResponse` additionally requires the outer response signature.

JWT issuance and validation support RS256 with RSA keys and ES256 with EC P-256 keys. A JWK's
`alg` may be omitted and inferred from its key shape; when present, it must match the key.

## Install

```sh
npm install @askrjs/auth
```
