# @askrjs/auth

[![CI](https://github.com/askrjs/askr-auth/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/askrjs/askr-auth/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/%40askrjs%2Fauth.svg)](https://www.npmjs.com/package/@askrjs/auth)

Shared authentication contracts, JWT and OIDC primitives, and request authentication resolution for Askr.

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
