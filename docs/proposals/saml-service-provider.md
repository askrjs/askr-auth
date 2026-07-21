# Feature request: SAML Service Provider support

## Summary

Add SAML 2.0 Service Provider (SP) support to `@askrjs/auth` — validating an inbound SAML
assertion from a third-party Identity Provider (IdP) and resolving it to a `Principal`, the same
role `oidc-client.ts` already plays for OIDC relying-party flows.

## Motivation

Enterprise integration partners keep asking for SAML SSO: their employees sign in through their
own corporate IdP (Okta, Azure AD, ADFS, PingFederate, etc.) rather than a password/passkey/TOTP
flow owned by the app. This is consistently a SAML *Service Provider* need — consuming an
assertion an external IdP issued — not a request for this library (or any consumer) to act as a
SAML IdP itself. IdP-side SAML is out of scope for this proposal.

Consumers (e.g. `puma-auth`) are intentionally kept free of dependencies beyond `puma-fx`/`@askrjs/*`
and hand-roll what they reasonably can (TOTP, WebAuthn/passkey assertion verification) against
`node:crypto`/Web Crypto alone. SAML doesn't fit that pattern — see "Security considerations"
below — so this needs to land as a first-class `@askrjs/auth` capability rather than get
hand-rolled per consumer.

## Proposed shape

Mirror the existing OIDC module split (`oidc-types.ts` / `oidc-crypto.ts` / `oidc-discovery.ts` /
`oidc-token.ts` / `oidc-client.ts` / `oidc.ts` barrel) and the `@askrjs/auth/jwt` /
`@askrjs/auth/oidc` subpath convention:

```
src/
  saml-types.ts       # SamlServiceProviderOptions, SamlAssertion, SamlAttribute, etc.
  saml-metadata.ts     # generate this SP's own metadata XML (entityId, ACS URL, certs)
  saml-request.ts      # build a signed/unsigned AuthnRequest + redirect-binding URL
  saml-response.ts      # parse a SAMLResponse (base64 + inflate for redirect binding, or POST binding)
  saml-crypto.ts       # XML-DSig signature verification, XML canonicalization, decryption
  saml-client.ts       # createSamlServiceProvider(options) -> { metadata(), createAuthnRequest(), validateResponse() }
  saml.ts              # barrel: export * from "./saml-client"; export * from "./saml-types";
```

Public surface, mirroring `createOidcClient`:

```ts
interface SamlServiceProviderOptions {
  entityId: string;
  acsUrl: string;
  idp: {
    entityId: string;
    ssoUrl: string;
    certificates: readonly string[]; // IdP signing cert(s), PEM — supports rollover
  };
  signRequests?: { privateKey: JsonWebKey; certificate: string };
  clock?: () => number;
  clockSkewSeconds?: number;
}

interface SamlServiceProvider {
  metadata(): string; // this SP's own SAML metadata XML, for the IdP's config screen
  createAuthnRequest(options?: { relayState?: string }): { url: string; requestId: string };
  validateResponse(samlResponse: string, options: { expectedRequestId?: string }): Promise<Principal>;
}

declare function createSamlServiceProvider(options: SamlServiceProviderOptions): SamlServiceProvider;
```

`validateResponse` is the load-bearing piece and should return a `Principal` the same way
`JwtValidator.validate`/`createOidcClient(...).exchangeCode` already do, so it slots into
`createAuth({ ... })` the same way JWT/OIDC do today.

## Security considerations (why this can't be hand-rolled per-consumer)

SAML's assertion format has a genuinely bad security history, distinct from "just another XML
format":

- **XML Signature Wrapping (XSW).** The classic SAML vulnerability class — an attacker
  restructures the XML so the *signed* assertion and the *processed* assertion are different
  nodes. Defending against it requires validating the signature over the exact node that's then
  read for claims, not "is there a valid signature somewhere in this document." This is easy to
  get subtly wrong.
- **XML canonicalization (C14N).** Signature verification depends on canonicalizing the signed
  subtree exactly per the XML-DSig spec before hashing; an incorrect/partial C14N implementation
  produces a validator that's either too strict (real IdPs fail) or unsafe (forged assertions
  pass).
- **Optional encrypted assertions (XML-Enc)** on top of signing, for IdPs that require it.
- **Replay protection** (`InResponseTo` matching the original `AuthnRequest` id, `NotBefore`/
  `NotOnOrAfter` conditions, one-time-use tracking) is part of the spec's actual security
  guarantee, not an optional extra.

This is a meaningfully larger, more failure-prone parsing/crypto surface than the WebAuthn
assertion verification already hand-rolled in `puma-auth` (a fixed-format binary structure, ES256
signature over two concatenated byte strings — no XML, no canonicalization, no wrapping-attack
class). Reusing a mature, audited XML-DSig/SAML implementation is the right call here rather than
extending the hand-roll-against-Web-Crypto pattern to XML.

## Resolved dependency and replay design

The implementation pins `xml-crypto@6.1.2`, `@xmldom/xmldom@0.8.13`, and
`xml-encryption@5.0.0`. `@askrjs/auth` owns protocol validation and reads claims only from the
exact canonical bytes returned by `xml-crypto.getSignedReferences()`.

SP-initiated requests are stored before redirect. Validation first looks up the signed
`SubjectConfirmationData.InResponseTo`, checks RelayState and every cryptographic/claim rule,
then calls the store's atomic `consume(id)`. Only the winning consume returns a principal, so two
concurrent validations cannot both succeed. IdP-initiated responses remain out of scope.

## Non-goals

- Acting as a SAML *Identity Provider* (issuing assertions to third-party SPs) — no current
  requester needs this.
- SAML Single Logout (SLO) — worth a follow-up once SP-initiated login is solid, not blocking.
- IdP-initiated flow (assertion arrives unprompted, no prior `AuthnRequest`) — likely needed
  eventually given how many enterprise IdPs default to it, but SP-initiated should land first.

## Consumer impact once available

`puma-auth`'s `identity` domain gains a "federated identity link" concept (a user record pointing
at `{idpEntityId, nameId}`, recorded only after `@askrjs/auth`'s SAML validator has already
verified the assertion — mirroring how `enrollPasskeyFactor` only ever receives an
already-verified credential, never raw ceremony bytes). `apps/app` gains an ACS endpoint and an SP
metadata endpoint that call `createSamlServiceProvider(...).validateResponse()` and dispatch a
command on success.
