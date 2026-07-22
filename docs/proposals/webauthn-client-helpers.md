# Feature request: browser-side WebAuthn ceremony helpers

Status: implemented in `@askrjs/auth@0.0.6` as the ESM-only
`@askrjs/auth/webauthn-client` subpath.

## Summary

`@askrjs/auth/mfa` provides the server-side half of a WebAuthn ceremony —
`verifyWebAuthnRegistration`/`verifyWebAuthnAuthentication`, taking raw `Uint8Array` fields
(`credentialId`, `clientDataJSON`, `attestationObject`/`authenticatorData`+`signature`) — but
nothing for the *browser* half: calling `navigator.credentials.create()`/`.get()` and converting
the resulting `ArrayBuffer` fields to/from the base64url strings that travel over the wire to the
server functions above. Every consumer has to hand-write this pairing themselves.

Add a small, dependency-free browser-side module with that pairing built in, so the base64url
encode/decode and the `navigator.credentials` call shape only need to be gotten right once, in
this library, rather than once per consuming app.

## Motivation

`puma-auth` built two WebAuthn HTTP ceremony pages (`apps/app/src/routes/webauthn-register.ts`,
`webauthn-authenticate.ts`) and, for each, hand-wrote:

- A vanilla-JS base64url ↔ `ArrayBuffer` pair (`b64uEncode`/`b64uDecode`), inlined as a `<script>`
  string since these pages have no build step of their own.
- The `navigator.credentials.create({publicKey: {...}})` / `.get({publicKey: {...}})` call itself,
  including the exact field names (`challenge`, `rp`, `user`, `pubKeyCredParams`,
  `authenticatorSelection`, `allowCredentials`, `rpId`) needed to line up with what
  `verifyWebAuthnRegistration`/`verifyWebAuthnAuthentication` expect back.

None of this is specific to `puma-auth` — it's the fixed, spec-defined shape of a WebAuthn
ceremony, and every consumer of the server-side verify functions will need exactly this pairing.
Shipping it once, next to the functions it's meant to pair with, means a consumer only has to
supply a challenge and a form to submit the result to — not re-derive the ceremony call shape and
its encoding boilerplate from the WebAuthn spec each time.

## Proposed shape

A new browser-safe subpath, e.g. `@askrjs/auth/webauthn-client` (no `node:crypto`, no server-only
imports — must be usable from a plain inline `<script>` or a bundled browser build):

```ts
declare function encodeBase64Url(buffer: ArrayBuffer): string;
declare function decodeBase64Url(value: string): ArrayBuffer;

interface CreatePasskeyOptions {
  challenge: string; // base64url
  rpId: string;
  rpName: string;
  userId: string; // base64url — the WebAuthn "user handle"
  userName: string;
  userDisplayName: string;
  userVerification?: UserVerificationRequirement; // default "required"
}
interface PasskeyRegistration {
  credentialId: string;
  clientDataJSON: string;
  attestationObject: string;
}
declare function createPasskey(options: CreatePasskeyOptions): Promise<PasskeyRegistration>;

interface GetPasskeyAssertionOptions {
  challenge: string; // base64url
  rpId: string;
  allowCredentials?: readonly string[]; // base64url credential ids; omit/empty for discoverable
  userVerification?: UserVerificationRequirement;
}
interface PasskeyAssertion {
  credentialId: string;
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
}
declare function getPasskeyAssertion(options: GetPasskeyAssertionOptions): Promise<PasskeyAssertion>;
```

Field names on `PasskeyRegistration`/`PasskeyAssertion` deliberately match
`WebAuthnRegistrationInput`/`WebAuthnAuthenticationInput`'s field names (minus the
server-context-only fields like `expectedChallenge`/`allowedOrigins`/`rpId`/`signCount`) so a
consumer's client→server payload can be forwarded close to as-is.

Registration requests `attestation: "none"`, a required discoverable credential, required user
verification, and algorithms in ES256, EdDSA, RS256 order. Authentication also requires user
verification and omits `allowCredentials` when the list is absent or empty. The strict codecs and
ceremony helpers use `TypeError` for malformed input, unavailable APIs, and wrong credential
shapes while preserving native WebAuthn `DOMException` rejections. The module has no evaluation-
time browser-global access and no Node-only dependency.

## Non-goals

- A full client-side "passkey manager" UI component — this is the encoding/call-shape primitive
  only, not a themed button or form component (that belongs in a themes/components package if it
  belongs anywhere in this ecosystem at all).
- Feature-detection/fallback UX (whether the browser supports WebAuthn, conditional UI/autofill) —
  a real concern, but a separate, larger piece of design than the encode/call-shape pairing this
  request is scoped to.

## Consumer impact once available

`puma-auth`'s `apps/app/src/webauthn/{base64url,client-script}.ts` — currently hand-rolled — would
be replaced by importing `@askrjs/auth/webauthn-client` directly in the inline `<script>` (via
whatever browser-bundle path this library already uses, if any, or copied as a small vendored
snippet if this library doesn't yet ship a browser bundle) instead of maintaining its own copy of
this encoding/ceremony-call logic.
