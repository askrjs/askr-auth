# Apple server provider

Import `createAppleProvider` from `@askrjs/auth/providers/apple`. Register a Services ID and exact HTTPS callback in Sign in with Apple. The Node application owns private-key file loading and supplies a private P-256 JWK; the preset reads no environment variable or filesystem path.

```ts
import { createPrivateKey } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createAppleProvider } from "@askrjs/auth/providers/apple";

const apple = createAppleProvider({
  id: "apple",
  servicesId: process.env.APPLE_SERVICES_ID!,
  teamId: process.env.APPLE_TEAM_ID!,
  keyId: process.env.APPLE_KEY_ID!,
  privateKey: createPrivateKey(await readFile(process.env.APPLE_PRIVATE_KEY_PATH!)).export({
    format: "jwk",
  }),
});
```

Supply the definition to `createProviderSession` from `@askrjs/auth/server`, or the Server provider-mode app configuration. Origin, cookies, replay authority, callback routing and transport belong to the shared engine. Keep private keys, client secrets and provider tokens server-side. Team and key IDs are explicit ten-character uppercase alphanumeric strings. The client-secret factory signs ES256 with the configured key ID, Team ID issuer, Services ID subject and exact Apple audience. Its cache is bounded to five minutes with a safety margin; cancellation and backwards clock movement cannot publish or reuse a future-issued secret.

The preset uses fixed issuer `https://appleid.apple.com`, `form_post`, and identity scopes `openid`, `email`, `name`, advertised by current discovery. The transaction cookie is Secure/HttpOnly/SameSite=None so a correlated callback does not require a Lax app cookie. The engine consumes the encrypted transaction before reading the callback body or exchanging its code. Signature, issuer, audience, nonce, subject and expiry remain mandatory. Generated PKCE fields are retained. Apple discovery does not advertise PKCE methods, so these signed simulations do not establish live Apple PKCE acceptance.

Optional `onSignIn` observes only validated signed `email`, `email_verified` and `is_private_email` alongside the minimal ID/subject. Present booleans accept actual booleans or exact `"true"`/`"false"` strings. Apple's documented empty managed-account email is permitted. The separately typed `profileHint` contains bounded first/last names from the unsigned first-login `user` member. Treat names as untrusted application input; they do not authenticate a user. Missing later profile hints are normal. Neither these hook fields nor arbitrary JWT claims are persisted in the engine principal or exposed in resolve/SSR/SPA snapshots.

Set an appropriate absolute app session lifetime. The default eight-hour session expires before a daily check becomes due. For longer sessions, `resolve` verifies account validity at the exact 24-hour boundary through the existing refresh-family lock and authority CAS. Concurrent requests share the identity-owned check while each caller keeps its own cancellation. A validated refreshed ID token advances only the check timestamp and actual refresh family; app expiry stays fixed. A confirmed invalid grant retires the exact authority and returns typed login interaction; later resolves are anonymous. Transport/store uncertainty remains a distinct safe failure and does not resend a possibly consumed refresh grant. Logout, replacement, closure and app expiry fence late results.

Apple exposes no API bearer resource policy and no provider logout redirect. Local logout can separately request token revocation. Signed native HTTP tests verify protocol and ownership mechanics; live Apple registration, browser behavior, nonce/PKCE acceptance and account status remain pending.

See [Apple authorization](https://developer.apple.com/documentation/signinwithapplerestapi/request-an-authorization-to-the-sign-in-with-apple-server.), [token validation](https://developer.apple.com/documentation/signinwithapplerestapi/generate-and-validate-tokens), [daily account verification](https://developer.apple.com/documentation/signinwithapple/verifying-a-user), [ID-token claims](https://developer.apple.com/documentation/signinwithapplejs/authorizationi/id_token), and [current discovery](https://appleid.apple.com/.well-known/openid-configuration).
