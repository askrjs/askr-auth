# Optional Auth0 SDK sessions

Install the SDK explicitly when choosing this adapter:

```sh
npm install @askrjs/auth @auth0/auth0-spa-js@^2.28.3
```

```ts
import { createAuth0Session } from "@askrjs/auth/auth0";

const session = createAuth0Session({
  domain: "tenant.auth0.com",
  clientId: "registered-public-client",
  redirectUri: `${location.origin}/callback`,
  authorizationParams: { audience: "https://api.example.com", organization: "org_example" },
});
const result = await session.restore();
// On an application login control:
location.assign(await session.login());
// Before an API request:
const current = await session.getToken();
// Local sign-out and permanent teardown:
session.logout();
session.dispose();
```

The adapter returns the existing `BrowserOidcSession` contract. Import its result,
error and session types from `@askrjs/auth/browser`; no duplicate contract aliases
are added. Application code owns navigation, URL cleanup after callback, login UI,
provider logout, API authorization and durable user/policy data. The runnable
[framework-neutral example](../examples/auth0-session/README.md) contains no
application token timers, transaction store or renewal coordinator.

## SDK ownership and configuration

The official SDK owns PKCE, redirect transaction storage/correlation, token
requests, token caching, concurrency locks, identity-claim handling and renewal.
The adapter uses `Auth0Client` directly, a fresh SDK `InMemoryCache` per local
identity, and the SDK's public cache interface to return the original absolute
access-token expiry. Repeated cache hits do not add `expires_in` to the current
clock. SDK 2.28.3 renews access tokens within its 60-second lead window;
`leewaySeconds` instead configures SDK ID-token claim clock skew (default 60,
greater than zero and at most 300 seconds). `authorizationTimeoutSeconds` controls SDK iframe waits
(default 15, greater than zero and at most 120 seconds).

`domain` accepts an HTTPS tenant/custom-domain URL or hostname. Optional `issuer`
selects the explicit HTTPS ID-token issuer. `redirectUri` is an absolute HTTP(S)
query-mode callback with no credentials, query or fragment. `scopes` defaults to
openid/profile/email; the SDK always includes openid. `loginHint` is a dedicated
bounded string. `authorizationParams` uses the same bounded extension bag as the
[native client](browser-session.md#provider-parameters-and-auth0-messages), including
such provider values as audience, organization, connection or prompt. Protocol
state/nonce/PKCE, client, redirect, scope, response mode and login hint cannot be
overridden through that bag. Silent SDK requests own `prompt=none`.

Refresh tokens are disabled by default. `useRefreshTokens: true` explicitly opts
into SDK refresh-token renewal, requesting offline access; tokens remain in the
owner's memory cache and disappear on reload. `useRefreshTokensFallback: true`
requires that opt-in and permits SDK iframe fallback. The adapter deliberately
uses an SDK cache instance rather than the SDK's worker cache: there is no worker
or persistent-token option here. An empty refresh cache without fallback fails
with the SDK's `missing_refresh_token` cause; the app can offer a fresh login.
Custom caches, localStorage token persistence, client secrets, popup orchestration
and unrelated SDK options are not accepted. See the
[SDK options reference](https://auth0.github.io/auth0-spa-js/interfaces/Auth0ClientOptions.html)
for the broader SDK contract.

SDK redirect transactions use sessionStorage and its tab/session lifetime. SDK
2.28.3 does not enforce a local transaction age in this storage mode; the
provider owns authorization-code expiry. SDK cookies record authentication and organization hints;
they are not access/ID/refresh tokens. App token results remain memory-only.
One live adapter should own a given client ID in a browser document: the SDK's
transaction key and concurrency locks are client-scoped. Independent applications
should use separate registered clients when independent ownership is required.

## Validation boundary

This adapter delegates identity-token handling to the installed SDK. For the
qualified SDK 2.28.3, source and real integration tests establish issuer, audience,
subject, nonce, RS256 algorithm label, authorized-party checks for multiple audiences and time-claim checks.
A zero leeway is rejected because the qualified SDK treats zero as its default rather than zero skew. Its [`jwt.verify`](https://github.com/auth0/auth0-spa-js/blob/d72b71d4d7641c501ab710968c3b8bdbbef033cf/src/jwt.ts)
decodes and checks claims; it does **not** fetch JWKS or cryptographically verify
the signature. Do not describe this path as Askr's native JOSE verification.
The native `@askrjs/auth/oidc` and `@askrjs/auth/browser` paths retain their own
ID-token signature/JWKS validation and do not require the SDK.

The SDK also owns iframe message acceptance and cleanup, which differs from the
native exact-iframe-window checks. The adapter does not insert a second message
parser, transaction format or token-validation engine around the SDK. Its
`Principal` copies the validated SDK subject and standard display claims only;
roles, permissions and application claim translation stay application-owned.
Resource servers must validate API access tokens under their own audience/policy.

## Lifecycle and recovery

`login()` returns the SDK authorization URL and retires the old local identity.
`restore()` consumes a query-mode callback through the SDK or requests a token.
Concurrent `getToken()` during callback restoration shares its result. Callback
replay/state errors remain `invalid-transaction` with the SDK error in `cause`.
Only login_required, consent_required, interaction_required and
account_selection_required become the typed interaction result. Provider denials,
claim failures and SDK operational failures remain `authorization-error` with
`cause`; missing or uncorrelated SDK cache/token data is `invalid-token-response`.

Logout, disposal and replacement login promptly settle pending Askr calls as
`cancelled`, even when SDK network work cannot be aborted. Each owner has a fresh
memory cache; late SDK results cannot publish identity into a new owner, and the
retired cache is cleared again after late completion. SDK iframe/network cleanup
still follows SDK timeout/completion. Disposal is terminal; logout permits a new
login or silent token request. Local logout rejects callbacks on that object until
a new login. SDK logout does not erase its redirect transaction storage, so the
adapter makes no cross-reload cancellation promise for an already-issued callback.
Redirect-preparation writes are ordered so a retired pending SDK PKCE preparation
cannot overwrite the next login's SDK transaction; token renewal stays SDK-owned.

Local logout calls SDK logout with navigation disabled. It does not end the
provider's cookie session or revoke issued tokens. Privacy restrictions, blocked
third-party cookies, CSP or a missing provider session may require interactive
login. Never retry interaction errors indefinitely. Configure Auth0 Allowed
Callback URLs, Allowed Web Origins, HTTPS, public application settings and API
permissions according to the [SDK guide](https://auth0.com/docs/libraries/auth0-single-page-app-sdk).

## Qualification boundary

Tests normally install the packed Auth package and SDK 2.28.3. Chromium, Firefox
and WebKit exercise signed simulated provider artifacts, SDK callback/state/replay
and claim failures, real iframe renewal, concurrent expiry requests, pending
callback/renewal retirement, delayed PKCE preparation and the standalone SPA.
Native/server imports and strict TypeScript 6/7 declarations also run with the
optional SDK absent. These are simulated-provider acceptance tests, not a live
Auth0 tenant qualification or certification of every compatible SDK version.
