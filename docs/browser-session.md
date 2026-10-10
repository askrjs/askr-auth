# Optional browser OIDC sessions

`@askrjs/auth/browser` exports `createBrowserOidcSession()` and its types/error
class. The independent protocol client remains in `@askrjs/auth/oidc`; server
entrypoints do not import DOM orchestration. Public clients never accept a secret.

```ts
import { createBrowserOidcSession } from "@askrjs/auth/browser";

const session = createBrowserOidcSession({
  issuer: "https://login.example.com",
  clientId: "spa-client",
  redirectUri: `${location.origin}/callback`,
  silent: { timeoutMs: 15_000 }, // Explicit provider web-message support.
});

const restored = await session.restore();
if (restored.status === "interaction-required") {
  // Show an application-owned login control.
}
// On login activation:
location.assign(await session.login());
// Before an API request:
const result = await session.getToken();
// On logout:
session.logout();
// On permanent teardown:
session.dispose();
```

`login()` replaces the local identity and returns the authorization URL. The app
owns navigation. Store no tokens: only state, nonce, PKCE verifier, and creation/
expiry timestamps survive in session storage under an issuer/client/redirect-
scoped key. `transactionStorage` can supply an app-owned synchronous store; it
must support atomic read/removal within one browser context. Login callbacks use
query parameters on the exact registered origin/path, with no fragment, duplicate
code/state/error values, or simultaneous code and error. A correlated transaction
is consumed before exchange, including provider error or signature failure. Its
default lifetime is five minutes (`transactionTtlMs`, maximum ten minutes).

After a reload, `restore()` consumes the callback if present, otherwise attempts
configured silent authorization. It does not deserialize identity or tokens from
storage. `getToken()` returns a fresh in-memory access token and validated
principal, or renews once for all concurrent callers. `expires_in` must be a
positive finite lifetime and token type must be Bearer. Freshness compares the
current clock with expiry, minus `clockLeewaySeconds` (default 30). Expiry is
conservatively measured from exchange start, so network/JWKS validation cannot
extend a token's lifetime; tokens already expired on completion are rejected. The optional
millisecond `now` clock controls access expiry and transactions; protocol ID-token
validation still uses its normal clock. ID/refresh tokens are discarded after
validation. The wrapper requests no offline access and does not use refresh tokens.

Silent authorization is disabled unless `silent` is configured. Supported
transport: an iframe authorization-code request with `prompt=none` and
`response_mode=web_message`. The provider must send a plain `{state, code}` or
`{state, error, error_description?}` object to `window.parent` at the application's
exact origin. Only messages from the authorization endpoint's exact origin,
the created iframe's window, and the generated state are accepted. Other messages
are ignored. The frame/listener is removed on success, provider error, abort or
timeout. `silent.redirectUri` may choose another registered path on the same
origin. The default frame timeout is 15 seconds, capped at two minutes.

`login_required`, `consent_required`, `interaction_required`, and
`account_selection_required` return the typed `interaction-required` result.
Other browser contract failures throw `BrowserOidcSessionError` with a stable
`code`; ID-token/exchange failures retain `OidcClientError`. Blocked storage,
expired/replayed correlation, timeout, cancellation, and disposal are explicit
failures. Handle these in application UI rather than retrying indefinitely.

Logout clears local ownership, aborts network/iframe work, and removes the pending
transaction. Disposal does the same and permanently rejects further use. A new
login/callback also replaces generation ownership; late provider results cannot
restore an old identity even if a fetch adapter ignores cancellation. Get-token
calls during interactive login require interaction until the callback is restored.
Do not dispose on navigation to the login provider: the redirect transaction must
remain available to the returning document.

Provider logout, token revocation, cookies, login routes, account linking,
permissions, API authorization, and non-web-message renewal transports belong to
the application/provider. Local logout alone does not end an IdP cookie session.
Third-party-cookie/privacy restrictions, CSP frame policy, or unsupported response
modes can prevent silent renewal; offer interactive login. See the runnable
[standalone SPA](../examples/browser-session/README.md).

## Provider parameters and Auth0 messages

`OidcClientOptions.authorizationParams`, also accepted by browser sessions, is a
snapshot of provider extension strings such as audience, organization, connection
and prompt. It accepts at most 32 own data properties, 64-character ASCII parameter
names, 2048-character values and 8192 total characters. Arrays, accessors, symbols,
non-string values and protocol-owned keys are rejected with
`OidcClientError("invalid-authorization-params")`. State, nonce, PKCE, client
credentials/ID, response type, redirect URI, scope, response mode and login hint
stay with dedicated options and generated transaction ownership. Silent requests
always replace an extension prompt with `none`.

The default silent format remains `flat`. For providers using Auth0 web messages,
select `silent: { responseFormat: "auth0" }` explicitly. The accepted payload is
`{ type: "authorization_response", response: { state, code } }`, or the same
nested response with an error. No format is guessed. Selection changes only the
payload envelope: exact provider origin, created iframe window, state, nonempty
exclusive code/error, timeout, cancellation and cleanup checks still apply.
ID tokens continue through native signature/JWKS verification.

For the optional official SDK path, use
[`createAuth0Session`](auth0-session.md) from `@askrjs/auth/auth0`; install its SDK
peer explicitly. The native browser/server paths remain independent of that SDK.
