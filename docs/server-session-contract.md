# Server provider sessions for 0.5.0

Proposed owner: `@askrjs/auth/server`. This document specifies the contract for
askr-auth#66 and gates provider implementations. It is the implementation contract; implementation and provider qualification
are tracked separately. It makes no runtime or live-provider qualification claim. Auth#64–71, Server#76, Core#777, CLI#185 and Examples#32 are
all in the maintainer-approved 0.5.0 scope. Publication remains held for full
maintainer review.

## Ownership and public shape

Auth owns confidential OIDC exchange, token validation, transaction correlation,
sealed session state, atomic retirement and token renewal. Server owns the
reserved `/auth` routes, Web transport, CSRF, safe redirects and typed problem
responses. Core owns the minimal client identity cache, route policies,
hydration continuity, cross-tab invalidation and private data retirement.
Applications own login UI, durable users, account linking and authorization.
No vendor SDK is required. Static hosting without a server is unsupported.

The API block below records the exact transport-facing method signatures. One `createProviderSession(options)` creates an authority and
implements the existing `AuthResolver.resolve`. It also supplies:

- `login(request, {provider, returnTo, resource?, scopes?}): Promise<Response>`;
- `callback(request, {provider}): Promise<Response>`;
- `logout(request, {provider?, providerLogout?, returnTo?, revoke?}): Promise<Response>`;
- `token(request, provider, {resource?, scopes, signal?}): Promise<string>`;
- `finalize(request, response): Promise<Response>` and `close(): Promise<void>`.

`origin` is an explicitly configured canonical HTTPS origin with no credentials,
path, query or fragment. It is never inferred from Host or forwarded headers.
Each provider has a unique conservative path-segment `id`. Its redirect URI is
exactly `${origin}/auth/callback/${id}`. An unsupported origin, duplicate provider,
unknown capability, invalid resource/scope policy, weakly encoded key or unsafe
post-logout destination fails at setup. Tests may inject fetch and a clock;
production transport still validates configured origins and endpoints. Synchronous
setup validates configuration, not a future discovery response: generic optional
providerLogout/revocation capabilities require their explicit endpoints. Presets
may declare their documented discovery operation, but a missing/malformed remote
endpoint fails safely as configuration before that operation, never as silent
local-only success or an interaction-required login/consent outcome.

`resolve` returns a constructed `AuthContext`, never the private session record
or provider token response. Its `session` is only `{id, subject, expiresAt}`.
Its public `principal` is a minimal identity keyed by issuer and subject, not
email and not arbitrary provider claims. The default browser snapshot contains
only `authenticated`, `principal: {id, subject?}`, `tenant` and normalized scopes;
`session` is omitted. `AuthContext.scopes` and snapshot scopes contain only the
current provider's confirmed identity/authentication scopes from the configured
identity policy (excluding offline_access); they never flatten API consent
grants, resource scopes or other providers. API authority is exclusively checked
by token(provider, {resource, scopes}). Equal scope names on different resources
cannot become interchangeable through requireScope or hydration. Provider mode
currently supports identity and those configured validated scopes only.
It does not resolve durable app users, roles or permissions; role/permission
predicates deny absent grants. Existing manual mode retains app-owned enriched
identity/policy. App-owned server policies/actions can consult their own domain
store. A generic `Principal` spread or an implicit serializer/enrichment hook is
not supported. A provider's
unsigned profile hint is not an authenticated claim. Optional server-only
`onSignIn` receives the validated principal plus a separately typed bounded
unsigned name hint. It lets applications persist first-login Apple profile data
without placing it in the public snapshot or treating it as verified identity.
The callback receives a signal and is fenced before/after await; app-owned side
effects must honor it. It cannot replace the principal, skip validation, or
return token/session state.

Provider definitions are branded, frozen shared-engine configuration. Only
`createOidcProvider` and the four presets produce valid definitions; copying or
spreading a definition loses its private policy ownership and is rejected at
setup. A private WeakMap binds each definition to issuer/claim/normalization
policies; no public callback can replace protocol validation. This policy
fingerprint is stable across workers, excludes secret values, and is checked
when loading a stored session; changed policy cannot reuse an old grant. Generic OIDC uses
one exact issuer; Google's two issuer spellings are preset-private and are
canonicalized to the configured HTTPS issuer for principal/cache identity.
Auth0 definitions without organization configuration reject unexpected org_id
or org_name claims. With an expected organization id/name, validate every
present corresponding claim; an org_name cannot be accepted based only on an
org_id match if its expected name was not configured. Require the expected name
when the provider returns one, rather than guessing it or treating an authorize
parameter as validation. Auth0's
organization id/name check, Google's hd check, and Apple's boolean normalization
and unsigned profile hint are private policies applied after the shared signed
ID-token validation. Keep generic low-level createOidcClient compatibility by
extending private helpers for response mode, secret factories, refresh, issuer
allowlists and claim checks; do not fork JWT validation or widen every caller's
trust. The factory is the demonstrated generic-OIDC entry, not an alias for a
preset. Trusted optional endpoint overrides are setup-only HTTPS URLs without
credentials/fragments; discovery issuer still must match. Provider fetches that
carry secrets/tokens reject redirects. Browser mocks intercept provider HTTP;
they do not add a production 'skip validation' switch.

Provider definitions are thin shared-engine configuration. They declare issuer,
client id/authentication, identity scopes, response mode, authorization extension
parameters and capabilities. Shared configuration includes explicit, bounded
issuer aliases/claim restrictions, resource-to-scope policy and endpoint options
where provider discovery does not advertise an operation. The default generic
OIDC validator remains exact-issuer. Google alone supplies its two documented
issuer spellings. Presets cannot replace signature/state/nonce validation.
Future client-authentication methods require a new discriminated method, not
an arbitrary string or a protocol-parameter override. A secret factory receives
only the operation signal and Unix-millisecond `now`; Apple's ES256 secret is
created server-side through the existing signer.

## Responses, request ownership and safe failures

Login and successful callback return a 303 redirect. Logout without provider
continuation returns 204; an explicitly requested supported provider logout may
return 303. Each method stages its cookie changes in engine-owned request state.
The host MUST call `finalize` as the last boundary for every response, including
errors and provider-route responses. `finalize` clones headers when necessary,
is idempotent for the same request/response ownership, and rechecks captured
identity epoch, record revision and engine lifetime before attaching pending
cookies. It preserves unrelated application Set-Cookie values and removes only
engine-owned stale issuance. It never slides absolute session expiry.

`ProviderSessionError` has safe codes `configuration`, `invalid-callback`,
`invalid-transaction`, `session-oversize`, `capacity`, `store-unavailable`, `provider-unavailable`, and
`closed`. The message identifies corrective action without input values.
`InteractionRequiredError` has `code: interaction-required`, `reason: login |
consent`, provider id, resource and required scopes. Server maps it to a 401
problem with those allowlisted fields. Configuration/capacity/store failures
remain distinct and are not mislabeled as login or consent. Invalid callback or
transaction is a bounded 400 failure with the transaction cookie cleared.

Never attach raw upstream response bodies, query/form input, tokens, secrets or
provider errors as an Error message, cause, enumerable property, log field or
problem detail. Internal diagnostics may record an operation, safe category and
HTTP status. Network/timeout/malformed upstream transport failures use a static
provider-unavailable error, distinct from store-unavailable; neither becomes
interaction-required. Caller cancellation uses a fixed-message AbortError.
Cancellation must settle callers promptly and cannot commit later.
The supplied request signal participates in provider fetch cancellation; joining
one renewal must not transfer ownership of the shared operation to a single
joining caller. `close` aborts this engine's pending work and forbids new work.
Closing a worker does not globally log out other workers using a shared store.

## Session storage and authority

The default is an AES-GCM encrypted `__Host-askr-session` cookie plus a bounded
in-process authority. It is NOT a stateless deployment mode. Cookie ciphertext
may contain the private envelope; page JavaScript never receives plaintext
tokens. In store mode, the cookie contains only an encrypted opaque locator and
identity epoch; the sealed private envelope lives in the configured store.
Both modes use the same state transitions and response finalizer.

Session keys are explicit base64url encodings of 32 cryptographically random
bytes, current first then previous keys. Use a new random 96-bit IV for every
AES-GCM seal, an explicit algorithm allow-list, a versioned envelope and AAD
binding its purpose, cookie name and configured application origin. Old keys
only decrypt; new writes use the current key. Tampered/unknown-key/expired
cookies resolve anonymously and cannot enroll their payload into authority.
The serialized cookie has a 3,800-byte UTF-8 budget including its attributes.
Oversize is a typed `session-oversize` error recommending a configured store,
not truncation or a fallback to unsigned storage. Session expiry defaults to
8 hours, measured from the successful code exchange start; cache hits and
renewal never move it forward. Session maxAgeSeconds is an integer 1..2,592,000 (30 days); leewaySeconds is
0..300 (default 30) and only shortens usable access-token life. maxEntries is an
integer 1..1,000,000. Secrets contain 1..4 keys. Transaction TTL is an integer
1..600. These are setup-validated bounds, not inferred entropy guarantees.

The authority retains the latest sealed payload, identity epoch, monotone
revision and current refresh grant state, not just a set of revocation ids.
Concurrent requests with an older cookie revision for the SAME active identity
epoch can use the latest authority state. That prevents a second rotation after
the first refresh has completed. A cookie from a different identity epoch never
resolves to the replacement user's identity. A retired id/epoch is never
reactivated by a cookie or a delayed request. The default capacity is 10,000
records; expired entries are pruned, but unexpired active records and retirement
or consumed-transaction tombstones are not evicted to make room. Capacity fails
closed. Restart/close loses the default authority: old cookies/transactions are
then rejected, and users sign in again. Sharing encryption keys alone does not
make multiple processes share this authority.

The new `ProviderSessionStore` is distinct from the existing read-only
`SessionStore.get` auth lookup API. It exposes `read`, `compareAndSwap`, and
`withLock`. Its opaque record contains revision, absolute expiry, retired flag
and engine-sealed value. CAS is atomic and linearizable, including creation
(expected revision null). Revisions only increase; retirement leaves a tombstone
until the maximum credential/transaction expiry plus accepted clock skew.
An old revision cannot recreate a retired or removed record. Store adapters
must not silently fall back to process memory after a connection failure.

`withLock` serializes the SAME refresh-token grant family across resources and
scope sets, while the acquisition promise cache deduplicates each exact token
key. The adapter MUST preserve exclusivity until the operation callback settles,
including the whole provider exchange. A lease that may expire while the
callback is still running does not implement this interface. Merely rejecting
withLock after the callback already performed exchange or CAS is insufficient.
Coordinate retries/worker failure without overlapping callback execution. CAS fences commits; CAS
alone does not stop two provider refresh requests or prevent token-family reuse.
If lock ownership or an exchange outcome becomes uncertain, fail closed and
require interactive recovery rather than retrying the old refresh token. No
built-in distributed adapter is claimed qualified in 0.5.0. Adapter tests must
run two independent engine instances sharing actual atomic test-store state.

| Deployment                                          | Callback single use       | Logout/replacement fencing    | Refresh serialization               | Restart continuity               |
| --------------------------------------------------- | ------------------------- | ----------------------------- | ----------------------------------- | -------------------------------- |
| Default one engine/process                          | Atomic in-process consume | Shared in-process epoch + CAS | In-process grant-family lock        | No; old authority rejected       |
| Multiple independent defaults, same keys            | Not supported             | Not shared                    | Not shared                          | Not supported                    |
| Shared atomic store and exclusive grant-family lock | Shared CAS                | Shared epoch + CAS            | Shared lock plus current payload    | Yes, subject to store durability |
| Pure encrypted stateless cookie                     | Not offered               | Cannot guarantee retirement   | Cannot guarantee rotation ownership | Not a supported mode             |

The finalizer prevents stale cookies attached after retirement; it cannot recall
HTTP bytes already handed to the network. A previously emitted response may
arrive late and overwrite the browser cookie. Authority must still reject its
retired epoch, so it cannot resurrect identity. Do not claim wire-order control
or that logout revokes an already-issued upstream access token. Local logout,
provider logout and upstream revocation are different operations.

## Transactions, replacement and callback methods

Each authorization stores random state, nonce, S256 verifier/challenge, provider
and client/issuer, validated returnTo, requested resource/scopes, creation/expiry,
an authority record id and the captured login/identity epoch. Default TTL is
300 seconds and maximum is 600. It uses an encrypted, Secure, HttpOnly provider-
scoped transaction cookie, Path=/ and no Domain; its name has the __Host- prefix.
A small unauthenticated session-authority envelope can establish the one app
cookie on first login. That stable authority correlates pending flows across
providers without introducing a second application session cookie.

Starting a newer login advances the authority's pending-login generation and
retires its superseded transactions while keeping the current identity active
until a replacement succeeds. Each transaction captures that generation. A
successful callback atomically checks it and advances the identity epoch with
the new account/token state. Concurrent older callbacks cannot replace the new
identity. Logout retires the authority and all captured pending flows before
revocation or a provider redirect. A form_post transaction carries the captured
authority/epoch because the Lax application session cookie may be absent on the
cross-site POST. Absence of that Lax cookie must not erase replacement fencing.

A valid encrypted transaction record is atomically consumed BEFORE any code
exchange, including provider denial and validation failure. Every callback
clears its transaction cookie; replaying a copied cookie is rejected by CAS,
including two callbacks arriving concurrently. Missing or undecryptable cookies
cannot initiate exchange. Validate method, bounded content type/body size,
duplicate protocol fields, a 32-KiB form-body budget, provider, state and expiry before using code/nonce. Denial/malformed provider callbacks cannot preserve a
usable transaction. If a transaction has insufficient remaining lifetime when
exchange completes, reject it; a slow exchange never extends its TTL.
Callbacks cannot take arbitrary redirect destinations or extension parameters.

Query-mode transactions use SameSite=Lax and accept GET only. Form-post
transactions use SameSite=None;Secure and accept only a bounded
application/x-www-form-urlencoded POST. Only that transaction cookie changes
SameSite; the application session stays Lax. Form_post callback is the narrow
exception to unsafe same-origin Origin enforcement, protected by its explicit
provider/method, encrypted browser correlation, single-use state and nonce.
No blanket CSRF exception for `/auth`, generic POST or every callback method.
If browser privacy policy blocks the correlation cookie, fail with an explicit
transaction error; never accept state without its browser-bound cookie.

All flows generate PKCE/state/nonce and exercise them with signed simulated
providers. Provider-enforced PKCE is a separate capability that MUST be evidenced,
not inferred because a server sent code_challenge. Apple's current public
request/token documentation does not establish PKCE enforcement; record this
as a live-qualification limitation, retaining state, nonce, confidential client
authentication and one-use transaction protection. Do not claim PKCE validation
by Apple without provider evidence or silently remove generated PKCE fields.

## Token acquisition and interaction

The exact cache key includes configured provider id and a stable non-secret
policy fingerprint (canonical issuer/aliases, client, organization/connection
constraints, resources/scopes and private policy version), then issuer + client +
subject/account + resource + canonical
sorted unique scopes. The grant and any retained refresh token are separately
bound to the authenticated identity and configured provider. Unknown resources,
unsupported scopes or capabilities fail configuration validation; an allowed
but not yet granted resource/scope set produces consent interaction. Identity
scope tokens never satisfy an API token request. Do not return an ID token as an
access token, broaden a cache key or reuse another account's grant. Token-type
and expiry fields must validate before caching. Access expiry is exchange-start
plus finite expires_in, with bounded leeway; cache hits never extend it.

Freshness checks run before and after awaited work, including consent exchange,
provider discovery, JWKS lookup, secret factories, refresh and cookie sealing.
A lost session epoch produces login interaction and cannot write refreshed data.
Code exchange still requires a signed ID token and its original nonce. Refresh
may omit an ID token and then retains the existing authenticated principal. If
refresh returns one, validate its signature, issuer, audience/azp, subject and
expiry against the same original account; normally its nonce is absent, and a
present nonce must equal the original. A refreshed ID token cannot change the
account or grant policy. Reuse shared private JWT validators, but never weaken
code-exchange nonce requirements to accommodate refresh.

Provider invalid_grant/login_required/consent_required outcomes are mapped to
safe typed interaction only; provider text is never exposed. Network/store
errors are distinguishable from required user interaction. There are no silent
iframe flows, automatic authorization retries or perpetual refresh loops.

Every valid logout locally retires the whole application identity. The
`provider` field only selects that identity's grant for optional operations; it
does not request a redirect. `providerLogout:true` separately requests supported
RP-initiated continuation AFTER local retirement; default false returns 204.
`revoke:true` separately revokes each unique selected refresh grant family (or
the provider's supported access-token revocation when no refresh grant exists).
With no selector, use the current identity provider and all its resource grants.
A configured list of providers does not imply linked identities: replacement
login retires the previous identity and its private grants; account linking is
out of scope. A foreign selector is a configuration error.
Google/Apple `{provider, revoke:true}` therefore means local logout + revocation
without an unsupported provider redirect. Unsupported providerLogout or
revocation requests fail validation before remote work; local-only logout
always remains available. A remote failure never reverses completed retirement. Post-logout redirect options are resolved only against a configured
same-origin path allow-list (default `/`); no arbitrary absolute callback or
returnTo is sent upstream. Local retirement survives upstream revocation failure.

## Provider capability matrix and honest support status

All four presets remain **pending live qualification** under Auth#71 until
provider-specific packed-version/commit/browser/SSR+SPA evidence is recorded.
The table specifies implementation targets, not a present support claim.

| Preset    | Callback/client authentication        | Identity and API separation                                                                                | Renewal                                                                   | Logout/revocation                                          |
| --------- | ------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- | ---------------------------------------------------------- |
| Auth0     | query; confidential secret            | Exact tenant/custom-domain issuer; organization claim checked; explicit audience + scopes                  | Configured rotating refresh grant; serialize whole family                 | Explicit OIDC logout; refresh-token revocation             |
| Microsoft | query; confidential Web client secret | Exact tenant GUID issuer only; Graph resource/scopes separate; no common/organizations/consumers authority | Replace stored refresh token after use; serialize whole grant             | Tenant end_session_endpoint; no generic revocation promise |
| Google    | query; web client secret              | Exactly two issuer spellings; enforce hd claim; identity scopes separate from configured API consent       | offline first-consent behavior; missing refresh means explicit re-consent | Local logout only; token revocation                        |
| Apple     | form_post; server ES256 JWT secret    | Services ID audience; unsigned first-login user hint separate; no API bearer capability                    | Account-validity check no more than once/day                              | Local logout only; token revocation                        |

Microsoft's documentation says replacement refresh tokens do not automatically
revoke old ones; do not describe it as Auth0-style theft/reuse detection. Auth0's
reuse interval can tolerate particular network races, but is not a distributed
session/logout authority or a replacement for a shared refresh lock. Apple
client-secret lifetime must stay within its provider limit, and the generated
secret cache uses a short expiry; Apple private-key/profile handling remains
server-side. Each preset has explicit setup and simulated-provider acceptance.

## Server, router and email/password disposition

`createAskrApp.auth` is an exclusive union. Provider mode accepts providers,
session and explicit origin; it creates the one engine and resolver. Existing
manual mode retains `{resolver, routes?, pages?}`. Combining either mode's fields
is rejected at setup and in strict types. Standalone `registerAuthRoutes` remains
for existing email/password apps. Provider mode does not auto-register its JWT
cookie routes or compose two resolvers. Combining local credentials and provider
login in one session is not advertised until a shared credential entry contract
exists; applications may stay on existing manual auth meanwhile.

Server's `ServerAuthContext` extends `AuthContext` with a required non-enumerable
`token(provider, options)` bound to the exact Request. Provider mode delegates
to the engine; manual mode throws a safe configuration error. Authentication
JSON/hydration serializers never spread this object. Cookie-authenticated unsafe
requests require exact configured-origin Origin, with only the correlated
form_post exception above. `/auth/session` has no-store, explicit minimal JSON
and no tokens; `/auth/logout` is POST only. API/page/action errors pass through
the same safe interaction mapping and final response boundary.

Core's binding is owned by `@askrjs/askr/router`, avoiding an Auth → Core cycle.
It must supply the existing RouteAuthOptions and login/logout helpers, use the
SSR sanitized snapshot for first hydration and later client navigations, dedupe
GET /auth/session until explicit invalidation, and attach cancellation/owner
fences. After logout, interaction loss or cross-tab notification, invalidate
identity and private data BEFORE acquiring/rendering another identity. Retire
only provider-binding-owned data runtimes and use #754/#756 ownership guards;
never globally reset unrelated roots or reuse a disposed singleton. Boot can
allocate an owned runtime for the opted-in binding. A supplied runtime needs
explicit ownership validation and cannot silently be shared across unrelated
identities. The binding has no static provider tokens, secrets or server imports. Core's
own focused tests do not introduce a Core → Server dev dependency cycle; the
actual packed Core + Auth + Server SSR/SPA native acceptance runs downstream in
Examples32. Cross-site form_post proof uses owned TLS app/provider sites and
real browser cookie handling, not fabricated Cookie headers or mocked flags.

Cross-tab messages contain only an invalidation event, never identity, token,
session id or principal data. BroadcastChannel is primary; storage-event plus
pageshow/visibility session revalidation is the documented fallback. Receivers
clear private data and refetch the same server session. A received event is not
authentication evidence. `currentAuth()` consumers must update observably, and
binding-owned listeners/requests stop with their app lifetime.

## Required proof before implementation closure

The contract/source must be reviewed and committed before preset code. Engine
RED→GREEN tests cover real signed artifacts, both callback methods, copied-cookie
concurrent replay, denial/invalid-state consumption, expiry/key rotation/size,
resource/account separation including equal scope spellings in two resources,
identity-only snapshot scopes, whole-grant rotation, two-engine shared-store
coordination, pending renewal vs logout/replacement, stale finalization and
restart rejection. A delayed already-emitted cookie must fail authentication.
Use exact secret/token canaries against response bodies, hydration, errors/logs
and browser bundle contents. Carry server-relevant regressions from Auth65's
removed tests before deleting them.

Server integration uses real createAskrApp and simulated provider HTTP. Native
Chromium/Firefox/WebKit run SSR AND SPA for every provider, including genuinely
cross-site form_post, no hydration refetch, denied policy, consent, renewal/loss,
logout and cross-tab private data clearing. Packed normal installs use actual
TS6/7 and Node floor/current, import server entries without window/document,
reject removed browser/auth0 exports and SDK dependencies, and inspect actual
client chunks for server modules/secrets. Normal npm ci and lifecycle final pack,
fmt/check/coverage and existing performance gates remain unchanged.

Auth71 live execution is separate: missing credentials never blocks engine,
presets, scaffolds, examples or simulated qualification. Record pending entries
for missing credentials and exact required setup; never substitute simulated
passes or invent provider evidence. A provider/pipeline change invalidates its
prior live pass. Tokens/keys/user data are never stored in qualification records.

## Primary references and design status

These are protocol/provider references, not claims that implementation exists:
[OIDC Core errata 2](https://openid.net/specs/openid-connect-core-1_0.html),
[OAuth Security BCP RFC9700](https://www.rfc-editor.org/rfc/rfc9700.html),
[current browser-apps RFC10017](https://datatracker.ietf.org/doc/rfc10017/),
[Auth0 rotation](https://auth0.com/docs/secure/tokens/refresh-tokens/configure-refresh-token-rotation),
[Auth0 OIDC logout](https://auth0.com/docs/authenticate/login/logout/log-users-out-of-auth0),
[Microsoft refresh](https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens),
[Google OIDC](https://developers.google.com/identity/openid-connect/openid-connect),
[Google Web OAuth](https://developers.google.com/identity/protocols/oauth2/web-server),
[Apple authorization](https://developer.apple.com/documentation/signinwithapplerestapi/request-an-authorization-to-the-sign-in-with-apple-server.),
[Apple account verification](https://developer.apple.com/documentation/signinwithapple/verifying-a-user),
[cookie attributes](https://privacysandbox.google.com/cookies/basics/cookie-attributes).

The atomic store, cookie budget, default TTL/capacity, strict response finalizer,
minimal serialization and deployment limitations are explicit Askr design
choices. They require the above implementation/native tests; references alone
are not acceptance evidence.

## Public API shape

```ts
// Reviewed-design API candidate; not compiled or implemented. Owner: @askrjs/auth/server.
import type { AuthContext, AuthResolver, Principal } from "@askrjs/auth";

export interface ProviderTokenRequest {
  readonly resource?: string;
  readonly scopes: readonly string[];
  readonly signal?: AbortSignal;
}
export interface ProviderLoginRequest {
  readonly provider: string;
  readonly returnTo: string;
  readonly resource?: string;
  readonly scopes?: readonly string[];
}
export interface ProviderLogoutRequest {
  readonly provider?: string; // Optional grant selector; defaults to the current identity provider.
  readonly providerLogout?: boolean; // Default false; independent of local retirement/revocation.
  readonly returnTo?: string; // Only used for explicit providerLogout continuation.
  readonly revoke?: boolean; // Default false; revoke each unique selected grant family.
}
export type ProviderClientAuthentication = {
  readonly method: "client_secret_post" | "client_secret_basic";
  readonly secret:
    | string
    | ((context: {
        readonly now: number;
        readonly signal: AbortSignal;
      }) => string | PromiseLike<string>);
};
export interface ProviderCapabilities {
  readonly renewal: "refresh" | "account-check" | "none";
  readonly incrementalConsent: boolean;
  readonly providerLogout: boolean;
  readonly revocation: boolean;
  readonly resources: readonly { readonly resource: string; readonly scopes: readonly string[] }[];
}
// Presets return this shared definition; provider-specific claim/parameter policies
// remain engine-owned, not user overrides of protocol-managed parameters.
declare const providerDefinitionBrand: unique symbol;
export interface ProviderDefinition {
  readonly [providerDefinitionBrand]: true;
  readonly id: string;
  readonly issuer: string;
  readonly clientId: string;
  readonly clientAuthentication: ProviderClientAuthentication;
  readonly responseMode: "query" | "form_post";
  readonly identityScopes: readonly string[];
  readonly capabilities: ProviderCapabilities;
  readonly authorizationParams?: Readonly<Record<string, string>>;
}
export interface OidcProviderOptions {
  readonly id: string;
  readonly issuer: string; // One exact issuer; aliases are private preset policy only.
  readonly clientId: string;
  readonly clientAuthentication: ProviderClientAuthentication;
  readonly identityScopes?: readonly string[];
  readonly responseMode?: "query" | "form_post";
  readonly capabilities?: Partial<ProviderCapabilities>;
  readonly authorizationParams?: Readonly<Record<string, string>>;
  readonly endpoints?: {
    readonly authorization?: string;
    readonly token?: string;
    readonly jwks?: string;
    readonly logout?: string;
    readonly revocation?: string;
  }; // Trusted explicit HTTPS URLs, no credentials/fragments; never request-supplied.
}
export declare function createOidcProvider(options: OidcProviderOptions): ProviderDefinition;
// Existing @askrjs/auth SessionStore remains the read-only auth lookup contract.
// This new owner is intentionally distinct: atomics/locking are mandatory.
export interface ProviderSessionRecord {
  readonly revision: number;
  readonly expiresAt: number;
  readonly retired: boolean;
  readonly value: string | null; // Engine-sealed opaque value, never a principal/token object.
}
export interface ProviderSessionStore {
  read(id: string, options: { signal: AbortSignal }): Promise<ProviderSessionRecord | null>;
  compareAndSwap(
    id: string,
    expectedRevision: number | null,
    next: ProviderSessionRecord,
    options: { signal: AbortSignal },
  ): Promise<boolean>;
  withLock<T>(
    key: string,
    operation: () => Promise<T>,
    options: { signal: AbortSignal },
  ): Promise<T>;
}
export interface ProviderSessionOptions {
  readonly origin: string; // Explicit canonical HTTPS origin; never inferred from Host/forwarded headers.
  readonly providers: readonly ProviderDefinition[];
  readonly session: {
    readonly secrets: readonly string[]; // Current then previous base64url-encoded 32-byte keys.
    readonly store?: ProviderSessionStore; // Presence selects opaque-id cookie + shared sealed storage.
    readonly maxAgeSeconds?: number; // Integer 1..2,592,000, default 28,800; absolute.
    readonly leewaySeconds?: number; // Integer 0..300, default 30; cannot extend expiry.
    readonly maxEntries?: number; // Integer 1..1,000,000, default 10,000; fail closed when full.
  };
  readonly onSignIn?: (context: {
    readonly provider: string;
    readonly principal: Readonly<Principal>;
    readonly profileHint?: { readonly givenName?: string; readonly familyName?: string };
    readonly signal: AbortSignal;
  }) => void | PromiseLike<void>; // Server-only; profileHint is unsigned/untrusted, never identity.
  readonly postLogoutRedirects?: readonly string[]; // Exact same-origin relative paths; default ["/"].
  readonly transactionTtlSeconds?: number; // Default 300, maximum 600.
  readonly fetch?: typeof fetch;
  readonly clock?: () => number; // Unix milliseconds.
}
export interface ProviderSession extends AuthResolver {
  resolve(request: Request, options?: { signal?: AbortSignal }): Promise<AuthContext>;
  login(request: Request, options: ProviderLoginRequest): Promise<Response>;
  callback(request: Request, options: { readonly provider: string }): Promise<Response>;
  logout(request: Request, options?: ProviderLogoutRequest): Promise<Response>;
  token(request: Request, provider: string, options: ProviderTokenRequest): Promise<string>;
  finalize(request: Request, response: Response): Promise<Response>;
  close(): Promise<void>;
}
export declare function createProviderSession(options: ProviderSessionOptions): ProviderSession;
export type ProviderSessionErrorCode =
  | "configuration"
  | "invalid-callback"
  | "invalid-transaction"
  | "session-oversize"
  | "capacity"
  | "store-unavailable"
  | "provider-unavailable"
  | "closed";
export declare class ProviderSessionError extends Error {
  readonly code: ProviderSessionErrorCode;
  constructor(code: ProviderSessionErrorCode); // Static safe message by code; no raw message/cause option.
}
export declare class InteractionRequiredError extends Error {
  constructor(options: {
    readonly reason: "login" | "consent";
    readonly provider: string;
    readonly resource?: string;
    readonly scopes: readonly string[];
  });
  readonly code: "interaction-required";
  readonly reason: "login" | "consent";
  readonly provider: string;
  readonly resource?: string;
  readonly scopes: readonly string[];
}
```
