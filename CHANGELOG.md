# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## 0.5.0 - 2026-10-10

### Breaking changes

- Remove ten JWT/OIDC, CBOR/COSE and browser encoding implementation names from public entrypoints. See [every removal and replacement](docs/0.5.0-api.md). Keep the low-level OIDC/passkey entries and the public `CoseAlgorithm` credential contract; the separate browser-session retirement is described below.

- Remove `@askrjs/auth/browser` and withdraw the develop-only `@askrjs/auth/auth0` SDK adapter, their browser-held session types/implementations, private SPA examples and optional Auth0 SPA SDK dependency. Migrate application sign-in to Server provider auth plus Core session binding; retain `/oidc`, `/webauthn-client` and native `/providers/auth0`. See the [breaking migration](docs/0.5.0-api.md#browser-session-migration).

### Added

- Native Google server preset at `@askrjs/auth/providers/google`, with signed hosted-domain checks, explicit API permissions, offline consent recovery and server-owned revocation. See [server setup](docs/providers-google.md); live-provider qualification remains pending.
- Native Apple server preset at `@askrjs/auth/providers/apple`, with ES256 client secrets, bounded server-only profile observation and CAS-owned daily account verification. See [server setup](docs/providers-apple.md); live-provider/PKCE qualification remains pending.
- Shared server provider-session engine with one-time callback authority, sealed sessions, refresh-family serialization, cancellation and stale-response fencing.
- Native Microsoft Entra ID preset at `@askrjs/auth/providers/microsoft`, with exact single-tenant issuer checks, explicit qualified API scopes, confidential rotating renewal and provider logout. See [server setup](docs/providers-microsoft.md); live-provider qualification remains pending.
- Native Auth0 preset at `@askrjs/auth/providers/auth0`, including explicit API audiences, signed organization checks, rotating refresh grants, OIDC logout and server-side revocation. See [server setup](docs/providers-auth0.md); live-provider qualification remains pending.
- Bounded native OIDC provider authorization parameters, retaining exact callback state/nonce and signature checks.
- Installed package contract checks under TypeScript 6 and 7, and Chromium/Firefox/WebKit browser qualification.
- Real signing-key rotation, clock equality/failure/recovery, signed WebAuthn mismatch and TOTP period/replay-ownership probes.

### Fixed

- Coordinate final cached and renewed server token delivery with shared-store logout and identity replacement, including delayed authority-read responses.
- Reject non-finite session/JWT clocks and timed issuance whose expiration cannot advance.
- Reject invalid SAML clocks, time policies and request lifetimes before returning or consuming authentication state.
- Reject invalid TOTP timestamps and skip drift counters outside the non-negative safe integer range.
- Bind an explicit OIDC authorized party to the configured client even for a single audience, and reject additional audiences without configured trust.
- Dispatch npm artifact checks through Node on Windows.

### Development

- First-party development workflows use Vite+; specialized compiler, runtime,
  browser, and package checks remain part of validation.

## 0.4.2 - 2026-10-08

### Breaking changes

- None.

### Deprecations

- None.

### Added

- Optional `@askrjs/auth/browser` session lifecycle with memory-only tokens,
  one-time redirect transactions, shared expiry renewal, correlated web-message
  transport, cancellation/disposal guards, and a standalone signed-provider SPA.

### Fixed

- Validate OIDC ID tokens in browsers without a Node `Buffer` polyfill while
  retaining canonical base64url, UTF-8, signature, and nonce validation.
- Install browser engines for the complete hosted publication gate.

## 0.4.1 - 2026-09-30

### Fixed

- Refresh OIDC signing keys for each token exchange so IdP key rotation takes
  effect without restarting the application.
- Decode JWT header and claim JSON as UTF-8 so non-ASCII claim values remain
  intact.
