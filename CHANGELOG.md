# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## 0.5.0 - 2026-10-10

### Breaking changes

- Remove ten JWT/OIDC, CBOR/COSE and browser encoding implementation names from public entrypoints. See [every removal and replacement](docs/0.5.0-api.md). Keep all seven provider/client entrypoints and the public `CoseAlgorithm` credential contract.

### Added

- Optional `@askrjs/auth/auth0` adapter using the official SDK peer with memory-only tokens, SDK-owned renewal and guarded local lifetime; includes a framework-neutral signed-provider example. See [SDK validation and ownership limits](docs/auth0-session.md).
- Bounded native provider authorization parameters and explicitly selected Auth0 nested web-message format, retaining native origin/source/state and signature checks.
- Installed package contract checks under TypeScript 6 and 7, and Chromium/Firefox/WebKit browser qualification.
- Real signing-key rotation, clock equality/failure/recovery, signed WebAuthn mismatch and TOTP period/replay-ownership probes.

### Fixed

- Reject non-finite session/JWT clocks and timed issuance whose expiration cannot advance.
- Reject invalid SAML clocks, time policies and request lifetimes before returning or consuming authentication state.
- Reject invalid TOTP timestamps and skip drift counters outside the non-negative safe integer range.
- Bind an explicit OIDC authorized party to the configured client even for a single audience, and reject additional audiences without configured trust.
- Use real cross-origin frame messages in the browser correlation test and dispatch npm artifact checks through Node on Windows.

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
