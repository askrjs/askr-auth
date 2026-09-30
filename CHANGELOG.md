# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## 0.4.1 - 2026-09-30

### Fixed

- Refresh OIDC signing keys for each token exchange so IdP key rotation takes
  effect without restarting the application.
- Decode JWT header and claim JSON as UTF-8 so non-ASCII claim values remain
  intact.
