# @askrjs/auth

[![CI](https://github.com/askrjs/askr-auth/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/askrjs/askr-auth/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/%40askrjs%2Fauth.svg)](https://www.npmjs.com/package/@askrjs/auth)

Shared authentication contracts, JWT and OIDC primitives, and request authentication resolution for Askr.

JWT issuance and validation support RS256 with RSA keys and ES256 with EC P-256 keys. A JWK's
`alg` may be omitted and inferred from its key shape; when present, it must match the key.

## Install

```sh
npm install @askrjs/auth
```
