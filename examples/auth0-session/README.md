# Optional Auth0 SDK session example

This framework-neutral SPA normally installs the packed Auth package and official
Auth0 SPA SDK 2.28.3. The adapter owns session lifetime; the SDK owns token and
transaction handling. Application code only displays results and initiates
navigation, API token access, local logout and demo-provider logout.

```sh
npm ci
npm run build
npm pack --ignore-scripts
cd examples/auth0-session
npm install
npm start
```

Open `https://127.0.0.1:8000` and accept the self-signed demo certificate. Its
included TLS key and certificate are public test fixtures. The local simulated
provider signs ID tokens with an ephemeral RSA key, checks S256 PKCE and consumes
codes once. It is not an Auth0 tenant or production identity service.

1. Click Login; the SDK transaction survives provider navigation and is consumed
   on return. The app then clears callback parameters from the address bar.
2. Click Reload; tokens were not persisted, so SDK silent authorization uses the
   provider cookie to restore a new in-memory session.
3. Wait at least 120 seconds and click Get token; the 180-second token is within
   SDK's 60-second renewal window. The displayed absolute expiry advances.
4. Click Logout; local ownership is cleared and the app separately clears the
   demo provider cookie. Reload requires interaction; Login recovers.

Use the existing native [browser example](../browser-session/README.md) for Askr
signature/JWKS validation without the SDK. See [adapter ownership and validation
limits](../../docs/auth0-session.md) before configuring a real Auth0 application.
