# Browser session example

This standalone SPA uses the public `@askrjs/auth/browser` contract with a local
OIDC provider. The provider generates an RSA signing key, verifies S256 PKCE,
consumes authorization codes once, and sets a provider session cookie. Interactive
login selects a fixed Demo user; this provider is for local demonstration only.

From the auth checkout:

```sh
npm ci
npm run build
npm pack --ignore-scripts
cd examples/browser-session
npm install
npm start
```

Open `https://127.0.0.1:8000` and accept the demo's self-signed localhost certificate.
The included TLS key/certificate are public demo fixtures. The starter installs the checkout's packed artifact;
The browser entrypoint is available starting with `@askrjs/auth@0.4.2`.

1. Click Login. The signed callback validates the ID token and consumes the
   redirect transaction. Callback parameters are then removed from the URL.
2. Click Reload. No token is persisted. Silent authorization restores the session
   using the provider's cookie, with a new nonce, PKCE verifier, and signed ID token.
3. Wait at least 25 seconds and click Get token. The 30-second access-token
   lifetime and five-second leeway trigger silent renewal. The displayed expiry
   moves forward. Concurrent calls share that renewal.
4. Click Logout. The app clears its local session, then explicitly clears the demo
   provider cookie. Reload now shows `Interaction required: login_required`.

The example requires no Node polyfills in the browser. Its small Node server owns
the demo provider and static serving. A real provider must explicitly support
authorization-code PKCE, CORS token/JWKS endpoints, the registered redirect URI,
and `response_mode=web_message` to the parent. Cookie restrictions can prevent
silent restoration; the application should then offer interactive Login.
