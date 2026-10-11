# Auth0 server provider

Import `createAuth0Provider` from `@askrjs/auth/providers/auth0` and pass its
definition to `createProviderSession` from `@askrjs/auth/server`. This preset
uses native OIDC and the shared server session engine. Provider tokens and the
client secret remain on the server; it does not load the Auth0 browser SDK.

```ts
import { createAuth0Provider } from "@askrjs/auth/providers/auth0";
import { createProviderSession } from "@askrjs/auth/server";

const auth = createProviderSession({
  origin: "https://app.example.com",
  session: { secrets: [process.env.AUTH_SESSION_SECRET!] },
  postLogoutRedirects: ["/"],
  providers: [
    createAuth0Provider({
      id: "auth0",
      domain: "tenant.auth0.com",
      clientId: process.env.AUTH0_CLIENT_ID!,
      clientSecret: process.env.AUTH0_CLIENT_SECRET!,
      resources: [{ resource: "https://api.example.com", scopes: ["read:records"] }],
    }),
  ],
});
```

Configure an Auth0 **Regular Web Application** with its callback URL set to
`https://app.example.com/auth/callback/auth0` and its allowed logout URL set to
`https://app.example.com/`. The explicit app origin, callback routing and session
keys belong to the shared engine. `domain` is the tenant or configured custom
domain without a scheme, port or path; its issuer is exactly `https://{domain}/`.

The default identity scopes are `openid profile email offline_access`. API
permissions belong to `resources`, where `resource` is the API's exact Auth0
audience identifier. Pass that resource and its requested scopes when starting
API consent. The preset sends `audience` and keeps token/cache ownership separate
for every audience and scope set. An identity-only login sends no audience.
`token()` selects an omitted resource only when exactly one is configured; zero
or multiple configured resources require explicit selection. Tokens for one API
never satisfy a different API request.

Enable offline access for the configured API and refresh-token rotation for the
application. The engine serializes every refresh in one provider grant family,
including requests for different audiences. Reusing a refresh token across APIs
requires Auth0 Multi-Resource Refresh Token (MRRT) policies for the permitted
audiences and scopes; enabling offline access and rotation alone does not grant
that access. Auth0 limits MRRT to first-party applications and APIs configured to
allow skipping user consent, and excludes the Auth0 Management API from MRRT
policies. See
[Auth0's MRRT setup and limitations](https://auth0.com/docs/secure/tokens/refresh-tokens/multi-resource-refresh-token).
For multi-instance deployments use the shared atomic session store with a
cross-instance grant-family lock; default
in-process authority is only for one engine process. Configure Auth0's rotation
reuse interval for expected network retry/race latency. That provider setting
does not replace the store's atomic authority or lock. See
[Auth0's rotation settings](https://auth0.com/docs/secure/tokens/refresh-tokens/configure-refresh-token-rotation).

Optional `connection` selects an Auth0 connection. Optional `organization` is
the expected `org_id`, which must match the signed ID token. If `org_name` is
returned, supply the exact expected `organizationName` as well; a name requires
an organization ID. Unexpected organization claims, missing/mismatched IDs and
mismatched names reject the callback. Neither an authorization parameter nor an
organization name substitutes for signed ID-token validation. See
[Auth0 organization token validation](https://auth0.com/docs/manage-users/organizations/using-tokens).

`logout(request, { providerLogout: true, returnTo: "/" })` uses Auth0's OIDC
RP-initiated logout endpoint after validating the application destination against
`postLogoutRedirects`. Add `revoke: true` to revoke the stored refresh token on
the server. The two operations are explicit and independent; local retirement
still fences late callbacks, refreshes and response finalizers.

Signed simulated-provider tests cover setup, organization claims, audience
isolation, rotation, logout and revocation. Their cross-audience refresh scenario
assumes the corresponding audience/scope MRRT policies are configured at the
simulated provider; it does not prove a tenant's dashboard configuration.
Live-tenant qualification remains
pending under Auth#71; the dashboard and deployment setup require that separate
qualification before claiming a live-provider pass.
