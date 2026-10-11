# Microsoft Entra ID server provider

Import `createMicrosoftProvider` from `@askrjs/auth/providers/microsoft` and pass
its definition to `createProviderSession` from `@askrjs/auth/server`. Provider
credentials, refresh grants and API access tokens remain on the server.

```ts
import { createMicrosoftProvider } from "@askrjs/auth/providers/microsoft";
import { createProviderSession } from "@askrjs/auth/server";

const graph = "https://graph.microsoft.com";
const auth = createProviderSession({
  origin: "https://app.example.com",
  session: { secrets: [process.env.AUTH_SESSION_SECRET!] },
  postLogoutRedirects: ["/"],
  providers: [
    createMicrosoftProvider({
      id: "microsoft",
      tenantId: process.env.MICROSOFT_TENANT_ID!,
      clientId: process.env.MICROSOFT_CLIENT_ID!,
      clientSecret: process.env.MICROSOFT_CLIENT_SECRET!,
      resources: [{ resource: graph, scopes: [`${graph}/User.Read`] }],
    }),
  ],
});
```

Register a confidential **Web** application with its exact callback URL,
`https://app.example.com/auth/callback/microsoft`. Keep the client secret in
server configuration. The app origin, callback routing and session keys belong
to the shared engine.

This preset accepts one explicit tenant GUID. It rejects `common`,
`organizations`, `consumers` and template issuers. The expected issuer is
`https://login.microsoftonline.com/{tenantId}/v2.0`; the signed `tid` must match
that tenant too. Discovery supplies the authorization/token/JWKS/logout endpoints;
a shared Microsoft JWKS URL does not relax issuer or tenant validation.

Default identity scopes are `openid profile email offline_access`. Configure API
permissions separately under each canonical resource, with fully qualified
scopes such as `https://graph.microsoft.com/User.Read` or
`api://application-id/access_as_user`. Start API consent with that explicit
resource and its configured scopes. The provider wire uses those qualified
scopes, with no generic `resource` or Auth0 `audience` parameter. Identity-only
login requests no API permission. An omitted `token()` resource selects only a
sole configured target; zero or multiple targets require explicit selection.

Each access-token cache entry belongs to the exact resource and scope set.
Renewal is serialized across the provider's refresh family, uses the latest
rotated refresh token, and requests only the current target's scopes. Configure
the app registration's delegated API permissions and the required user/admin
consent; this preset does not infer consent from a signed identity.

Microsoft may omit the token response's `scope` property when it is identical
to the request. Only a truly absent property confirms this exchange's requested
API set; a present malformed, empty or narrowed response never inherits a
broader grant. For the exact Graph resource, the preset accepts Graph's short or
qualified returned permission names with ASCII case-insensitive suffix matching.
Other APIs keep exact configured strings. Identity scopes and `offline_access`
never become API grants merely because they were requested. See
[Microsoft's authorization-code protocol](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
and [Graph permission response guidance](https://learn.microsoft.com/en-us/aspnet/core/blazor/security/webassembly/graph-api?view=aspnetcore-10.0).

`logout(request, { providerLogout: true, returnTo: "/" })` uses the discovered
tenant logout endpoint after validating the destination against
`postLogoutRedirects`. Local retirement still fences old callbacks, refreshes and
response finalizers. This preset advertises no refresh-token revocation endpoint.
For multiple engine processes, supply a shared atomic session store with a
cross-instance grant-family lock.

The signed simulated-provider suite exercises tenant validation, real PKCE/JWKS
exchange, resource isolation, response-scope variants, refresh rotation and
logout. It provides release regression evidence; live Entra tenant configuration
and compatibility remain pending under Auth#71.
