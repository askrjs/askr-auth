# Google server provider

Import `createGoogleProvider` from `@askrjs/auth/providers/google` and pass the resulting definition to `createProviderSession` from `@askrjs/auth/server`. Configure a confidential Web application client in Google Cloud and register the engine's exact HTTPS callback URI. Keep the client secret and session secret in server configuration. The preset owns Google's protocol policy; app origin, callback routing, encrypted sessions, replay authority and server transport remain shared-engine options.

```ts
import { createGoogleProvider } from "@askrjs/auth/providers/google";

const google = createGoogleProvider({
  id: "google",
  clientId: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  hostedDomain: "example.com",
  resources: [
    {
      resource: "https://www.googleapis.com",
      scopes: ["https://www.googleapis.com/auth/drive.readonly"],
    },
  ],
});
```

`hostedDomain` is optional. When supplied, it is both an authorization hint and an exact policy on the signed `hd` claim. The canonical identity issuer is `https://accounts.google.com`; Google's documented signed `accounts.google.com` spelling has that same identity owner. Other spellings are rejected.

Identity scopes default to `openid`, `profile`, and `email`. API permissions belong to explicit canonical resource policies and are compared case-sensitively with the actual token response. Identity aliases affect only the minimal identity snapshot; they cannot satisfy a differently spelled API permission. The preset does not send generic `resource` or `audience` parameters. A resource key still owns token cache entries and interaction errors.

Authorization requests use `access_type=offline` and `include_granted_scopes=true`. First login does not force another consent prompt. A current same-provider/policy identity lacking a usable refresh grant, or carrying persisted refresh uncertainty, requests explicit consent on the next login. This decision is made from the locked current authority, never a cookie hint. Failed renewal does not retry automatically or borrow another resource's permission. Google may omit a new refresh token on later authorizations; applications must handle typed login/consent recovery.

Local logout can request revocation. The preset has no provider logout redirect capability. Tokens stay server-side; session snapshots remain minimal. Signed simulated-provider HTTP tests are development evidence. Live tenant consent, verification status and provider compatibility remain pending.

See Google's [Web server OAuth guide](https://developers.google.com/identity/protocols/oauth2/web-server) and [OpenID Connect validation guide](https://developers.google.com/identity/openid-connect/openid-connect).
