import { afterEach, expect, it } from "vite-plus/test";
import { createAuth0Provider } from "../src/providers/auth0";
import type { Auth0ProviderOptions } from "../src/providers/auth0";
import { createProviderSession } from "../src/server";
import {
  presetFixture,
  closePresetFixtures,
  appOrigin,
  clientId,
  clientSecret,
} from "./provider-preset-fixture";

afterEach(closePresetFixtures);

const options: Auth0ProviderOptions = {
  id: "auth0",
  domain: "tenant.auth0.test",
  clientId,
  clientSecret,
};
const first = "https://first-api.example.test";
const second = "https://second-api.example.test";
const resources = [
  { resource: first, scopes: ["read:records"] },
  { resource: second, scopes: ["read:records"] },
];
const endpoints = {
  authorization: "https://tenant.auth0.test/authorize",
  token: "https://tenant.auth0.test/oauth/token",
  jwks: "https://tenant.auth0.test/.well-known/jwks.json",
  logout: "https://tenant.auth0.test/oidc/logout",
  revocation: "https://tenant.auth0.test/oauth/revoke",
  resourceParameter: "audience",
};

it("constructs one branded server policy with explicit Auth0 capabilities", () => {
  const provider = createAuth0Provider(options);
  expect(provider.issuer).toBe("https://tenant.auth0.test/");
  expect(provider.identityScopes).toEqual(["email", "offline_access", "openid", "profile"]);
  expect(provider.capabilities).toEqual({
    renewal: "refresh",
    incrementalConsent: true,
    providerLogout: true,
    revocation: true,
    resources: [],
  });
  expect(provider.clientAuthentication).toEqual({
    method: "client_secret_post",
    secret: clientSecret,
  });
  expect(Object.isFrozen(provider)).toBe(true);
  expect(() =>
    createProviderSession({
      origin: appOrigin,
      providers: [{ ...provider }],
      session: { secrets: [Buffer.alloc(32).toString("base64url")] },
    }),
  ).toThrow(expect.objectContaining({ code: "configuration" }));
});

it.each([
  "",
  "https://tenant.auth0.test",
  "tenant.auth0.test/path",
  "user@tenant.auth0.test",
  "tenant.auth0.test:443",
  "tenant.auth0.test?x",
  "tenant.auth0.test#x",
  "tenant.auth0.test\\evil",
])("rejects unsafe Auth0 domain %s at setup", (domain) => {
  expect(() => createAuth0Provider({ ...options, domain })).toThrow(
    expect.objectContaining({ code: "configuration" }),
  );
});

it("rejects unsupported identity scopes and a name without an expected organization ID", () => {
  // @ts-expect-error API permissions are resource policy, not identity scope options.
  expect(() =>
    createAuth0Provider({ ...options, identityScopes: ["openid", "read:records"] }),
  ).toThrow(expect.objectContaining({ code: "configuration" }));
  expect(() => createAuth0Provider({ ...options, organizationName: "acme" })).toThrow(
    expect.objectContaining({ code: "configuration" }),
  );
});

it.each([null, 0, Symbol("invalid"), {}])(
  "rejects malformed runtime organization configuration %# safely",
  (organization) => {
    // @ts-expect-error JavaScript callers still receive a typed safe setup error.
    expect(() => createAuth0Provider({ ...options, organization })).toThrow(
      expect.objectContaining({ code: "configuration" }),
    );
  },
);

it("sends connection and expected organization while sign-in requests identity only", async () => {
  const f = await presetFixture(
    createAuth0Provider({
      ...options,
      connection: "enterprise",
      organization: "org_expected",
      organizationName: "acme",
      resources,
    }),
    endpoints,
  );
  f.setClaims({ org_id: "org_expected", org_name: "acme", email: "PRIVATE_PROFILE" });
  const started = await f.start();
  expect(started.authorization.searchParams.get("connection")).toBe("enterprise");
  expect(started.authorization.searchParams.get("organization")).toBe("org_expected");
  expect(started.authorization.searchParams.has("audience")).toBe(false);
  expect(started.authorization.searchParams.get("scope")!.split(" ")).toEqual([
    "email",
    "offline_access",
    "openid",
    "profile",
  ]);
  const signed = await f.complete(started);
  const context = await f.engine.resolve(f.appRequest(signed.cookie));
  expect(context.authenticated).toBe(true);
  expect(context.principal).toEqual({
    id: JSON.stringify(["https://tenant.auth0.test/", "account"]),
    subject: "account",
  });
  expect(context.scopes).toEqual(["email", "openid", "profile"]);
  expect(JSON.stringify(context)).not.toContain("PRIVATE_PROFILE");
  expect(JSON.stringify(context)).not.toContain("org_expected");
});

it.each([
  { configured: { organization: "org_expected" }, claims: {} },
  { configured: { organization: "org_expected" }, claims: { org_id: "org_foreign" } },
  {
    configured: { organization: "org_expected" },
    claims: { org_id: "org_expected", org_name: "unexpected" },
  },
  {
    configured: { organization: "org_expected", organizationName: "acme" },
    claims: { org_id: "org_expected", org_name: "foreign" },
  },
  { configured: {}, claims: { org_id: "org_unexpected" } },
  { configured: {}, claims: { org_name: "unexpected" } },
])(
  "rejects signed unexpected or mismatched organization claims %#",
  async ({ configured, claims }) => {
    const f = await presetFixture(createAuth0Provider({ ...options, ...configured }), endpoints);
    f.setClaims(claims);
    await expect(f.complete(await f.start())).rejects.toMatchObject({ code: "invalid-callback" });
    expect(f.exchanges).toBe(1);
  },
);

it("keys grants by audience and rotates the one refresh family across audiences", async () => {
  const f = await presetFixture(createAuth0Provider({ ...options, resources }), endpoints);
  const initial = await f.signIn("", { resource: first, scopes: ["read:records"] });
  expect(
    await f.engine.token(f.appRequest(initial.cookie), "auth0", {
      resource: first,
      scopes: ["read:records"],
    }),
  ).toBe(`ACCESS_1_${first}`);
  await expect(
    f.engine.token(f.appRequest(initial.cookie), "auth0", {
      resource: second,
      scopes: ["read:records"],
    }),
  ).rejects.toMatchObject({
    code: "interaction-required",
    reason: "consent",
    resource: second,
    scopes: ["read:records"],
  });
  expect(f.refreshes).toBe(0);
  const consented = await f.signIn(initial.cookie, { resource: second, scopes: ["read:records"] });
  expect(
    await f.engine.token(f.appRequest(consented.cookie), "auth0", {
      resource: first,
      scopes: ["read:records"],
    }),
  ).toBe(`ACCESS_1_${first}`);
  expect(
    await f.engine.token(f.appRequest(consented.cookie), "auth0", {
      resource: second,
      scopes: ["read:records"],
    }),
  ).toBe(`ACCESS_2_${second}`);
  f.advance(31_000);
  const renewed = await Promise.all(
    [first, second].map((resource) =>
      f.engine.token(f.appRequest(consented.cookie), "auth0", {
        resource,
        scopes: ["read:records"],
      }),
    ),
  );
  expect(new Set(renewed)).toEqual(new Set(["RENEWED_1", "RENEWED_2"]));
  const refreshes = f.requests.filter(
    (request) => request.fields.get("grant_type") === "refresh_token",
  );
  expect(refreshes.map((request) => request.fields.get("audience"))).toEqual([first, second]);
  expect(refreshes.map((request) => request.fields.get("refresh_token"))).toEqual([
    "REFRESH_2",
    "ROTATED_1",
  ]);
  expect(refreshes.map((request) => request.fields.get("scope"))).toEqual([
    "read:records",
    "read:records",
  ]);
});

it("constructs OIDC logout only for an allowlisted app destination and revokes server-side", async () => {
  const f = await presetFixture(createAuth0Provider(options), endpoints);
  const signed = await f.signIn();
  await expect(
    f.logout(signed.cookie, { providerLogout: true, returnTo: "https://foreign.example.test/" }),
  ).rejects.toMatchObject({ code: "configuration" });
  const loggedOut = await f.logout(signed.cookie, {
    providerLogout: true,
    revoke: true,
    returnTo: "/signed-out",
  });
  const location = new URL(loggedOut.response.headers.get("location")!);
  expect(location.origin + location.pathname).toBe(endpoints.logout);
  expect(location.searchParams.get("client_id")).toBe(clientId);
  expect(location.searchParams.get("post_logout_redirect_uri")).toBe(`${appOrigin}/signed-out`);
  expect(location.searchParams.has("client_secret")).toBe(false);
  expect((await f.engine.resolve(f.appRequest(signed.cookie))).authenticated).toBe(false);
  const revoked = f.requests.filter((request) => request.url === endpoints.revocation);
  expect(revoked).toHaveLength(1);
  expect(revoked[0]!.fields.get("token")).toBe("REFRESH_1");
});
