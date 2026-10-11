import { afterEach, expect, it } from "vite-plus/test";
import { createMicrosoftProvider } from "../src/providers/microsoft";
import { createOidcProvider } from "../src/server";
import {
  closePresetFixtures,
  presetFixture,
  clientId,
  clientSecret,
} from "./provider-preset-fixture";

afterEach(closePresetFixtures);
const tenant = "12345678-1234-1234-1234-123456789abc";
const issuer = `https://login.microsoftonline.com/${tenant}/v2.0`;
const options = { id: "microsoft", tenantId: tenant, clientId, clientSecret };
const graph = "https://graph.microsoft.com";
const read = `${graph}/User.Read`;
const mail = `${graph}/Mail.Read`;
const custom = "api://custom-api";
const customRead = `${custom}/User.Read`;
const resources = [{ resource: graph, scopes: [read, mail] }];
const endpoints = {
  authorization: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`,
  token: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
  jwks: "https://login.microsoftonline.com/common/discovery/v2.0/keys",
  logout: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/logout`,
  resourceParameter: null,
  responseScopes: (requested: string) =>
    requested
      .split(" ")
      .filter((scope) => scope.startsWith(`${graph}/`))
      .join(" "),
};

it("defines an exact single-tenant confidential policy without generic revocation", () => {
  const p = createMicrosoftProvider(options);
  expect(p.issuer).toBe(issuer);
  expect(p.identityScopes).toEqual(["email", "offline_access", "openid", "profile"]);
  expect(p.capabilities).toEqual({
    renewal: "refresh",
    incrementalConsent: true,
    providerLogout: true,
    revocation: false,
    resources: [],
  });
});
it.each(["common", "organizations", "consumers", "", "12345678-1234-1234-1234-123456789abg"])(
  "rejects unsupported tenant %s",
  (tenantId) => {
    expect(() => createMicrosoftProvider({ ...options, tenantId })).toThrow(
      expect.objectContaining({ code: "configuration" }),
    );
  },
);
it("requires qualified permissions belonging to the explicitly configured API", () => {
  expect(() =>
    createMicrosoftProvider({
      ...options,
      resources: [{ resource: graph, scopes: ["User.Read"] }],
    }),
  ).toThrow(expect.objectContaining({ code: "configuration" }));
  expect(() =>
    createMicrosoftProvider({
      ...options,
      resources: [{ resource: graph, scopes: ["https://foreign.test/User.Read"] }],
    }),
  ).toThrow(expect.objectContaining({ code: "configuration" }));
});
it("sends qualified authorization scopes without any resource, audience or null-key parameter", async () => {
  const f = await presetFixture(createMicrosoftProvider({ ...options, resources }), endpoints);
  f.setClaims({ tid: tenant });
  const started = await f.start("", { resource: graph, scopes: [read] });
  expect(started.authorization.searchParams.get("scope")!.split(" ")).toEqual(
    expect.arrayContaining(["openid", "offline_access", read]),
  );
  for (const field of ["resource", "audience", "null"])
    expect(started.authorization.searchParams.has(field)).toBe(false);
  await f.complete(started);
  expect(f.requests).toHaveLength(1);
  for (const field of ["resource", "audience", "null"])
    expect(f.requests[0]!.fields.has(field)).toBe(false);
});
it("validates signed identity separately from API and offline permissions", async () => {
  const f = await presetFixture(createMicrosoftProvider({ ...options, resources }), endpoints);
  f.setClaims({ tid: tenant });
  const signed = await f.signIn();
  expect((await f.engine.resolve(f.appRequest(signed.cookie))).scopes).toEqual(["openid"]);
  const consented = await f.signIn(signed.cookie, { resource: graph, scopes: [read] });
  expect(
    await f.engine.token(f.appRequest(consented.cookie), "microsoft", {
      resource: graph,
      scopes: [read],
    }),
  ).toBe("ACCESS_2_identity");
  expect((await f.engine.resolve(f.appRequest(consented.cookie))).scopes).toEqual(["openid"]);
  await expect(
    f.engine.token(f.appRequest(consented.cookie), "microsoft", {
      resource: graph,
      scopes: [mail],
    }),
  ).rejects.toMatchObject({ reason: "consent", resource: graph, scopes: [mail] });
  f.advance(31_000);
  expect(
    await f.engine.token(f.appRequest(consented.cookie), "microsoft", {
      resource: graph,
      scopes: [read],
    }),
  ).toBe("RENEWED_1");
  const renewed = f.requests.filter(
    (request) => request.fields.get("grant_type") === "refresh_token",
  );
  expect(renewed[0]!.fields.get("scope")).toBe(read);
  expect(renewed[0]!.fields.get("refresh_token")).toBe("REFRESH_2");
});
it.each(["User.Read", "uSeR.rEaD", `${graph}/USER.read`])(
  "accepts Graph's documented response permission form %s",
  async (scope) => {
    const f = await presetFixture(createMicrosoftProvider({ ...options, resources }), endpoints);
    f.setClaims({ tid: tenant });
    f.setResponseScopes(() => scope);
    const signed = await f.signIn("", { resource: graph, scopes: [read] });
    expect(
      await f.engine.token(f.appRequest(signed.cookie), "microsoft", {
        resource: graph,
        scopes: [read],
      }),
    ).toBe("ACCESS_1_identity");
    expect((await f.engine.resolve(f.appRequest(signed.cookie))).scopes).toEqual(["openid"]);
    f.advance(31_000);
    expect(
      await f.engine.token(f.appRequest(signed.cookie), "microsoft", {
        resource: graph,
        scopes: [read],
      }),
    ).toBe("RENEWED_1");
  },
);
it("uses absent callback scope only for the sealed selected API request, with multiple resources configured", async () => {
  const f = await presetFixture(
    createMicrosoftProvider({
      ...options,
      resources: [...resources, { resource: custom, scopes: [customRead] }],
    }),
    endpoints,
  );
  f.setClaims({ tid: tenant });
  f.setResponseScopes(() => undefined);
  const signed = await f.signIn("", { resource: graph, scopes: [read] });
  expect(
    await f.engine.token(f.appRequest(signed.cookie), "microsoft", {
      resource: graph,
      scopes: [read],
    }),
  ).toBe("ACCESS_1_identity");
  expect((await f.engine.resolve(f.appRequest(signed.cookie))).scopes).toEqual(["openid"]);
  await expect(
    f.engine.token(f.appRequest(signed.cookie), "microsoft", { resource: graph, scopes: [mail] }),
  ).rejects.toMatchObject({ reason: "consent", resource: graph, scopes: [mail] });
  await expect(
    f.engine.token(f.appRequest(signed.cookie), "microsoft", {
      resource: custom,
      scopes: [customRead],
    }),
  ).rejects.toMatchObject({ reason: "consent", resource: custom, scopes: [customRead] });
});
it("bounds absent refresh scope to the outgoing current request rather than a broader previous grant", async () => {
  const f = await presetFixture(createMicrosoftProvider({ ...options, resources }), endpoints);
  f.setClaims({ tid: tenant });
  const broad = await f.signIn("", { resource: graph, scopes: [read, mail] });
  const exactRead = await f.signIn(broad.cookie, { resource: graph, scopes: [read] });
  const signed = await f.signIn(exactRead.cookie, { resource: graph, scopes: [mail] });
  f.advance(31_000);
  f.setResponseScopes(() => undefined);
  expect(
    await f.engine.token(f.appRequest(signed.cookie), "microsoft", {
      resource: graph,
      scopes: [read],
    }),
  ).toBe("RENEWED_1");
  expect(
    await f.engine.token(f.appRequest(signed.cookie), "microsoft", {
      resource: graph,
      scopes: [mail],
    }),
  ).toBe("RENEWED_2");
  const renewed = f.requests.filter(
    (request) => request.fields.get("grant_type") === "refresh_token",
  );
  expect(renewed.map((request) => request.fields.get("scope"))).toEqual([read, mail]);
  expect(renewed.map((request) => request.fields.get("refresh_token"))).toEqual([
    "REFRESH_3",
    "ROTATED_1",
  ]);
  expect((await f.engine.resolve(f.appRequest(signed.cookie))).scopes).toEqual(["openid"]);
});
it.each([
  "",
  "openid profile",
  "Mail.Read",
  "https://foreign.test/User.Read",
  "https%3A%2F%2Fgraph.microsoft.com%2FUser.Read",
])("rejects present narrowed or foreign Graph permissions %s", async (scope) => {
  const f = await presetFixture(createMicrosoftProvider({ ...options, resources }), endpoints);
  f.setClaims({ tid: tenant });
  f.setResponseScopes(() => scope);
  await expect(
    f.complete(await f.start("", { resource: graph, scopes: [read] })),
  ).rejects.toMatchObject({
    code: "interaction-required",
    reason: "consent",
    resource: graph,
    scopes: [read],
  });
});
it.each([null, 0, [], {}])(
  "rejects a present malformed scope instead of applying omission fallback %#",
  async (scope) => {
    const f = await presetFixture(createMicrosoftProvider({ ...options, resources }), endpoints);
    f.setClaims({ tid: tenant });
    f.setResponseScopes(() => scope);
    await expect(
      f.complete(await f.start("", { resource: graph, scopes: [read] })),
    ).rejects.toMatchObject({ code: "provider-unavailable" });
  },
);
it.each(["User.Read", `${custom}/user.read`, read])(
  "keeps non-Graph resource permissions exact despite matching short names %s",
  async (scope) => {
    const f = await presetFixture(
      createMicrosoftProvider({
        ...options,
        resources: [...resources, { resource: custom, scopes: [customRead] }],
      }),
      endpoints,
    );
    f.setClaims({ tid: tenant });
    f.setResponseScopes(() => scope);
    await expect(
      f.complete(await f.start("", { resource: custom, scopes: [customRead] })),
    ).rejects.toMatchObject({
      code: "interaction-required",
      reason: "consent",
      resource: custom,
      scopes: [customRead],
    });
  },
);
it("accepts an exact non-Graph permission without changing the configured canonical key", async () => {
  const f = await presetFixture(
    createMicrosoftProvider({
      ...options,
      resources: [{ resource: custom, scopes: [customRead] }],
    }),
    endpoints,
  );
  f.setClaims({ tid: tenant });
  f.setResponseScopes(() => customRead);
  const signed = await f.signIn("", { resource: custom, scopes: [customRead] });
  expect(
    await f.engine.token(f.appRequest(signed.cookie), "microsoft", {
      resource: custom,
      scopes: [customRead],
    }),
  ).toBe("ACCESS_1_identity");
});
it.each([
  {
    issuer: "https://login.microsoftonline.com/87654321-4321-4321-4321-cba987654321/v2.0",
    tid: tenant,
  },
  { issuer, tid: "87654321-4321-4321-4321-cba987654321" },
  { issuer: "https://login.microsoftonline.com/{tenantid}/v2.0", tid: tenant },
])("rejects signed foreign/template tenant ownership %#", async (claims) => {
  const f = await presetFixture(createMicrosoftProvider(options), endpoints);
  f.setTokenIssuer(claims.issuer);
  f.setClaims({ tid: claims.tid });
  await expect(f.complete(await f.start())).rejects.toMatchObject({ code: "invalid-callback" });
});
it("uses tenant logout after local allowlist validation without revocation", async () => {
  const f = await presetFixture(createMicrosoftProvider(options), endpoints);
  f.setClaims({ tid: tenant });
  const signed = await f.signIn();
  const out = await f.logout(signed.cookie, { providerLogout: true, returnTo: "/signed-out" });
  const url = new URL(out.response.headers.get("location")!);
  expect(url.origin + url.pathname).toBe(endpoints.logout);
  expect(url.searchParams.get("post_logout_redirect_uri")).toBe(
    "https://app.example.test/signed-out",
  );
  expect((await f.engine.resolve(f.appRequest(signed.cookie))).authenticated).toBe(false);
});
it("retains generic OIDC exact requested-scope checks", async () => {
  const generic = createOidcProvider({
    id: "microsoft",
    issuer,
    clientId,
    clientAuthentication: { method: "client_secret_post", secret: clientSecret },
    identityScopes: ["openid", "profile", "email", "offline_access"],
  });
  const f = await presetFixture(generic, endpoints);
  f.setClaims({ tid: tenant });
  await expect(f.complete(await f.start())).rejects.toMatchObject({
    code: "interaction-required",
    reason: "consent",
  });
});
