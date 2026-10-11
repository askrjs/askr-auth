import assert from "node:assert/strict";
import { realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { createMicrosoftProvider } from "@askrjs/auth/providers/microsoft";
import { ProviderSessionError } from "@askrjs/auth/server";
import { closePresetFixtures, presetFixture, clientId, clientSecret } from "./preset-fixture.mjs";

const entry = "@askrjs/auth/providers/microsoft";
assert.equal((await import(entry)).createMicrosoftProvider, createMicrosoftProvider);
assert.equal(
  await realpath(fileURLToPath(import.meta.resolve(entry))),
  await realpath(
    fileURLToPath(
      new URL("node_modules/@askrjs/auth/dist/providers/microsoft.js", import.meta.url),
    ),
  ),
);
assert.equal(typeof globalThis.window, "undefined");
await assert.rejects(import("@auth0/auth0-spa-js"), { code: "ERR_MODULE_NOT_FOUND" });
const tenantId = "12345678-1234-1234-1234-123456789abc";
const options = { id: "microsoft", tenantId, clientId, clientSecret };
const graph = "https://graph.microsoft.com";
const read = `${graph}/User.Read`;
const mail = `${graph}/Mail.Read`;
const custom = "api://custom-api";
const customRead = `${custom}/User.Read`;
const resources = [
  { resource: graph, scopes: [read, mail] },
  { resource: custom, scopes: [customRead] },
];
const endpoints = {
  authorization: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`,
  token: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
  jwks: "https://login.microsoftonline.com/common/discovery/v2.0/keys",
  logout: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/logout`,
  resourceParameter: null,
};
assert.throws(
  () => createMicrosoftProvider({ ...options, tenantId: "common" }),
  (error) => error instanceof ProviderSessionError && error.code === "configuration",
);
try {
  const f = await presetFixture(createMicrosoftProvider({ ...options, resources }), endpoints);
  f.setClaims({ tid: tenantId });
  f.setResponseScopes(() => "uSeR.rEaD");
  const started = await f.start("", { resource: graph, scopes: [read] });
  for (const field of ["resource", "audience", "null"])
    assert.equal(started.authorization.searchParams.has(field), false);
  assert.ok(started.authorization.searchParams.get("scope").split(" ").includes(read));
  const signed = await f.complete(started);
  const context = await f.engine.resolve(f.appRequest(signed.cookie));
  assert.equal(context.authenticated, true);
  assert.deepEqual(context.principal, {
    id: JSON.stringify([`https://login.microsoftonline.com/${tenantId}/v2.0`, "account"]),
    subject: "account",
  });
  assert.deepEqual(context.scopes, ["openid"]);
  assert.equal(context.tenant, null);
  assert.equal(context.session.subject, "account");
  assert.equal(
    await f.engine.token(f.appRequest(signed.cookie), "microsoft", {
      resource: graph,
      scopes: [read],
    }),
    "ACCESS_1_identity",
  );
  await assert.rejects(
    f.engine.token(f.appRequest(signed.cookie), "microsoft", { scopes: [read] }),
    { code: "configuration" },
  );
  await assert.rejects(
    f.engine.token(f.appRequest(signed.cookie), "microsoft", {
      resource: custom,
      scopes: [customRead],
    }),
    { code: "interaction-required", reason: "consent", resource: custom },
  );
  f.setResponseScopes(() => undefined);
  const consented = await f.signIn(signed.cookie, { resource: graph, scopes: [mail] });
  f.advance(31_000);
  assert.equal(
    await f.engine.token(f.appRequest(consented.cookie), "microsoft", {
      resource: graph,
      scopes: [read],
    }),
    "RENEWED_1",
  );
  assert.equal(
    await f.engine.token(f.appRequest(consented.cookie), "microsoft", {
      resource: graph,
      scopes: [mail],
    }),
    "RENEWED_2",
  );
  const renewals = f.requests.filter(
    (request) => request.fields.get("grant_type") === "refresh_token",
  );
  assert.deepEqual(
    renewals.map((request) => request.fields.get("scope")),
    [read, mail],
  );
  assert.deepEqual(
    renewals.map((request) => request.fields.get("refresh_token")),
    ["REFRESH_2", "ROTATED_1"],
  );
  for (const request of f.requests)
    for (const field of ["resource", "audience", "null"])
      assert.equal(request.fields.has(field), false);
  assert.deepEqual((await f.engine.resolve(f.appRequest(consented.cookie))).scopes, ["openid"]);
  const out = await f.logout(consented.cookie, { providerLogout: true, returnTo: "/signed-out" });
  const location = new URL(out.response.headers.get("location"));
  assert.equal(location.origin + location.pathname, endpoints.logout);
  assert.equal(
    location.searchParams.get("post_logout_redirect_uri"),
    "https://app.example.test/signed-out",
  );
  assert.equal((await f.engine.resolve(f.appRequest(consented.cookie))).authenticated, false);

  const mismatch = await presetFixture(createMicrosoftProvider(options), endpoints);
  mismatch.setClaims({ tid: "87654321-4321-4321-4321-cba987654321" });
  await assert.rejects(mismatch.complete(await mismatch.start()), { code: "invalid-callback" });
} finally {
  await closePresetFixtures();
}
