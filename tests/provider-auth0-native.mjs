import assert from "node:assert/strict";
import { realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { createAuth0Provider } from "@askrjs/auth/providers/auth0";
import { ProviderSessionError } from "@askrjs/auth/server";
import { closePresetFixtures, presetFixture, clientId, clientSecret } from "./preset-fixture.mjs";

const entry = "@askrjs/auth/providers/auth0";
assert.equal((await import(entry)).createAuth0Provider, createAuth0Provider);
assert.equal(
  await realpath(fileURLToPath(import.meta.resolve(entry))),
  await realpath(
    fileURLToPath(new URL("node_modules/@askrjs/auth/dist/providers/auth0.js", import.meta.url)),
  ),
);
assert.equal(typeof globalThis.window, "undefined");
await assert.rejects(import("@auth0/auth0-spa-js"), { code: "ERR_MODULE_NOT_FOUND" });
assert.throws(
  () =>
    createAuth0Provider({ id: "auth0", domain: "https://foreign.test", clientId, clientSecret }),
  (error) => error instanceof ProviderSessionError && error.code === "configuration",
);

const options = { id: "auth0", domain: "tenant.auth0.test", clientId, clientSecret };
const first = "https://first-api.example.test";
const second = "https://second-api.example.test";
const resources = [first, second].map((resource) => ({ resource, scopes: ["read:records"] }));
const endpoints = {
  authorization: "https://tenant.auth0.test/authorize",
  token: "https://tenant.auth0.test/oauth/token",
  jwks: "https://tenant.auth0.test/.well-known/jwks.json",
  logout: "https://tenant.auth0.test/oidc/logout",
  revocation: "https://tenant.auth0.test/oauth/revoke",
  resourceParameter: "audience",
};

try {
  const f = await presetFixture(
    createAuth0Provider({
      ...options,
      resources,
      organization: "org_expected",
      organizationName: "acme",
      connection: "enterprise",
    }),
    endpoints,
  );
  f.setClaims({ org_id: "org_expected", org_name: "acme", email: "PRIVATE_SIGNED_PROFILE" });
  const started = await f.start("", { resource: first, scopes: ["read:records"] });
  assert.equal(started.authorization.searchParams.get("audience"), first);
  assert.equal(started.authorization.searchParams.get("organization"), "org_expected");
  assert.equal(started.authorization.searchParams.get("connection"), "enterprise");
  const signed = await f.complete(started);
  const context = await f.engine.resolve(f.appRequest(signed.cookie));
  assert.equal(context.authenticated, true);
  assert.deepEqual(context.principal, {
    id: JSON.stringify(["https://tenant.auth0.test/", "account"]),
    subject: "account",
  });
  assert.ok(!JSON.stringify(context).includes("PRIVATE_SIGNED_PROFILE"));
  assert.equal(
    await f.engine.token(f.appRequest(signed.cookie), "auth0", {
      resource: first,
      scopes: ["read:records"],
    }),
    `ACCESS_1_${first}`,
  );
  await assert.rejects(
    f.engine.token(f.appRequest(signed.cookie), "auth0", {
      resource: second,
      scopes: ["read:records"],
    }),
    { code: "interaction-required", reason: "consent", resource: second },
  );
  const consented = await f.signIn(signed.cookie, { resource: second, scopes: ["read:records"] });
  f.advance(31_000);
  assert.deepEqual(
    new Set(
      await Promise.all(
        [first, second].map((resource) =>
          f.engine.token(f.appRequest(consented.cookie), "auth0", {
            resource,
            scopes: ["read:records"],
          }),
        ),
      ),
    ),
    new Set(["RENEWED_1", "RENEWED_2"]),
  );
  const grants = f.requests.filter(
    (request) => request.fields.get("grant_type") === "refresh_token",
  );
  assert.deepEqual(
    grants.map((request) => request.fields.get("audience")),
    [first, second],
  );
  assert.deepEqual(
    grants.map((request) => request.fields.get("refresh_token")),
    ["REFRESH_2", "ROTATED_1"],
  );
  await assert.rejects(
    f.logout(consented.cookie, { providerLogout: true, returnTo: "https://foreign.test/" }),
    { code: "configuration" },
  );
  const loggedOut = await f.logout(consented.cookie, {
    providerLogout: true,
    revoke: true,
    returnTo: "/signed-out",
  });
  const location = new URL(loggedOut.response.headers.get("location"));
  assert.equal(location.origin + location.pathname, endpoints.logout);
  assert.equal(
    location.searchParams.get("post_logout_redirect_uri"),
    "https://app.example.test/signed-out",
  );
  assert.equal((await f.engine.resolve(f.appRequest(consented.cookie))).authenticated, false);
  assert.equal(
    f.requests.find((request) => request.url === endpoints.revocation).fields.get("token"),
    "ROTATED_2",
  );

  const mismatch = await presetFixture(
    createAuth0Provider({ ...options, organization: "org_expected", organizationName: "acme" }),
    endpoints,
  );
  mismatch.setClaims({ org_id: "org_expected", org_name: "foreign" });
  await assert.rejects(mismatch.complete(await mismatch.start()), { code: "invalid-callback" });
} finally {
  await closePresetFixtures();
}
