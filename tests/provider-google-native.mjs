import assert from "node:assert/strict";
import { realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { createGoogleProvider } from "@askrjs/auth/providers/google";
import { ProviderSessionError } from "@askrjs/auth/server";
import { closePresetFixtures, presetFixture, clientId, clientSecret } from "./preset-fixture.mjs";

const entry = "@askrjs/auth/providers/google";
assert.equal((await import(entry)).createGoogleProvider, createGoogleProvider);
assert.equal(
  await realpath(fileURLToPath(import.meta.resolve(entry))),
  await realpath(
    fileURLToPath(new URL("node_modules/@askrjs/auth/dist/providers/google.js", import.meta.url)),
  ),
);
assert.equal(typeof globalThis.window, "undefined");
await assert.rejects(import("@auth0/auth0-spa-js"), { code: "ERR_MODULE_NOT_FOUND" });
const options = { id: "google", clientId, clientSecret, hostedDomain: "example.com" };
assert.throws(
  () => createGoogleProvider({ ...options, hostedDomain: Symbol("private") }),
  (error) => error instanceof ProviderSessionError && error.code === "configuration",
);
const resource = "https://www.googleapis.com";
const drive = "https://www.googleapis.com/auth/drive.readonly";
const mail = "https://www.googleapis.com/auth/gmail.readonly";
const endpoints = {
  authorization: "https://accounts.google.com/o/oauth2/v2/auth",
  token: "https://oauth2.googleapis.com/token",
  jwks: "https://www.googleapis.com/oauth2/v3/certs",
  revocation: "https://oauth2.googleapis.com/revoke",
  resourceParameter: null,
};
try {
  const f = await presetFixture(
    createGoogleProvider({ ...options, resources: [{ resource, scopes: [drive, mail] }] }),
    endpoints,
  );
  f.setClaims({ hd: "example.com", email: "SIGNED_PRIVATE_EMAIL" });
  f.setTokenIssuer("accounts.google.com");
  f.setResponseScopes(() => drive);
  const started = await f.start("", { resource, scopes: [drive] });
  assert.equal(started.authorization.searchParams.get("access_type"), "offline");
  assert.equal(started.authorization.searchParams.get("include_granted_scopes"), "true");
  assert.equal(started.authorization.searchParams.get("hd"), "example.com");
  assert.equal(started.authorization.searchParams.has("prompt"), false);
  for (const field of ["resource", "audience", "null"])
    assert.equal(started.authorization.searchParams.has(field), false);
  const signed = await f.complete(started);
  const context = await f.engine.resolve(f.appRequest(signed.cookie));
  assert.deepEqual(context.principal, {
    id: JSON.stringify(["https://accounts.google.com", "account"]),
    subject: "account",
  });
  assert.deepEqual(context.scopes, ["openid"]);
  assert.equal(JSON.stringify(context).includes("SIGNED_PRIVATE_EMAIL"), false);
  assert.equal(
    await f.engine.token(f.appRequest(signed.cookie), "google", { resource, scopes: [drive] }),
    "ACCESS_1_identity",
  );
  await assert.rejects(
    f.engine.token(f.appRequest(signed.cookie), "google", { resource, scopes: [mail] }),
    { code: "interaction-required", reason: "consent", resource },
  );
  f.advance(31_000);
  assert.equal(
    await f.engine.token(f.appRequest(signed.cookie), "google", { resource, scopes: [drive] }),
    "RENEWED_1",
  );
  const renewal = f.requests.find(
    (request) => request.fields.get("grant_type") === "refresh_token",
  );
  assert.equal(renewal.fields.get("scope"), drive);
  assert.equal(renewal.fields.get("refresh_token"), "REFRESH_1");
  for (const request of f.requests)
    for (const field of ["resource", "audience", "null"])
      assert.equal(request.fields.has(field), false);
  const out = await f.logout(signed.cookie, { revoke: true });
  assert.equal(out.response.status, 204);
  assert.equal(out.response.headers.has("location"), false);
  assert.equal((await f.engine.resolve(f.appRequest(signed.cookie))).authenticated, false);
  assert.equal(
    f.requests.find((request) => request.url === endpoints.revocation).fields.get("token"),
    "ROTATED_1",
  );
  const wrongDomain = await presetFixture(createGoogleProvider(options), endpoints);
  wrongDomain.setClaims({ hd: "foreign.test" });
  await assert.rejects(wrongDomain.complete(await wrongDomain.start()), {
    code: "invalid-callback",
  });
} finally {
  await closePresetFixtures();
}
