import assert from "node:assert/strict";
import { realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { createAppleProvider } from "@askrjs/auth/providers/apple";
import { InteractionRequiredError, ProviderSessionError } from "@askrjs/auth/server";
import {
  appleFixture,
  appleKey,
  appleOrigin,
  servicesId,
  teamId,
  keyId,
  closeAppleFixtures,
} from "./apple-fixture.mjs";

const entry = "@askrjs/auth/providers/apple";
assert.equal((await import(entry)).createAppleProvider, createAppleProvider);
assert.equal(
  await realpath(fileURLToPath(import.meta.resolve(entry))),
  await realpath(
    fileURLToPath(new URL("node_modules/@askrjs/auth/dist/providers/apple.js", import.meta.url)),
  ),
);
assert.equal(typeof globalThis.window, "undefined");
await assert.rejects(import("@auth0/auth0-spa-js"), { code: "ERR_MODULE_NOT_FOUND" });
const options = { id: "apple", servicesId, teamId, keyId, privateKey: appleKey };
assert.throws(
  () => createAppleProvider({ ...options, teamId: Symbol("private") }),
  (error) => error instanceof ProviderSessionError && error.code === "configuration",
);
try {
  let observation;
  const f = await appleFixture(createAppleProvider(options), {
    onSignIn(value) {
      observation = value;
    },
  });
  f.setClaims({
    email: "signed@example.test",
    email_verified: "true",
    is_private_email: "false",
    roles: ["PRIVATE_ROLE"],
  });
  f.setUser(
    JSON.stringify({
      name: { firstName: "Unsigned Given", lastName: "Unsigned Family" },
      email: "forged@example.test",
    }),
  );
  const started = await f.start();
  assert.equal(started.authorization.searchParams.get("response_mode"), "form_post");
  assert.ok(
    started.response.headers
      .getSetCookie()
      .some((line) => line.includes("__Host-askr-txn-apple=") && line.includes("SameSite=None")),
  );
  assert.equal(
    f.callbackRequest(started).headers.get("cookie").includes("__Host-askr-session="),
    false,
  );
  const signed = await f.complete(started);
  assert.deepEqual(observation.principal, {
    id: JSON.stringify([appleOrigin, "apple-account"]),
    subject: "apple-account",
    email: "signed@example.test",
    email_verified: true,
    is_private_email: false,
  });
  assert.deepEqual(observation.profileHint, {
    givenName: "Unsigned Given",
    familyName: "Unsigned Family",
  });
  const before = await f.engine.resolve(f.appRequest(signed.cookie));
  assert.deepEqual(before.principal, {
    id: JSON.stringify([appleOrigin, "apple-account"]),
    subject: "apple-account",
  });
  assert.deepEqual(before.scopes, ["openid"]);
  assert.equal(JSON.stringify(before).includes("signed@example.test"), false);
  await assert.rejects(f.engine.callback(f.callbackRequest(started), { provider: "apple" }), {
    code: "invalid-transaction",
  });
  f.setRotation(true);
  f.advance(86_400_000 - 1);
  await f.engine.resolve(f.appRequest(signed.cookie));
  assert.equal(f.refreshes, 0);
  f.advance(1);
  const checked = await f.engine.resolve(f.appRequest(signed.cookie));
  assert.deepEqual(checked, before);
  assert.equal(f.refreshes, 1);
  const renewal = f.requests.find(
    (request) => request.fields.get("grant_type") === "refresh_token",
  );
  assert.equal(renewal.fields.get("refresh_token"), "APPLE_REFRESH_1");
  for (const field of ["scope", "resource", "audience"])
    assert.equal(renewal.fields.has(field), false);
  const out = await f.logout(signed.cookie, true);
  assert.equal(out.response.status, 204);
  assert.equal(out.response.headers.has("location"), false);
  assert.equal(f.requests.at(-1).fields.get("token"), "APPLE_ROTATED_1");
  assert.equal((await f.engine.resolve(f.appRequest(signed.cookie))).authenticated, false);
  const revoked = await appleFixture(createAppleProvider(options));
  const other = await revoked.signIn();
  revoked.advance(86_400_000);
  revoked.setRefreshFailure("invalid_grant");
  await assert.rejects(
    revoked.engine.resolve(revoked.appRequest(other.cookie)),
    (error) =>
      error instanceof InteractionRequiredError &&
      error.reason === "login" &&
      error.provider === "apple",
  );
  assert.equal(
    (await revoked.engine.resolve(revoked.appRequest(other.cookie))).authenticated,
    false,
  );
} finally {
  await closeAppleFixtures();
}
