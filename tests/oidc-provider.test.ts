import { expect, it } from "vitest";
import { createOidcClient } from "../src/oidc";

const base = {
  issuer: "https://issuer.test",
  clientId: "public-client",
  redirectUri: "https://app.test/callback",
  fetch: async () =>
    Response.json({
      issuer: "https://issuer.test",
      authorization_endpoint: "https://issuer.test/authorize",
      token_endpoint: "https://issuer.test/token",
      jwks_uri: "https://issuer.test/jwks",
    }),
};

it("copies bounded provider parameters without replacing protocol-owned authorization", async () => {
  const authorizationParams = {
    audience: "https://api.test",
    organization: "org_demo",
    prompt: "login",
  };
  const client = createOidcClient({ ...base, authorizationParams });
  authorizationParams.audience = "https://changed.test";
  const request = await client.createAuthorizationRequest({ loginHint: "user@example.test" });
  const url = new URL(request.url);
  expect(Object.fromEntries(url.searchParams)).toMatchObject({
    audience: "https://api.test",
    organization: "org_demo",
    prompt: "login",
    client_id: base.clientId,
    redirect_uri: base.redirectUri,
    response_type: "code",
    code_challenge_method: "S256",
    state: request.state,
    nonce: request.nonce,
    login_hint: "user@example.test",
  });
  expect(url.searchParams.get("code_challenge")).toBeTruthy();
});

it.each([
  "state",
  "nonce",
  "code_challenge",
  "code_challenge_method",
  "code_verifier",
  "client_id",
  "client_secret",
  "response_type",
  "redirect_uri",
  "scope",
  "response_mode",
  "login_hint",
  "STATE",
])("rejects the protocol-owned provider parameter %s", (name) => {
  expect(() => createOidcClient({ ...base, authorizationParams: { [name]: "override" } })).toThrow(
    expect.objectContaining({ code: "invalid-authorization-params" }),
  );
});

it.each([
  null,
  [],
  "audience",
  { audience: 42 },
  { audience: undefined },
  { "invalid key": "value" },
  { ["a".repeat(65)]: "value" },
  { audience: "x".repeat(2049) },
  Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`param${i}`, "value"])),
  Object.fromEntries(Array.from({ length: 5 }, (_, i) => [`param${i}`, "x".repeat(2048)])),
])("rejects an invalid or unbounded provider parameter bag: %j", (authorizationParams) => {
  expect(() => createOidcClient({ ...base, authorizationParams } as never)).toThrow(
    expect.objectContaining({ code: "invalid-authorization-params" }),
  );
});

it("rejects accessors and symbol parameters without invoking application getters", () => {
  let calls = 0;
  const authorizationParams = Object.defineProperty({}, "audience", {
    enumerable: true,
    get() {
      calls++;
      return "api";
    },
  });
  expect(() => createOidcClient({ ...base, authorizationParams })).toThrow(
    expect.objectContaining({ code: "invalid-authorization-params" }),
  );
  expect(calls).toBe(0);
  expect(() =>
    createOidcClient({ ...base, authorizationParams: { [Symbol("audience")]: "api" } }),
  ).toThrow(expect.objectContaining({ code: "invalid-authorization-params" }));
});
