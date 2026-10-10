import { expect, it } from "vite-plus/test";
import { createBrowserOidcSession, BrowserOidcSessionError } from "../src/browser";

const options = {
  issuer: "https://issuer.test",
  clientId: "public-client",
  redirectUri: "https://app.test/callback",
};

it("imports and configures browser sessions without touching DOM in Node", async () => {
  const values = new Map<string, string>();
  const session = createBrowserOidcSession({
    ...options,
    transactionStorage: {
      getItem: (key) => values.get(key) ?? null,
      setItem: (key, value) => {
        values.set(key, value);
      },
      removeItem: (key) => {
        values.delete(key);
      },
    },
  });
  expect(await session.getToken()).toEqual({
    status: "interaction-required",
    error: "login_required",
  });
  session.logout();
  session.dispose();
  session.dispose();
  expect(() => session.getToken()).toThrow(BrowserOidcSessionError);
});

it.each([
  { transactionTtlMs: -1 },
  { transactionTtlMs: 600_001 },
  { transactionTtlMs: NaN },
  { clockLeewaySeconds: Infinity },
  { clockLeewaySeconds: -1 },
  { silent: { timeoutMs: 0 } },
  { silent: { timeoutMs: 120_001 } },
  { silent: { responseFormat: "auto" } },
  { silent: { redirectUri: "https://other-app.test/callback" } },
  { redirectUri: "https://app.test/callback?unbound=1" },
  { redirectUri: "not-an-absolute-url" },
  { redirectUri: "file:///callback" },
  { clientId: "" },
  { clientSecret: "never-in-a-browser" },
])("rejects invalid public-client options: %j", (override) => {
  expect(() => createBrowserOidcSession({ ...options, ...override })).toThrow(
    BrowserOidcSessionError,
  );
});

it("identifies malformed callback URLs", () => {
  const session = createBrowserOidcSession(options);
  expect(() => session.restore("not-an-absolute-url")).toThrow(BrowserOidcSessionError);
});

it("reports unavailable transaction storage and still retires disposed ownership", async () => {
  const session = createBrowserOidcSession({
    ...options,
    transactionStorage: {
      getItem: () => {
        throw new Error("blocked");
      },
      setItem: () => {
        throw new Error("blocked");
      },
      removeItem: () => {
        throw new Error("blocked");
      },
    },
  });
  await expect(session.login()).rejects.toMatchObject({ code: "storage-unavailable" });
  expect(() => session.dispose()).toThrow(BrowserOidcSessionError);
  expect(() => session.getToken()).toThrow(BrowserOidcSessionError);
});
