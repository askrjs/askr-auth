import { afterEach, expect, it, vi } from "vitest";

const fixture = vi.hoisted(() => ({ clients: [] as any[] }));
vi.mock("@auth0/auth0-spa-js", () => ({
  InMemoryCache: class {
    enclosedCache = (() => {
      const values = new Map();
      return {
        get: (key: string) => values.get(key),
        set: (key: string, value: unknown) => values.set(key, value),
        remove: (key: string) => values.delete(key),
        allKeys: () => [...values.keys()],
      };
    })();
  },
  Auth0Client: class {
    constructor(options: any) {
      const state: any = {
        options,
        user: { sub: "sdk-user", name: "SDK user", roles: ["unmapped"] },
        logouts: 0,
        token: async () => {
          if (!options.cache.get("access"))
            options.cache.set("access", {
              body: {
                client_id: options.clientId,
                audience: options.authorizationParams.audience ?? "default",
                access_token: "access",
              },
              expiresAt: Math.floor(Date.now() / 1000) + 3600,
            });
          return { access_token: "access", token_type: "Bearer", expires_in: 3600 };
        },
        login: async (input: any) => {
          await input.openUrl("https://login.test/authorize?state=sdk-state");
        },
        callback: async () => {},
      };
      fixture.clients.push(state);
      Object.assign(this, {
        getTokenSilently: (...args: any[]) => state.token(...args),
        getUser: async () => state.user,
        loginWithRedirect: (input: any) => state.login(input),
        handleRedirectCallback: (url: string) => state.callback(url),
        logout: async (input: any) => {
          state.logouts++;
          state.logoutOptions = input;
          for (const key of options.cache.allKeys()) options.cache.remove(key);
        },
      });
    }
  },
}));

import { createAuth0Session } from "../src/auth0";

const options = {
  domain: "https://login.test",
  clientId: "client",
  redirectUri: "https://app.test/callback",
  authorizationParams: { audience: "https://api.test" },
};
afterEach(() => {
  fixture.clients.length = 0;
  vi.useRealTimers();
});

it("uses the existing session contract and SDK-owned absolute cache expiry", async () => {
  vi.useFakeTimers();
  vi.setSystemTime(1_000_000);
  const session = createAuth0Session(options);
  const first = await session.getToken();
  vi.setSystemTime(1_030_000);
  const repeated = await session.getToken();
  expect(first).toMatchObject({
    status: "authenticated",
    accessToken: "access",
    expiresAt: 4_600_000,
    principal: { id: "sdk-user", subject: "sdk-user", name: "SDK user" },
  });
  expect(repeated).toEqual(first);
  expect(first.status === "authenticated" && first.principal.roles).toBeUndefined();
  expect(fixture.clients[0].options.cache).toBeDefined();
  expect(fixture.clients[0].options.cacheLocation).toBeUndefined();
  session.dispose();
});

it.each(["logout", "dispose", "login"] as const)(
  "promptly retires uncancellable SDK work through %s",
  async (action) => {
    const session = createAuth0Session(options);
    await session.getToken();
    const old = fixture.clients[0];
    let release!: () => void;
    old.token = () =>
      new Promise((resolve) => {
        release = () => {
          old.options.cache.set("late", {
            body: { access_token: "stale", client_id: "client", audience: "https://api.test" },
            expiresAt: Date.now() / 1000 + 3600,
          });
          resolve({ access_token: "stale", token_type: "Bearer" });
        };
      });
    const pending = session.getToken().catch((error) => error.code);
    await Promise.resolve();
    await Promise.resolve();
    if (action === "login") await session.login();
    else session[action]();
    expect(
      await Promise.race([
        pending,
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error("Retirement did not settle pending SDK work.")), 100),
        ),
      ]),
    ).toBe("cancelled");
    release();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(old.options.cache.allKeys()).toEqual([]);
    expect(old.logoutOptions).toEqual({ openUrl: false });
    if (action === "dispose")
      expect(() => session.getToken()).toThrow(expect.objectContaining({ code: "disposed" }));
    else if (action === "logout")
      expect(await session.getToken()).toMatchObject({
        status: "authenticated",
        accessToken: "access",
      });
    session.dispose();
  },
);

it("returns the SDK URL for application-owned navigation and rejects callbacks after local logout", async () => {
  const session = createAuth0Session(options);
  expect(await session.login()).toBe("https://login.test/authorize?state=sdk-state");
  expect(await session.getToken()).toEqual({
    status: "interaction-required",
    error: "login_required",
  });
  session.logout();
  await expect(
    session.restore("https://app.test/callback?code=old&state=sdk-state"),
  ).rejects.toMatchObject({ code: "invalid-transaction" });
  session.dispose();
  session.dispose();
  await expect(session.login()).rejects.toMatchObject({ code: "disposed" });
});

it("maps only SDK interaction outcomes and preserves authoritative failures", async () => {
  const session = createAuth0Session(options);
  await session.getToken();
  fixture.clients[0].token = async () => {
    throw { error: "consent_required", error_description: "Consent is needed." };
  };
  expect(await session.getToken()).toEqual({
    status: "interaction-required",
    error: "consent_required",
    description: "Consent is needed.",
  });
  const failure = { error: "access_denied", message: "Provider denied authorization." };
  fixture.clients[0].token = async () => {
    throw failure;
  };
  await expect(session.getToken()).rejects.toMatchObject({
    code: "authorization-error",
    cause: failure,
  });
  session.dispose();
});

it("requires a matching finite SDK cache record instead of extending detailedResponse.expires_in", async () => {
  const session = createAuth0Session(options);
  await session.getToken();
  fixture.clients[0].options.cache.remove("access");
  fixture.clients[0].token = async () => ({
    access_token: "uncorrelated",
    token_type: "Bearer",
    expires_in: 3600,
  });
  await expect(session.getToken()).rejects.toMatchObject({ code: "invalid-token-response" });
  session.dispose();
});

it.each([
  { scopes: 123 },
  { issuer: 123 },
  { scopes: ["bad scope"] },
  { domain: "http://login.test" },
  { domain: "https://user:secret@login.test" },
  { domain: "https://login.test?query=1" },
  { clientId: "" },
  { clientSecret: "secret" },
  { redirectUri: "not-a-url" },
  { redirectUri: "https://app.test/callback?extra=1" },
  { authorizationTimeoutSeconds: 0 },
  { authorizationTimeoutSeconds: 121 },
  { leewaySeconds: 0 },
  { leewaySeconds: Infinity },
  { leewaySeconds: -1 },
  { useRefreshTokens: "yes" },
  { useRefreshTokensFallback: true },
  { cache: {} },
  { cacheLocation: "localstorage" },
])("rejects unsupported Auth0 options: %j", (override) => {
  expect(() => createAuth0Session({ ...options, ...override } as never)).toThrow(
    expect.objectContaining({ code: "invalid-options" }),
  );
});
