import { afterEach, expect, it } from "vite-plus/test";
import { createGoogleProvider } from "../src/providers/google";
import type { ProviderSessionRecord, ProviderSessionStore } from "../src/server";
import {
  closePresetFixtures,
  presetFixture,
  clientId,
  clientSecret,
} from "./provider-preset-fixture";

afterEach(closePresetFixtures);
const options = { id: "google", clientId, clientSecret };
const resource = "https://www.googleapis.com";
const drive = "https://www.googleapis.com/auth/drive.readonly";
const mail = "https://www.googleapis.com/auth/gmail.readonly";
const resources = [{ resource, scopes: [drive, mail] }];
const endpoints = {
  authorization: "https://accounts.google.com/o/oauth2/v2/auth",
  token: "https://oauth2.googleapis.com/token",
  jwks: "https://www.googleapis.com/oauth2/v3/certs",
  revocation: "https://oauth2.googleapis.com/revoke",
  resourceParameter: null,
};

// Test-owned atomic authority, not an OIDC/token validation stub.
function authority() {
  const rows = new Map<string, ProviderSessionRecord>();
  const queues = new Map<string, Promise<void>>();
  let barrier: (() => Promise<void>) | undefined;
  const store: ProviderSessionStore = {
    async read(id, { signal }) {
      if (signal.aborted) throw new DOMException("Cancelled", "AbortError");
      return rows.get(id) ?? null;
    },
    async compareAndSwap(id, expected, next, { signal }) {
      if (signal.aborted) throw new DOMException("Cancelled", "AbortError");
      const previous = rows.get(id);
      if (
        (previous?.revision ?? null) !== expected ||
        previous?.retired ||
        next.revision !== (expected === null ? 0 : expected + 1)
      )
        return false;
      rows.set(id, Object.freeze({ ...next }));
      return true;
    },
    async withLock(key, operation, { signal }) {
      if (barrier && key.startsWith("authority:")) {
        const wait = barrier;
        barrier = undefined;
        await wait();
      }
      const previous = queues.get(key) ?? Promise.resolve();
      const result = previous.then(() => {
        if (signal.aborted) throw new DOMException("Cancelled", "AbortError");
        return operation();
      });
      const tail = result.then(
        () => undefined,
        () => undefined,
      );
      queues.set(key, tail);
      void tail.then(() => {
        if (queues.get(key) === tail) queues.delete(key);
      });
      return result;
    },
  };
  return {
    store,
    holdNextAuthority(wait: () => Promise<void>) {
      barrier = wait;
    },
  };
}
async function observed(predicate: () => boolean) {
  const deadline = Date.now() + 2000;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("Owned authority transition did not enter.");
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
}

it("defines confidential offline Web OAuth without a provider logout redirect", () => {
  const p = createGoogleProvider(options);
  expect(p.issuer).toBe("https://accounts.google.com");
  expect(p.identityScopes).toEqual(["email", "openid", "profile"]);
  expect(p.capabilities).toEqual({
    renewal: "refresh",
    incrementalConsent: true,
    providerLogout: false,
    revocation: true,
    resources: [],
  });
});
it.each(["https://example.com", "*.example.com", "EXAMPLE.com", null, Symbol("private")])(
  "rejects malformed hosted-domain input safely %#",
  (hostedDomain) => {
    expect(() => createGoogleProvider({ ...options, hostedDomain: hostedDomain as never })).toThrow(
      expect.objectContaining({ code: "configuration" }),
    );
  },
);
it("does not accept offline_access as a Google identity scope", () => {
  expect(() =>
    createGoogleProvider({ ...options, identityScopes: ["openid", "offline_access"] as never }),
  ).toThrow(expect.objectContaining({ code: "configuration" }));
});
it.each(["https://accounts.google.com", "accounts.google.com"])(
  "canonicalizes only Google's signed issuer spelling %s",
  async (issuer) => {
    const f = await presetFixture(createGoogleProvider(options), endpoints);
    f.setTokenIssuer(issuer);
    const signed = await f.signIn();
    const context = await f.engine.resolve(f.appRequest(signed.cookie));
    expect(context.principal).toEqual({
      id: JSON.stringify(["https://accounts.google.com", "account"]),
      subject: "account",
    });
  },
);
it.each(["https://accounts.google.com/", "https://foreign.test"])(
  "rejects unconfigured signed issuer spelling %s",
  async (issuer) => {
    const f = await presetFixture(createGoogleProvider(options), endpoints);
    f.setTokenIssuer(issuer);
    await expect(f.complete(await f.start())).rejects.toMatchObject({ code: "invalid-callback" });
  },
);
it.each([undefined, "foreign.test", "EXAMPLE.com"])(
  "enforces signed hosted-domain policy despite the authorization hint %#",
  async (hd) => {
    const f = await presetFixture(
      createGoogleProvider({ ...options, hostedDomain: "example.com" }),
      endpoints,
    );
    f.setClaims({ hd });
    const started = await f.start();
    expect(started.authorization.searchParams.get("hd")).toBe("example.com");
    await expect(f.complete(started)).rejects.toMatchObject({ code: "invalid-callback" });
  },
);
it("accepts the exact signed hosted domain without putting arbitrary claims in the app snapshot", async () => {
  const f = await presetFixture(
    createGoogleProvider({ ...options, hostedDomain: "example.com" }),
    endpoints,
  );
  f.setClaims({ hd: "example.com", email: "PRIVATE_SIGNED_EMAIL" });
  const signed = await f.signIn();
  expect(JSON.stringify(await f.engine.resolve(f.appRequest(signed.cookie)))).not.toContain(
    "PRIVATE_SIGNED_EMAIL",
  );
});
it("requests offline incremental access without forcing first-login consent or sending generic resource fields", async () => {
  const f = await presetFixture(createGoogleProvider({ ...options, resources }), endpoints);
  const started = await f.start("", { resource, scopes: [drive] });
  expect(started.authorization.searchParams.get("access_type")).toBe("offline");
  expect(started.authorization.searchParams.get("include_granted_scopes")).toBe("true");
  expect(started.authorization.searchParams.has("prompt")).toBe(false);
  for (const field of ["resource", "audience", "null"])
    expect(started.authorization.searchParams.has(field)).toBe(false);
  await f.complete(started);
  for (const field of ["resource", "audience", "null"])
    expect(f.requests[0]!.fields.has(field)).toBe(false);
});
it("separates actual API permission grants from signed identity and unconfirmed profile/email", async () => {
  const f = await presetFixture(createGoogleProvider({ ...options, resources }), endpoints);
  f.setResponseScopes(() => drive);
  const signed = await f.signIn("", { resource, scopes: [drive] });
  expect(
    await f.engine.token(f.appRequest(signed.cookie), "google", { resource, scopes: [drive] }),
  ).toBe("ACCESS_1_identity");
  expect((await f.engine.resolve(f.appRequest(signed.cookie))).scopes).toEqual(["openid"]);
  await expect(
    f.engine.token(f.appRequest(signed.cookie), "google", { resource, scopes: [mail] }),
  ).rejects.toMatchObject({
    code: "interaction-required",
    reason: "consent",
    resource,
    scopes: [mail],
  });
});
it("normalizes Google's actual identity aliases only in the identity snapshot", async () => {
  const f = await presetFixture(createGoogleProvider(options), endpoints);
  f.setResponseScopes(
    () =>
      "openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile",
  );
  const signed = await f.signIn();
  expect((await f.engine.resolve(f.appRequest(signed.cookie))).scopes).toEqual([
    "email",
    "openid",
    "profile",
  ]);
});
it("does not use an identity alias to satisfy an explicitly configured API URL permission", async () => {
  const email = "https://www.googleapis.com/auth/userinfo.email";
  const f = await presetFixture(
    createGoogleProvider({ ...options, resources: [{ resource, scopes: [email] }] }),
    endpoints,
  );
  f.setResponseScopes(() => "openid email");
  await expect(f.complete(await f.start("", { resource, scopes: [email] }))).rejects.toMatchObject({
    code: "interaction-required",
    reason: "consent",
    resource,
    scopes: [email],
  });
});
it.each([undefined, null, 0, [], {}])(
  "does not copy Microsoft's absent/malformed scope fallback %#",
  async (scope) => {
    const f = await presetFixture(createGoogleProvider({ ...options, resources }), endpoints);
    f.setResponseScopes(() => scope);
    await expect(
      f.complete(await f.start("", { resource, scopes: [drive] })),
    ).rejects.toMatchObject({ code: "provider-unavailable" });
  },
);
it.each(["", "openid profile email", drive.toUpperCase(), mail])(
  "requires exact present API scope %s",
  async (scope) => {
    const f = await presetFixture(createGoogleProvider({ ...options, resources }), endpoints);
    f.setResponseScopes(() => scope);
    await expect(
      f.complete(await f.start("", { resource, scopes: [drive] })),
    ).rejects.toMatchObject({
      code: "interaction-required",
      reason: "consent",
      resource,
      scopes: [drive],
    });
  },
);
it("recovers a missing refresh grant through explicit current-owner consent and real renewal", async () => {
  const f = await presetFixture(createGoogleProvider({ ...options, resources }), {
    ...endpoints,
    issueRefreshToken: false,
  });
  const first = await f.start("", { resource, scopes: [drive] });
  expect(first.authorization.searchParams.has("prompt")).toBe(false);
  const signed = await f.complete(first);
  f.advance(31_000);
  await expect(
    f.engine.token(f.appRequest(signed.cookie), "google", { resource, scopes: [drive] }),
  ).rejects.toMatchObject({ reason: "login", resource });
  const consent = await f.start(signed.cookie, { resource, scopes: [drive] });
  expect(consent.authorization.searchParams.get("prompt")).toBe("consent");
  f.setIssueRefreshToken(true);
  const recovered = await f.complete(consent);
  f.advance(31_000);
  expect(
    await f.engine.token(f.appRequest(recovered.cookie), "google", { resource, scopes: [drive] }),
  ).toBe("RENEWED_1");
});
it("does not force consent while the latest authority has a usable refresh family", async () => {
  const f = await presetFixture(createGoogleProvider({ ...options, resources }), endpoints);
  const signed = await f.signIn("", { resource, scopes: [drive] });
  const next = await f.start(signed.cookie, { resource, scopes: [mail] });
  expect(next.authorization.searchParams.has("prompt")).toBe(false);
});
it("forces consent for persisted refresh uncertainty and never restores the uncertain old grant", async () => {
  const f = await presetFixture(createGoogleProvider({ ...options, resources }), endpoints);
  const signed = await f.signIn("", { resource, scopes: [drive] });
  f.advance(31_000);
  f.setResponseScopes(() => null);
  await expect(
    f.engine.token(f.appRequest(signed.cookie), "google", { resource, scopes: [drive] }),
  ).rejects.toMatchObject({ code: "provider-unavailable" });
  f.setResponseScopes(() => drive);
  const started = await f.start(signed.cookie, { resource, scopes: [drive] });
  expect(started.authorization.searchParams.get("prompt")).toBe("consent");
  f.setIssueRefreshToken(false);
  const replaced = await f.complete(started);
  f.advance(31_000);
  await expect(
    f.engine.token(f.appRequest(replaced.cookie), "google", { resource, scopes: [drive] }),
  ).rejects.toMatchObject({ reason: "login", resource });
});
it.each(["other-provider", "changed-policy"])(
  "does not force consent from foreign ownership %s",
  async (kind) => {
    const shared = authority();
    const f = await presetFixture(createGoogleProvider({ ...options, resources }), {
      ...endpoints,
      issueRefreshToken: false,
      store: shared.store,
    });
    const signed = await f.signIn("", { resource, scopes: [drive] });
    const other = createGoogleProvider({
      ...options,
      resources,
      ...(kind === "other-provider" ? { id: "other" } : { hostedDomain: "example.com" }),
    });
    const g = await presetFixture(other, { ...endpoints, store: shared.store });
    const started = await g.start(signed.cookie, { resource, scopes: [drive] });
    expect(started.authorization.searchParams.has("prompt")).toBe(false);
  },
);
it("rechecks the locked authority after logout rather than publishing stale consent", async () => {
  const shared = authority();
  const f = await presetFixture(createGoogleProvider({ ...options, resources }), {
    ...endpoints,
    issueRefreshToken: false,
    store: shared.store,
  });
  const signed = await f.signIn("", { resource, scopes: [drive] });
  let entered = false;
  let release!: () => void;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  shared.holdNextAuthority(async () => {
    entered = true;
    await held;
  });
  const started = f.start(signed.cookie, { resource, scopes: [drive] });
  void started.catch(() => undefined);
  try {
    await observed(() => entered);
    await f.logout(signed.cookie);
    release();
    await expect(started).rejects.toMatchObject({ code: "invalid-transaction" });
  } finally {
    release();
    await started.catch(() => undefined);
  }
  expect(f.exchanges).toBe(1);
});
it("supports local logout plus real token revocation without a provider redirect", async () => {
  const f = await presetFixture(createGoogleProvider(options), endpoints);
  const signed = await f.signIn();
  await expect(f.logout(signed.cookie, { providerLogout: true })).rejects.toMatchObject({
    code: "configuration",
  });
  const out = await f.logout(signed.cookie, { revoke: true });
  expect(out.response.status).toBe(204);
  expect(out.response.headers.has("location")).toBe(false);
  expect((await f.engine.resolve(f.appRequest(signed.cookie))).authenticated).toBe(false);
  expect(
    f.requests.find((request) => request.url === endpoints.revocation)!.fields.get("token"),
  ).toBe("REFRESH_1");
});
