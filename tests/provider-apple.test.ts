import { afterEach, describe, expect, it } from "vite-plus/test";
import { createAppleProvider } from "../src/providers/apple";
import { InteractionRequiredError } from "../src/server";
import type { ProviderSessionRecord, ProviderSessionStore } from "../src/server";
import {
  appleFixture,
  appleKey,
  servicesId,
  teamId,
  keyId,
  appleOrigin,
  boundedObservation,
  closeAppleFixtures,
} from "./provider-apple-fixture";

afterEach(closeAppleFixtures);
const options = () => ({ id: "apple", servicesId, teamId, keyId, privateKey: { ...appleKey } });
const provider = () => createAppleProvider(options());
const day = 86_400_000;
interface ObservedSettlement<T> {
  value(): Promise<T>;
  error(): Promise<unknown>;
  drain(): Promise<void>;
}
function observeSettlement<T>(pending: Promise<T>): ObservedSettlement<T> {
  let result: { kind: "fulfilled"; value: T } | { kind: "rejected"; error: unknown } | undefined;
  // Observe immediately so cleanup never leaves a later rejection unhandled.
  void pending.then(
    (value) => {
      result = { kind: "fulfilled", value };
    },
    (error: unknown) => {
      result = { kind: "rejected", error };
    },
  );
  async function settled() {
    await boundedObservation(() => result !== undefined);
    if (result === undefined) throw new Error("Owned operation did not settle");
    return result;
  }
  return {
    async value() {
      const outcome = await settled();
      if (outcome.kind === "rejected") throw outcome.error;
      return outcome.value;
    },
    async error() {
      const outcome = await settled();
      expect(outcome.kind).toBe("rejected");
      if (outcome.kind !== "rejected") throw new Error("Owned operation unexpectedly fulfilled");
      return outcome.error;
    },
    async drain() {
      await settled();
    },
  };
}
function ownedStore() {
  const records = new Map<string, ProviderSessionRecord>();
  const locks = new Map<string, Promise<void>>();
  let fail = false;
  const store: ProviderSessionStore = {
    async read(id) {
      return records.get(id) ?? null;
    },
    async compareAndSwap(id, revision, next) {
      if (fail) throw new Error("PRIVATE_STORE_CANARY");
      if ((records.get(id)?.revision ?? null) !== revision) return false;
      records.set(id, next);
      return true;
    },
    async withLock(key, operation) {
      const prior = locks.get(key) ?? Promise.resolve();
      let release!: () => void;
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      const tail = prior.then(() => gate);
      locks.set(key, tail);
      await prior;
      try {
        return await operation();
      } finally {
        release();
        if (locks.get(key) === tail) locks.delete(key);
      }
    },
  };
  return {
    store,
    setFailure(value: boolean) {
      fail = value;
    },
    records,
  };
}
describe("Apple server preset", () => {
  it("owns exact immutable protocol policy without API bearer or provider logout", async () => {
    const p = provider();
    expect(p.issuer).toBe(appleOrigin);
    expect(p.clientId).toBe(servicesId);
    expect(p.responseMode).toBe("form_post");
    expect(p.identityScopes).toEqual(["email", "name", "openid"]);
    expect(p.capabilities).toEqual({
      renewal: "account-check",
      incrementalConsent: false,
      providerLogout: false,
      revocation: true,
      resources: [],
    });
    const f = await appleFixture(p);
    await expect(f.engine.token(f.appRequest(""), "apple", { scopes: [] })).rejects.toMatchObject({
      code: "configuration",
    });
    await expect(
      f.engine.login(f.appRequest(""), {
        provider: "apple",
        returnTo: "/",
        resource: "api",
        scopes: [],
      }),
    ).rejects.toMatchObject({ code: "configuration" });
    await expect(
      f.engine.logout(f.appRequest(""), { provider: "apple", providerLogout: true }),
    ).rejects.toMatchObject({ code: "configuration" });
  });
  it.each([
    { teamId: "short" },
    { keyId: "lowercase1" },
    { servicesId: "https://foreign.test" },
    { teamId: Symbol("private") },
    { keyId: null },
    { servicesId: Symbol("private") },
    { privateKey: null },
    { privateKey: { ...appleKey, kty: "RSA" } },
    { privateKey: { ...appleKey, d: "not-canonical" } },
    { privateKey: { ...appleKey, alg: "RS256" } },
    { privateKey: { ...appleKey, use: "enc" } },
    { privateKey: { ...appleKey, key_ops: ["verify"] } },
  ])("rejects malformed runtime setup safely (%#)", (invalid) => {
    // @ts-expect-error Deliberately exercise malformed JavaScript configuration.
    expect(() => createAppleProvider({ ...options(), ...invalid })).toThrow(
      expect.objectContaining({ code: "configuration" }),
    );
  });
  it("copies the supplied private key and verifies real ES256 secrets/cache/clock boundaries", async () => {
    const input = options();
    const p = createAppleProvider(input);
    input.privateKey.d = "A".repeat(43);
    const f = await appleFixture(p);
    const first = await f.signIn();
    const initial = f.requests[0]!.secret;
    f.advance(1000);
    const second = await f.signIn(first.cookie);
    expect(f.requests[1]!.secret).toBe(initial);
    f.advance(270_000);
    const third = await f.signIn(second.cookie);
    expect(f.requests[2]!.secret).not.toBe(initial);
    f.advance(-500_000);
    await f.signIn(third.cookie);
    expect(f.requests[3]!.secretClaims.iat).toBe(Math.floor(f.time / 1000));
    expect(f.requests[3]!.secret).not.toBe(f.requests[2]!.secret);
  });
  it("owns failed crypto import at actual first use without an unhandled rejection", async () => {
    const observed: unknown[] = [];
    const listener = (error: unknown) => {
      observed.push(error);
    };
    process.on("unhandledRejection", listener);
    try {
      const f = await appleFixture(
        createAppleProvider({
          ...options(),
          privateKey: { ...appleKey, x: "A".repeat(43), y: "A".repeat(43) },
        }),
      );
      await expect(f.complete(await f.start())).rejects.toMatchObject({ code: "configuration" });
      await new Promise((resolve) => setTimeout(resolve, 0));
      expect(observed).toEqual([]);
      expect(f.exchanges).toBe(0);
    } finally {
      process.off("unhandledRejection", listener);
    }
  });
  it("consumes a Secure form_post transaction without the Lax app cookie and rejects copied replay", async () => {
    const f = await appleFixture(provider());
    const started = await f.start();
    expect(
      started.response.headers
        .getSetCookie()
        .find((line) => line.startsWith("__Host-askr-txn-apple=")),
    ).toContain("SameSite=None");
    const request = f.callbackRequest(started);
    expect(request.headers.get("cookie")).not.toContain("__Host-askr-session=");
    const signed = await f.complete(started);
    expect((await f.engine.resolve(f.appRequest(signed.cookie))).authenticated).toBe(true);
    await expect(
      f.engine.callback(f.callbackRequest(started), { provider: "apple" }),
    ).rejects.toMatchObject({ code: "invalid-transaction" });
    expect(f.exchanges).toBe(1);
  });
  it("consumes oversized declared ingress before body/exchange and copied replay", async () => {
    const f = await appleFixture(provider());
    const started = await f.start();
    const request = f.callbackRequest(started);
    request.headers.set("content-length", "32769");
    await expect(f.engine.callback(request, { provider: "apple" })).rejects.toMatchObject({
      code: "invalid-callback",
    });
    await expect(
      f.engine.callback(f.callbackRequest(started), { provider: "apple" }),
    ).rejects.toMatchObject({ code: "invalid-transaction" });
    expect(f.exchanges).toBe(0);
  });
  it("bounds the actual streamed form before exchange and consumes the copied transaction", async () => {
    const f = await appleFixture(provider());
    f.setUser("x".repeat(32_769));
    const started = await f.start();
    await expect(
      f.engine.callback(f.callbackRequest(started), { provider: "apple" }),
    ).rejects.toMatchObject({ code: "invalid-callback" });
    await expect(
      f.engine.callback(f.callbackRequest(started), { provider: "apple" }),
    ).rejects.toMatchObject({ code: "invalid-transaction" });
    expect(f.exchanges).toBe(0);
  });
  it("rejects an actual invalid identity signature", async () => {
    const f = await appleFixture(provider());
    f.setInvalidSignature(true);
    await expect(f.signIn()).rejects.toMatchObject({ code: "invalid-callback" });
  });
  it("does not publish a client-secret cache entry after the signing owner is cancelled", async () => {
    const p = provider();
    const secret = p.clientAuthentication.secret;
    if (typeof secret !== "function") throw new Error("Apple requires an owned secret factory");
    const f = await appleFixture(p);
    const abort = new AbortController();
    const pending = Promise.resolve(secret({ now: f.time - 1000, signal: abort.signal }));
    const observed = pending.catch((error: unknown) => error);
    abort.abort();
    expect(await observed).toMatchObject({ name: "AbortError" });
    await f.signIn();
    expect(f.requests[0]!.secretClaims.iat).toBe(f.time / 1000);
  });
  it.each([
    { iss: "https://foreign.test" },
    { aud: "wrong-service" },
    { nonce: "wrong-nonce" },
    { sub: "" },
    { exp: 0 },
  ])("rejects invalid signed identity (%#)", async (claims) => {
    const f = await appleFixture(provider());
    f.setClaims(claims);
    await expect(f.complete(await f.start())).rejects.toMatchObject({ code: "invalid-callback" });
  });
  it("keeps signed normalized Apple claims and unsigned names only in the server hook", async () => {
    const seen: { readonly principal: unknown; readonly profileHint?: unknown }[] = [];
    const f = await appleFixture(provider(), {
      onSignIn(context) {
        seen.push(context);
      },
    });
    f.setClaims({
      email: "signed@example.test",
      email_verified: "true",
      is_private_email: "false",
      roles: ["private-role"],
      arbitrary: "PRIVATE_CLAIM",
    });
    f.setUser(
      JSON.stringify({
        name: { firstName: "Given <untrusted>", lastName: "Family" },
        email: "unsigned@example.test",
        sub: "foreign",
        roles: ["admin"],
      }),
    );
    const signed = await f.signIn();
    expect(seen[0]!.principal).toEqual({
      id: JSON.stringify([appleOrigin, "apple-account"]),
      subject: "apple-account",
      email: "signed@example.test",
      email_verified: true,
      is_private_email: false,
    });
    expect(seen[0]!.profileHint).toEqual({ givenName: "Given <untrusted>", familyName: "Family" });
    const context = await f.engine.resolve(f.appRequest(signed.cookie));
    expect(context.principal).toEqual({
      id: JSON.stringify([appleOrigin, "apple-account"]),
      subject: "apple-account",
    });
    expect(context.scopes).toEqual(["openid"]);
    expect(JSON.stringify(context)).not.toMatch(/email|Given|Family|PRIVATE|role/u);
    f.advance(day);
    await f.engine.resolve(f.appRequest(signed.cookie));
    expect(seen).toHaveLength(1);
  });
  it("accepts empty managed-account email and boolean claims without inventing a missing user hint", async () => {
    let principal: unknown;
    let hint: unknown = "not-called";
    const f = await appleFixture(provider(), {
      onSignIn(value) {
        principal = value.principal;
        hint = value.profileHint;
      },
    });
    f.setClaims({ email: "", email_verified: false, is_private_email: true });
    await f.signIn();
    expect(principal).toMatchObject({ email: "", email_verified: false, is_private_email: true });
    expect(hint).toBeUndefined();
  });
  it.each([
    { email_verified: "TRUE" },
    { is_private_email: 1 },
    { email: null },
    { email: "line\nprivate" },
  ])("rejects malformed signed projection (%#)", async (claims) => {
    const f = await appleFixture(provider());
    f.setClaims(claims);
    await expect(f.signIn()).rejects.toMatchObject({ code: "invalid-callback" });
  });
  it.each([
    "not-json",
    "null",
    JSON.stringify({ name: { firstName: 42 } }),
    JSON.stringify({ name: { lastName: "x".repeat(257) } }),
    "x".repeat(4097),
  ])("rejects malformed unsigned profile before exchange (%#)", async (user) => {
    const f = await appleFixture(provider());
    f.setUser(user);
    await expect(f.signIn()).rejects.toMatchObject({ code: "invalid-callback" });
    expect(f.exchanges).toBe(0);
  });
  it("checks at the exact daily boundary while preserving app expiry and retaining an omitted refresh token", async () => {
    const f = await appleFixture(provider());
    const signed = await f.signIn();
    const initial = await f.engine.resolve(f.appRequest(signed.cookie));
    f.advance(day - 1);
    await f.engine.resolve(f.appRequest(signed.cookie));
    expect(f.refreshes).toBe(0);
    f.advance(1);
    const checked = await f.engine.resolve(f.appRequest(signed.cookie));
    expect(f.refreshes).toBe(1);
    expect(checked).toEqual(initial);
    f.advance(day);
    await f.engine.resolve(f.appRequest(signed.cookie));
    expect(f.refreshes).toBe(2);
    expect(
      f.requests
        .filter((r) => r.fields.get("grant_type") === "refresh_token")
        .map((r) => r.fields.get("refresh_token")),
    ).toEqual(["APPLE_REFRESH_1", "APPLE_REFRESH_1"]);
  });
  it("does not certify an interval after the clock moves backwards", async () => {
    const f = await appleFixture(provider());
    const signed = await f.signIn();
    f.advance(-1000);
    await f.engine.resolve(f.appRequest(signed.cookie));
    expect(f.refreshes).toBe(1);
  });
  it("serializes two engine owners through the real shared-store family lock", async () => {
    const owned = ownedStore();
    const f = await appleFixture(provider(), { store: owned.store });
    const other = f.sibling();
    const signed = await f.signIn();
    f.advance(day);
    const hold = f.holdRefresh();
    const first = observeSettlement(f.engine.resolve(f.appRequest(signed.cookie)));
    let second: ObservedSettlement<Awaited<ReturnType<typeof other.resolve>>> | undefined;
    try {
      await boundedObservation(() => hold.entered);
      second = observeSettlement(other.resolve(f.appRequest(signed.cookie)));
      await new Promise((resolve) => setTimeout(resolve, 25));
      expect(f.refreshes).toBe(1);
      hold.release();
      expect((await first.value()).authenticated).toBe(true);
      expect((await second.value()).authenticated).toBe(true);
      expect(f.refreshes).toBe(1);
    } finally {
      hold.release();
      await Promise.all([first.drain(), second?.drain()]);
    }
  });
  it("deduplicates two daily waiters without giving the aborted starter ownership", async () => {
    const f = await appleFixture(provider());
    const signed = await f.signIn();
    f.advance(day);
    const hold = f.holdRefresh();
    const abort = new AbortController();
    const first = observeSettlement(f.engine.resolve(f.appRequest(signed.cookie, abort.signal)));
    let second: ObservedSettlement<Awaited<ReturnType<typeof f.engine.resolve>>> | undefined;
    try {
      await boundedObservation(() => hold.entered);
      second = observeSettlement(f.engine.resolve(f.appRequest(signed.cookie)));
      abort.abort();
      expect(await first.error()).toMatchObject({ name: "AbortError" });
      hold.release();
      expect((await second.value()).authenticated).toBe(true);
      expect(f.refreshes).toBe(1);
    } finally {
      hold.release();
      await Promise.all([first.drain(), second?.drain()]);
    }
  });
  it("uses the latest rotated family and retires confirmed invalid_grant for BOTH joined callers", async () => {
    const owned = ownedStore();
    const f = await appleFixture(provider(), { store: owned.store });
    const signed = await f.signIn();
    const sessionId = (await f.engine.resolve(f.appRequest(signed.cookie))).session!.id;
    f.setRotation(true);
    f.advance(day);
    await f.engine.resolve(f.appRequest(signed.cookie));
    f.advance(day);
    f.setRefreshFailure("invalid_grant");
    const hold = f.holdRefresh();
    const first = observeSettlement(f.engine.resolve(f.appRequest(signed.cookie)));
    const observed = [first];
    try {
      await boundedObservation(() => hold.entered);
      observed.push(observeSettlement(f.engine.resolve(f.appRequest(signed.cookie))));
      await new Promise((resolve) => setTimeout(resolve, 25));
      expect(f.refreshes).toBe(2);
      hold.release();
      for (const error of await Promise.all(observed.map((operation) => operation.error()))) {
        expect(error).toBeInstanceOf(InteractionRequiredError);
        expect(error).toMatchObject({
          code: "interaction-required",
          reason: "login",
          provider: "apple",
          scopes: ["email", "name", "openid"],
        });
      }
      const retired = observeSettlement(f.engine.resolve(f.appRequest(signed.cookie)));
      observed.push(retired);
      expect((await retired.value()).authenticated).toBe(false);
      expect(f.refreshes).toBe(2);
      expect(owned.records.get(sessionId)).toMatchObject({ retired: true, value: null });
      expect(
        f.requests
          .filter((r) => r.fields.get("grant_type") === "refresh_token")[1]!
          .fields.get("refresh_token"),
      ).toBe("APPLE_ROTATED_1");
    } finally {
      hold.release();
      await Promise.all(observed.map((operation) => operation.drain()));
    }
  });
  it.each(["logout", "close", "request"] as const)(
    "preserves genuine %s cancellation before terminal CAS",
    async (action) => {
      const f = await appleFixture(provider());
      const signed = await f.signIn();
      f.advance(day);
      f.setRefreshFailure("invalid_grant");
      const hold = f.holdRefresh();
      const abort = new AbortController();
      const pending = observeSettlement(
        f.engine.resolve(f.appRequest(signed.cookie, abort.signal)),
      );
      let cancellation: ObservedSettlement<unknown> | undefined;
      try {
        await boundedObservation(() => hold.entered);
        if (action === "logout") cancellation = observeSettlement(f.logout(signed.cookie));
        else if (action === "close") cancellation = observeSettlement(f.engine.close());
        else abort.abort();
        if (cancellation) await cancellation.value();
        expect(await pending.error()).toMatchObject({ name: "AbortError" });
      } finally {
        hold.release();
        await Promise.all([pending.drain(), cancellation?.drain()]);
      }
    },
  );
  it("preserves transport uncertainty without resending the refresh grant", async () => {
    const f = await appleFixture(provider());
    const signed = await f.signIn();
    f.advance(day);
    f.setTransportFailure(true);
    await expect(f.engine.resolve(f.appRequest(signed.cookie))).rejects.toMatchObject({
      code: "provider-unavailable",
    });
    f.setTransportFailure(false);
    await expect(f.engine.resolve(f.appRequest(signed.cookie))).rejects.toMatchObject({
      code: "interaction-required",
      reason: "login",
    });
    expect(f.refreshes).toBe(1);
  });
  it("requests typed login for a missing refresh grant without an upstream check", async () => {
    const f = await appleFixture(provider());
    f.setIssueRefreshToken(false);
    const signed = await f.signIn();
    f.advance(day);
    await expect(f.engine.resolve(f.appRequest(signed.cookie))).rejects.toMatchObject({
      code: "interaction-required",
      reason: "login",
      provider: "apple",
    });
    expect(f.refreshes).toBe(0);
  });
  it("keeps store failure distinct from interaction and fences the uncertain grant", async () => {
    const owned = ownedStore();
    const f = await appleFixture(provider(), { store: owned.store });
    const signed = await f.signIn();
    f.advance(day);
    const hold = f.holdRefresh();
    const pending = observeSettlement(f.engine.resolve(f.appRequest(signed.cookie)));
    let retry: ObservedSettlement<Awaited<ReturnType<typeof f.engine.resolve>>> | undefined;
    try {
      await boundedObservation(() => hold.entered);
      owned.setFailure(true);
      hold.release();
      expect(await pending.error()).toMatchObject({ code: "store-unavailable" });
      owned.setFailure(false);
      retry = observeSettlement(f.engine.resolve(f.appRequest(signed.cookie)));
      expect(await retry.error()).toMatchObject({
        code: "interaction-required",
        reason: "login",
      });
      expect(f.refreshes).toBe(1);
    } finally {
      owned.setFailure(false);
      hold.release();
      await Promise.all([pending.drain(), retry?.drain()]);
    }
  });
  it.each([
    undefined,
    { sub: "changed-account" },
    { exp: 0 },
    { iss: "https://foreign.test" },
    { nonce: "wrong-present-nonce" },
  ])("rejects invalid refresh identity without advancing authority (%#)", async (claims) => {
    const f = await appleFixture(provider());
    const signed = await f.signIn();
    f.advance(day);
    if (claims === undefined) f.setRefreshIdToken(false);
    else f.setRefreshClaims(claims);
    await expect(f.engine.resolve(f.appRequest(signed.cookie))).rejects.toMatchObject({
      code: "provider-unavailable",
    });
    await expect(f.engine.resolve(f.appRequest(signed.cookie))).rejects.toMatchObject({
      code: "interaction-required",
      reason: "login",
    });
    expect(f.refreshes).toBe(1);
  });
  it("cannot publish held old checks after a successful new login", async () => {
    const f = await appleFixture(provider());
    const signed = await f.signIn();
    f.advance(day);
    const hold = f.holdRefresh();
    const old = observeSettlement(f.engine.resolve(f.appRequest(signed.cookie)));
    const observed: ObservedSettlement<unknown>[] = [old];
    try {
      await boundedObservation(() => hold.entered);
      const login = observeSettlement(f.signIn(signed.cookie));
      observed.push(login);
      const newer = await login.value();
      expect(await old.error()).toMatchObject({ name: "AbortError" });
      hold.release();
      const current = observeSettlement(f.engine.resolve(f.appRequest(newer.cookie)));
      observed.push(current);
      expect((await current.value()).authenticated).toBe(true);
      const previous = observeSettlement(f.engine.resolve(f.appRequest(signed.cookie)));
      observed.push(previous);
      expect((await previous.value()).authenticated).toBe(false);
    } finally {
      hold.release();
      await Promise.all(observed.map((operation) => operation.drain()));
    }
  });
  it("drops a previously staged checked-session issuance after logout", async () => {
    const f = await appleFixture(provider());
    const signed = await f.signIn();
    f.advance(day);
    const old = f.appRequest(signed.cookie);
    await f.engine.resolve(old);
    await f.logout(signed.cookie);
    expect((await f.engine.finalize(old, new Response("private"))).headers.getSetCookie()).toEqual(
      [],
    );
  });
  it("returns anonymous at absolute expiry without another account HTTP call", async () => {
    const f = await appleFixture(provider(), { maxAgeSeconds: 86400 });
    const signed = await f.signIn();
    f.advance(day);
    expect((await f.engine.resolve(f.appRequest(signed.cookie))).authenticated).toBe(false);
    expect(f.refreshes).toBe(0);
  });
  it("cannot commit an allocated held check across absolute application expiry", async () => {
    const f = await appleFixture(provider(), { maxAgeSeconds: 86401 });
    const signed = await f.signIn();
    f.advance(day);
    const hold = f.holdRefresh();
    const pending = observeSettlement(f.engine.resolve(f.appRequest(signed.cookie)));
    const observed: ObservedSettlement<unknown>[] = [pending];
    try {
      await boundedObservation(() => hold.entered);
      f.advance(1000);
      const expired = observeSettlement(f.engine.resolve(f.appRequest(signed.cookie)));
      observed.push(expired);
      expect((await expired.value()).authenticated).toBe(false);
      expect(await pending.error()).toMatchObject({ name: "AbortError" });
      hold.release();
      const after = observeSettlement(f.engine.resolve(f.appRequest(signed.cookie)));
      observed.push(after);
      expect((await after.value()).authenticated).toBe(false);
    } finally {
      hold.release();
      await Promise.all(observed.map((operation) => operation.drain()));
    }
  });
  it("revokes the current family after local retirement without a provider redirect", async () => {
    const f = await appleFixture(provider());
    const signed = await f.signIn();
    f.setRotation(true);
    f.advance(day);
    await f.engine.resolve(f.appRequest(signed.cookie));
    const out = await f.logout(signed.cookie, true);
    expect(out.response.status).toBe(204);
    expect(out.response.headers.has("location")).toBe(false);
    expect(f.requests.at(-1)!.fields.get("token")).toBe("APPLE_ROTATED_1");
    expect((await f.engine.resolve(f.appRequest(signed.cookie))).authenticated).toBe(false);
  });
});
