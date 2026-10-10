import { readCookie } from "./auth-cookie";
import { codeChallenge, randomString } from "./oidc-crypto";
import { requestOidcToken } from "./oidc-token";
import { providerPolicy, resourceName, scopeList } from "./provider-definition";
import {
  configurationError,
  InteractionRequiredError,
  ProviderSessionError,
} from "./provider-session-error";
import {
  boundedInteger,
  checkCancellation,
  memoryAuthority,
  sessionSealer,
  waitFor,
} from "./provider-session-storage";
import {
  confidentialAuthentication,
  exchangeProviderTokens,
  providerMetadata,
  providerTransport,
  validateProviderIdentity,
} from "./provider-session-oidc";
import type { AuthContext, Principal } from "./model";
import type {
  ProviderDefinition,
  ProviderSession,
  ProviderSessionOptions,
  ProviderSessionRecord,
} from "./provider-session-types";

const sessionCookie = "__Host-askr-session";
const transactionCookie = (provider: string) => `__Host-askr-txn-${provider}`;
const anonymous: AuthContext = Object.freeze({
  authenticated: false,
  principal: null,
  session: null,
  tenant: null,
});
interface Grant {
  resource?: string;
  scopes: readonly string[];
  accessToken: string;
  expiresAt: number;
}
interface Authority {
  kind: "authority";
  id: string;
  epoch: string;
  generation: number;
  expiresAt: number;
  provider?: string;
  fingerprint?: string;
  principal?: Principal;
  nonce?: string;
  refreshToken?: string;
  refreshing?: string;
  identityScopes: readonly string[];
  grants: readonly Grant[];
  pending: readonly string[];
  pendingUntil?: number;
}
interface Transaction {
  kind: "transaction";
  id: string;
  authorityId: string;
  epoch: string;
  generation: number;
  provider: string;
  fingerprint: string;
  state: string;
  nonce: string;
  verifier: string;
  createdAt: number;
  expiresAt: number;
  returnTo: string;
  resource?: string;
  scopes: readonly string[];
}
interface LocatedAuthority {
  record: ProviderSessionRecord;
  value: Authority;
}
interface Issuance {
  name: string;
  line: string;
  id?: string;
  epoch?: string;
  revision?: number;
  generation?: number;
  retired?: boolean;
  expiresAt?: number;
}
interface RequestState {
  pending: Map<string, Issuance>;
  ownedLines: Set<string>;
}

function localPath(value: string, origin: string): string {
  if (
    typeof value !== "string" ||
    !value.startsWith("/") ||
    value.startsWith("//") ||
    value.length > 2048 ||
    /[\\\s\x00-\x1f\x7f]/u.test(value)
  )
    throw configurationError();
  const url = new URL(value, origin);
  if (url.origin !== origin) throw configurationError();
  return `${url.pathname}${url.search}${url.hash}`;
}
function cookieLine(
  name: string,
  value: string,
  age: number,
  sameSite: "Lax" | "None" = "Lax",
): string {
  const line = `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=${Math.max(0, Math.floor(age))}`;
  if (new TextEncoder().encode(line).length > 3800)
    throw new ProviderSessionError("session-oversize");
  return line;
}

/** Confidential provider sessions share one atomic authority and one application cookie. */
export function createProviderSession(options: ProviderSessionOptions): ProviderSession {
  if (
    !options ||
    !options.session ||
    !Array.isArray(options.providers) ||
    !options.providers.length ||
    options.providers.length > 32
  )
    throw configurationError();
  let origin: string;
  try {
    const url = new URL(options.origin);
    if (url.protocol !== "https:" || url.origin !== options.origin) throw new Error();
    origin = url.origin;
  } catch {
    throw configurationError();
  }
  const providers = new Map<string, ProviderDefinition>();
  for (const provider of options.providers) {
    providerPolicy(provider);
    if (providers.has(provider.id)) throw configurationError();
    providers.set(provider.id, provider);
  }
  const maxAge = boundedInteger(options.session.maxAgeSeconds, 28_800, 1, 2_592_000);
  const leeway = boundedInteger(options.session.leewaySeconds, 30, 0, 300);
  const transactionTtl = boundedInteger(options.transactionTtlSeconds, 300, 1, 600);
  const maxEntries = boundedInteger(options.session.maxEntries, 10_000, 1, 1_000_000);
  if (
    (options.clock !== undefined && typeof options.clock !== "function") ||
    (options.fetch !== undefined && typeof options.fetch !== "function") ||
    (options.onSignIn !== undefined && typeof options.onSignIn !== "function")
  )
    throw configurationError();
  const clock = options.clock ?? Date.now;
  const now = () => {
    let value: number;
    try {
      value = clock();
    } catch {
      throw configurationError();
    }
    if (!Number.isSafeInteger(value) || value < 0) throw configurationError();
    return value;
  };
  now();
  const sealer = sessionSealer(origin, options.session.secrets);
  const storeMode = options.session.store !== undefined;
  const store = options.session.store ?? memoryAuthority(maxEntries, now);
  if (
    !store ||
    [store.read, store.compareAndSwap, store.withLock].some(
      (method) => typeof method !== "function",
    )
  )
    throw configurationError();
  const fetcher = options.fetch ?? globalThis.fetch;
  const onSignIn = options.onSignIn;
  const postLogout = options.postLogoutRedirects ?? ["/"];
  if (!Array.isArray(postLogout) || !postLogout.length || postLogout.length > 32)
    throw configurationError();
  const logoutPaths = new Set(Array.from(postLogout, (path) => localPath(path, origin)));
  const lifetime = new AbortController();
  const identityExpired = Symbol("identity-expired");
  const identities = new Map<string, { controller: AbortController; expiresAt: number }>();
  const transactions = new Map<string, AbortController>();
  const requests = new WeakMap<Request, RequestState>();
  const renewals = new Map<string, Promise<{ authority: LocatedAuthority; token: string }>>();
  let closed = false;
  const live = () => {
    if (closed) throw new ProviderSessionError("closed");
    const time = now();
    for (const [key, owner] of identities)
      if (owner.expiresAt <= time) {
        identities.delete(key);
        owner.controller.abort(identityExpired);
      }
  };
  const composed = (...signals: (AbortSignal | undefined)[]) =>
    AbortSignal.any([
      lifetime.signal,
      ...signals.filter((signal): signal is AbortSignal => signal !== undefined),
    ]);
  const identitySignal = (authority: Authority) => {
    const key = `${authority.id}:${authority.epoch}`;
    let owner = identities.get(key);
    if (!owner) {
      owner = { controller: new AbortController(), expiresAt: authority.expiresAt };
      identities.set(key, owner);
    } else owner.expiresAt = authority.expiresAt;
    return owner.controller.signal;
  };
  const retireLocal = (authority: Authority) => {
    const key = `${authority.id}:${authority.epoch}`;
    identities.get(key)?.controller.abort();
    identities.delete(key);
  };
  const currentProvider = (id: string) => {
    const provider = providers.get(id);
    if (!provider) throw configurationError();
    return provider;
  };
  const state = (request: Request) => {
    let value = requests.get(request);
    if (!value) {
      value = { pending: new Map(), ownedLines: new Set() };
      requests.set(request, value);
    }
    return value;
  };
  const stage = (request: Request, issuance: Issuance) => {
    const value = state(request);
    // One request may publish only its latest application-session owner.
    if (issuance.name === sessionCookie && issuance.id !== undefined) {
      for (const [name, previous] of value.pending)
        if (previous.id !== undefined && previous.id !== issuance.id) value.pending.delete(name);
    }
    value.pending.set(issuance.name, issuance);
    value.ownedLines.add(issuance.line);
  };
  const clearTransaction = (
    request: Request,
    provider: ProviderDefinition,
    owner: Pick<Issuance, "id" | "epoch" | "generation" | "revision" | "retired"> = {},
  ) =>
    stage(request, {
      ...owner,
      name: transactionCookie(provider.id),
      line: cookieLine(
        transactionCookie(provider.id),
        "",
        0,
        provider.responseMode === "form_post" ? "None" : "Lax",
      ),
    });
  async function stored<T>(operation: () => Promise<T>, signal: AbortSignal): Promise<T> {
    live();
    checkCancellation(signal);
    try {
      const value = await waitFor(operation(), signal);
      live();
      checkCancellation(signal);
      return value;
    } catch (error) {
      live();
      checkCancellation(signal);
      if (error instanceof ProviderSessionError || error instanceof InteractionRequiredError)
        throw error;
      throw new ProviderSessionError("store-unavailable");
    }
  }
  async function record(id: string, signal: AbortSignal) {
    const result = await stored(() => store.read(id, { signal }), signal);
    if (
      result !== null &&
      (!Number.isSafeInteger(result.revision) ||
        result.revision < 0 ||
        !Number.isSafeInteger(result.expiresAt) ||
        typeof result.retired !== "boolean" ||
        (result.value !== null && typeof result.value !== "string"))
    )
      throw new ProviderSessionError("store-unavailable");
    return result;
  }
  async function loadAuthority(id: string, signal: AbortSignal): Promise<LocatedAuthority | null> {
    const item = await record(id, signal);
    if (!item || item.retired || item.expiresAt <= now()) return null;
    const value = await waitFor(sealer.open<Authority>("authority", item.value), signal);
    if (
      !value ||
      value.kind !== "authority" ||
      value.id !== id ||
      typeof value.epoch !== "string" ||
      !Number.isSafeInteger(value.generation) ||
      value.expiresAt <= now() ||
      !Array.isArray(value.identityScopes) ||
      !Array.isArray(value.grants) ||
      !Array.isArray(value.pending)
    )
      return null;
    if (
      value.provider &&
      (!providers.has(value.provider) ||
        value.fingerprint !== providerPolicy(currentProvider(value.provider)).fingerprint)
    )
      return null;
    return { record: item, value };
  }
  async function requestAuthority(
    request: Request,
    signal: AbortSignal,
  ): Promise<LocatedAuthority | null> {
    const locator = await waitFor(
      sealer.open<{ id: string; epoch: string; revision: number }>(
        sessionCookie,
        readCookie(request.headers.get("cookie"), sessionCookie),
      ),
      signal,
    );
    if (
      !locator ||
      typeof locator.id !== "string" ||
      typeof locator.epoch !== "string" ||
      !Number.isSafeInteger(locator.revision) ||
      locator.revision < 0
    )
      return null;
    const authority = await loadAuthority(locator.id, signal);
    return authority &&
      authority.value.epoch === locator.epoch &&
      locator.revision <= authority.record.revision
      ? authority
      : null;
  }
  async function sessionIssuance(
    authority: Authority,
    revision: number,
    signal: AbortSignal,
  ): Promise<Issuance> {
    const value = await waitFor(
      sealer.seal(sessionCookie, {
        id: authority.id,
        epoch: authority.epoch,
        revision,
        generation: authority.generation,
        ...(storeMode ? {} : { payload: authority }),
      }),
      signal,
    );
    return {
      name: sessionCookie,
      line: cookieLine(sessionCookie, value, (authority.expiresAt - now()) / 1000),
      id: authority.id,
      epoch: authority.epoch,
      revision,
      expiresAt: authority.expiresAt,
    };
  }
  async function commitAuthority(
    previous: LocatedAuthority | null,
    value: Authority,
    signal: AbortSignal,
  ) {
    const revision = previous ? previous.record.revision + 1 : 0;
    const sealed = await waitFor(sealer.seal("authority", value), signal);
    const issuance = await sessionIssuance(value, revision, signal);
    checkCancellation(signal);
    const next = {
      revision,
      expiresAt: Math.max(
        previous?.record.expiresAt ?? 0,
        value.expiresAt + 300_000,
        (value.pendingUntil ?? 0) + 300_000,
      ),
      retired: false,
      value: sealed,
    };
    if (
      !(await stored(
        () => store.compareAndSwap(value.id, previous?.record.revision ?? null, next, { signal }),
        signal,
      ))
    )
      throw new ProviderSessionError("invalid-transaction");
    return { authority: { record: next, value }, issuance };
  }
  async function consume(id: string, item: ProviderSessionRecord, signal: AbortSignal) {
    return stored(
      () =>
        store.compareAndSwap(
          id,
          item.revision,
          { revision: item.revision + 1, expiresAt: item.expiresAt, retired: true, value: null },
          { signal },
        ),
      signal,
    );
  }
  async function currentTransaction(transaction: Transaction, signal: AbortSignal) {
    live();
    checkCancellation(signal);
    if (transaction.expiresAt <= now()) throw new ProviderSessionError("invalid-transaction");
    const current = await loadAuthority(transaction.authorityId, signal);
    if (
      !current ||
      current.value.epoch !== transaction.epoch ||
      current.value.generation !== transaction.generation
    )
      throw new ProviderSessionError("invalid-transaction");
    return current;
  }
  function requestedScopes(
    provider: ProviderDefinition,
    resource: string | undefined,
    value: readonly string[] | undefined,
  ): readonly string[] {
    const target =
      resource === undefined
        ? undefined
        : provider.capabilities.resources.find(
            (candidate) => candidate.resource === resourceName(resource),
          );
    if (resource !== undefined && !target) throw configurationError();
    const scopes = scopeList(value ?? (target ? target.scopes : provider.identityScopes));
    const allowed = target ? target.scopes : provider.identityScopes;
    if (!scopes.length || scopes.some((scope) => !allowed.includes(scope)))
      throw configurationError();
    return scopes;
  }
  function interaction(
    provider: ProviderDefinition,
    resource: string,
    scopes: readonly string[],
    reason: "login" | "consent" = "login",
  ) {
    return new InteractionRequiredError({ provider: provider.id, resource, scopes, reason });
  }
  async function callbackFields(
    request: Request,
    provider: ProviderDefinition,
    signal: AbortSignal,
  ): Promise<URLSearchParams> {
    const url = new URL(request.url);
    if (url.origin !== origin || url.pathname !== `/auth/callback/${provider.id}` || url.hash)
      throw new ProviderSessionError("invalid-callback");
    const declaredLength = request.headers.get("content-length");
    if (
      declaredLength !== null &&
      (!/^\d+$/u.test(declaredLength) ||
        !Number.isSafeInteger(Number(declaredLength)) ||
        Number(declaredLength) > 32_768)
    )
      throw new ProviderSessionError("invalid-callback");
    let fields: URLSearchParams;
    if (provider.responseMode === "query") {
      if (request.method !== "GET" || url.search.length > 32_768)
        throw new ProviderSessionError("invalid-callback");
      fields = url.searchParams;
    } else {
      if (
        request.method !== "POST" ||
        url.search ||
        !/^application\/x-www-form-urlencoded(?:\s*;\s*charset=utf-8)?$/iu.test(
          request.headers.get("content-type") ?? "",
        )
      )
        throw new ProviderSessionError("invalid-callback");
      const reader = request.body?.getReader();
      if (!reader) throw new ProviderSessionError("invalid-callback");
      let size = 0;
      const chunks: Uint8Array[] = [];
      try {
        for (;;) {
          const next = await waitFor(reader.read(), signal);
          if (next.done) break;
          size += next.value.length;
          if (size > 32_768) {
            void reader.cancel().catch(() => undefined);
            throw new ProviderSessionError("invalid-callback");
          }
          chunks.push(next.value);
        }
      } catch {
        checkCancellation(signal);
        void reader.cancel().catch(() => undefined);
        throw new ProviderSessionError("invalid-callback");
      } finally {
        if (signal.aborted) void reader.cancel().catch(() => undefined);
        reader.releaseLock();
      }
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.length;
      }
      try {
        fields = new URLSearchParams(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
      } catch {
        throw new ProviderSessionError("invalid-callback");
      }
    }
    const names = [...fields.keys()];
    if (
      names.length > 32 ||
      new Set(names).size !== names.length ||
      names.some(
        (name) =>
          ![
            "state",
            "code",
            "error",
            "error_description",
            "error_uri",
            "session_state",
            "iss",
            "user",
          ].includes(name),
      )
    )
      throw new ProviderSessionError("invalid-callback");
    return fields;
  }
  async function requireIdentity(
    original: Authority,
    signal: AbortSignal,
    provider: ProviderDefinition,
    resource: string,
    scopes: readonly string[],
  ) {
    live();
    checkCancellation(signal);
    const current = await loadAuthority(original.id, signal);
    if (
      !current ||
      current.value.epoch !== original.epoch ||
      current.value.provider !== provider.id ||
      current.value.fingerprint !== providerPolicy(provider).fingerprint ||
      !current.value.principal
    )
      throw interaction(provider, resource, scopes);
    return current;
  }
  const grantFor = (authority: Authority, resource: string, scopes: readonly string[]) =>
    authority.grants.find(
      (grant) =>
        grant.resource === resource &&
        scopes.length === grant.scopes.length &&
        scopes.every((scope, index) => scope === grant.scopes[index]),
    );
  const usable = (grant: Grant | undefined) =>
    grant !== undefined && grant.expiresAt - leeway * 1000 > now();

  const engine: ProviderSession = {
    async resolve(request, resolveOptions) {
      live();
      const signal = composed(request.signal, resolveOptions?.signal);
      const value = (await requestAuthority(request, signal))?.value;
      if (!value?.principal) return anonymous;
      const principal = value.principal;
      return Object.freeze({
        authenticated: true,
        principal: Object.freeze({ ...principal }),
        session: Object.freeze({
          id: value.id,
          subject: principal.subject!,
          expiresAt: value.expiresAt,
        }),
        tenant: null,
        scopes: Object.freeze([...value.identityScopes]),
      });
    },
    async login(request, loginOptions) {
      live();
      const provider = currentProvider(loginOptions?.provider);
      const signal = composed(request.signal);
      const returnTo = localPath(loginOptions.returnTo, origin);
      const scopes = requestedScopes(provider, loginOptions.resource, loginOptions.scopes);
      if (loginOptions.resource !== undefined && !provider.capabilities.incrementalConsent)
        throw configurationError();
      const existing = await requestAuthority(request, signal);
      const id = existing?.value.id ?? randomString();
      const result = await stored(
        () =>
          store.withLock(
            `authority:${id}`,
            async () => {
              const previous = existing ? await loadAuthority(id, signal) : null;
              if (existing && (!previous || previous.value.epoch !== existing.value.epoch))
                throw new ProviderSessionError("invalid-transaction");
              const time = now();
              const authority: Authority = previous
                ? {
                    ...previous.value,
                    generation: previous.value.generation + 1,
                    expiresAt: previous.value.principal
                      ? previous.value.expiresAt
                      : time + transactionTtl * 1000,
                    pending: [],
                  }
                : {
                    kind: "authority",
                    id,
                    epoch: randomString(),
                    generation: 0,
                    expiresAt: time + transactionTtl * 1000,
                    identityScopes: [],
                    grants: [],
                    pending: [],
                  };
              for (const pending of previous?.value.pending ?? []) {
                const item = await record(pending, signal);
                if (item && !item.retired) await consume(pending, item, signal);
                transactions.get(pending)?.abort();
              }
              const transaction: Transaction = {
                kind: "transaction",
                id: randomString(),
                authorityId: id,
                epoch: authority.epoch,
                generation: authority.generation,
                provider: provider.id,
                fingerprint: providerPolicy(provider).fingerprint,
                state: randomString(),
                nonce: randomString(),
                verifier: randomString(),
                createdAt: time,
                expiresAt: time + transactionTtl * 1000,
                returnTo,
                resource: loginOptions.resource,
                scopes,
              };
              const value = await waitFor(sealer.seal("transaction", transaction), signal);
              if (
                !(await stored(
                  () =>
                    store.compareAndSwap(
                      transaction.id,
                      null,
                      {
                        revision: 0,
                        expiresAt: transaction.expiresAt + 300_000,
                        retired: false,
                        value,
                      },
                      { signal },
                    ),
                  signal,
                ))
              )
                throw new ProviderSessionError("invalid-transaction");
              const committed = await commitAuthority(
                previous,
                { ...authority, pending: [transaction.id], pendingUntil: transaction.expiresAt },
                signal,
              );
              return { ...committed, transaction };
            },
            { signal },
          ),
        signal,
      );
      const current = async () => {
        await currentTransaction(result.transaction, signal);
      };
      const transport = providerTransport(fetcher, signal, current);
      const metadata = await waitFor(providerMetadata(provider, transport, current), signal);
      await current();
      const authorization = new URL(metadata.authorization_endpoint);
      const protocol: Record<string, string> = {
        response_type: "code",
        client_id: provider.clientId,
        redirect_uri: `${origin}/auth/callback/${provider.id}`,
        state: result.transaction.state,
        nonce: result.transaction.nonce,
        code_challenge: await codeChallenge(result.transaction.verifier),
        code_challenge_method: "S256",
        scope: [...new Set([...provider.identityScopes, ...scopes])].sort().join(" "),
      };
      for (const [name, value] of Object.entries({ ...provider.authorizationParams, ...protocol }))
        authorization.searchParams.set(name, value);
      if (provider.responseMode === "form_post")
        authorization.searchParams.set("response_mode", "form_post");
      if (loginOptions.resource !== undefined)
        authorization.searchParams.set(
          providerPolicy(provider).authorizationResourceParameter,
          loginOptions.resource,
        );
      const correlation = await waitFor(
        sealer.seal(transactionCookie(provider.id), {
          id: result.transaction.id,
          authorityId: id,
          epoch: result.transaction.epoch,
          generation: result.transaction.generation,
          provider: provider.id,
        }),
        signal,
      );
      await current();
      stage(request, result.issuance);
      stage(request, {
        name: transactionCookie(provider.id),
        line: cookieLine(
          transactionCookie(provider.id),
          correlation,
          transactionTtl,
          provider.responseMode === "form_post" ? "None" : "Lax",
        ),
        id,
        epoch: result.transaction.epoch,
        revision: result.authority.record.revision,
        generation: result.transaction.generation,
        expiresAt: result.transaction.expiresAt,
      });
      return new Response(null, {
        status: 303,
        headers: { location: authorization.href, "cache-control": "no-store" },
      });
    },
    async callback(request, callbackOptions) {
      live();
      const provider = currentProvider(callbackOptions?.provider);
      clearTransaction(request, provider);
      const baseSignal = composed(request.signal);
      // Malformed transaction cleanup can still retain a known browser owner.
      // Valid transaction correlation also works when form_post omits this Lax cookie.
      const browserOwner = await waitFor(
        sealer.open<{ id: string; epoch: string; generation: number }>(
          sessionCookie,
          readCookie(request.headers.get("cookie"), sessionCookie),
        ),
        baseSignal,
      );
      if (
        browserOwner &&
        typeof browserOwner.id === "string" &&
        typeof browserOwner.epoch === "string" &&
        Number.isSafeInteger(browserOwner.generation)
      )
        clearTransaction(request, provider, {
          id: browserOwner.id,
          epoch: browserOwner.epoch,
          generation: browserOwner.generation,
        });
      const correlation = await waitFor(
        sealer.open<{
          id: string;
          authorityId: string;
          epoch: string;
          generation: number;
          provider: string;
        }>(
          transactionCookie(provider.id),
          readCookie(request.headers.get("cookie"), transactionCookie(provider.id)),
        ),
        baseSignal,
      );
      if (
        !correlation ||
        correlation.provider !== provider.id ||
        typeof correlation.id !== "string"
      )
        throw new ProviderSessionError("invalid-transaction");
      clearTransaction(request, provider, {
        id: correlation.authorityId,
        epoch: correlation.epoch,
        generation: correlation.generation,
      });
      const item = await record(correlation.id, baseSignal);
      if (!item || item.retired || item.expiresAt <= now())
        throw new ProviderSessionError("invalid-transaction");
      const transaction = await waitFor(
        sealer.open<Transaction>("transaction", item.value),
        baseSignal,
      );
      if (
        !transaction ||
        transaction.kind !== "transaction" ||
        transaction.id !== correlation.id ||
        transaction.provider !== provider.id ||
        transaction.authorityId !== correlation.authorityId ||
        transaction.epoch !== correlation.epoch ||
        transaction.generation !== correlation.generation ||
        transaction.fingerprint !== providerPolicy(provider).fingerprint
      )
        throw new ProviderSessionError("invalid-transaction");
      if (!(await consume(transaction.id, item, baseSignal)))
        throw new ProviderSessionError("invalid-transaction");
      const original = await currentTransaction(transaction, baseSignal);
      const controller = new AbortController();
      transactions.set(transaction.id, controller);
      const identity = identitySignal(original.value);
      const signal = composed(request.signal, identity, controller.signal);
      try {
        const current = async () => {
          await currentTransaction(transaction, signal);
        };
        const fields = await callbackFields(request, provider, signal);
        if (
          fields.get("state") !== transaction.state ||
          fields.has("error") ||
          !fields.get("code") ||
          fields.get("code")!.length > 8192 ||
          (fields.has("iss") && fields.get("iss") !== provider.issuer)
        )
          throw new ProviderSessionError("invalid-callback");
        const transport = providerTransport(fetcher, signal, current);
        const metadata = await waitFor(providerMetadata(provider, transport, current), signal);
        await current();
        const exchangeStart = now();
        const body = new URLSearchParams({
          grant_type: "authorization_code",
          code: fields.get("code")!,
          redirect_uri: `${origin}/auth/callback/${provider.id}`,
          code_verifier: transaction.verifier,
        });
        if (transaction.resource !== undefined)
          body.set(providerPolicy(provider).authorizationResourceParameter, transaction.resource);
        const tokens = await exchangeProviderTokens(
          provider,
          transport,
          metadata.token_endpoint,
          body,
          [...new Set([...provider.identityScopes, ...transaction.scopes])],
          exchangeStart,
          signal,
          transaction.resource,
        );
        await current();
        const principal = await waitFor(
          validateProviderIdentity(
            provider,
            tokens.idToken,
            transaction.nonce,
            metadata.jwks_uri,
            transport,
            now(),
          ),
          signal,
        );
        await current();
        if (onSignIn) {
          try {
            await waitFor(
              Promise.resolve(onSignIn({ provider: provider.id, principal, signal })),
              signal,
            );
          } catch (error) {
            checkCancellation(signal);
            if (error instanceof ProviderSessionError) throw error;
            throw configurationError();
          }
          await current();
        }
        const result = await stored(
          () =>
            store.withLock(
              `authority:${transaction.authorityId}`,
              async () => {
                const previous = await currentTransaction(transaction, signal);
                const sameAccount =
                  previous.value.provider === provider.id &&
                  previous.value.principal?.id === principal.id;
                const grant: Grant = {
                  resource: transaction.resource,
                  scopes: transaction.scopes,
                  accessToken: tokens.accessToken,
                  expiresAt: exchangeStart + tokens.expiresIn * 1000,
                };
                const grants = sameAccount
                  ? previous.value.grants.filter(
                      (entry) =>
                        entry.resource !== grant.resource ||
                        JSON.stringify(entry.scopes) !== JSON.stringify(grant.scopes),
                    )
                  : [];
                const value: Authority = {
                  kind: "authority",
                  id: transaction.authorityId,
                  epoch: randomString(),
                  generation: transaction.generation + 1,
                  provider: provider.id,
                  fingerprint: providerPolicy(provider).fingerprint,
                  principal,
                  nonce: transaction.nonce,
                  expiresAt: sameAccount ? previous.value.expiresAt : exchangeStart + maxAge * 1000,
                  refreshToken:
                    tokens.refreshToken ??
                    (sameAccount && previous.value.refreshing === undefined
                      ? previous.value.refreshToken
                      : undefined),
                  identityScopes: tokens.scopes.filter(
                    (scope) =>
                      scope !== "offline_access" && provider.identityScopes.includes(scope),
                  ),
                  grants: [...grants, grant],
                  pending: [],
                };
                const committed = await commitAuthority(previous, value, signal);
                return { ...committed, previous: previous.value };
              },
              { signal },
            ),
          signal,
        );
        retireLocal(result.previous);
        stage(request, result.issuance);
        clearTransaction(request, provider, {
          id: result.authority.value.id,
          epoch: result.authority.value.epoch,
          generation: result.authority.value.generation,
          revision: result.authority.record.revision,
        });
        return new Response(null, {
          status: 303,
          headers: {
            location: new URL(transaction.returnTo, origin).href,
            "cache-control": "no-store",
          },
        });
      } catch (error) {
        // Explicit cancellation wins even when expiry aborted the composed signal first.
        checkCancellation(baseSignal);
        checkCancellation(controller.signal);
        if (identity.reason === identityExpired)
          throw new ProviderSessionError("invalid-transaction");
        throw error;
      } finally {
        if (transactions.get(transaction.id) === controller) transactions.delete(transaction.id);
      }
    },
    async token(request, providerId, tokenOptions) {
      live();
      const provider = currentProvider(providerId);
      if (!tokenOptions || !Array.isArray(tokenOptions.scopes)) throw configurationError();
      const resource =
        tokenOptions?.resource ??
        (provider.capabilities.resources.length === 1
          ? provider.capabilities.resources[0]!.resource
          : undefined);
      if (resource === undefined) throw configurationError();
      const scopes = requestedScopes(provider, resource, tokenOptions.scopes);
      const caller = composed(request.signal, tokenOptions.signal);
      const original = await requestAuthority(request, caller);
      if (!original?.value.principal || original.value.provider !== provider.id)
        throw interaction(provider, resource, scopes);
      const active = await requireIdentity(original.value, caller, provider, resource, scopes);
      const existing = grantFor(active.value, resource, scopes);
      if (usable(existing)) return existing!.accessToken;
      if (!existing) throw interaction(provider, resource, scopes, "consent");
      if (provider.capabilities.renewal !== "refresh" || !active.value.refreshToken)
        throw interaction(provider, resource, scopes);
      const key = JSON.stringify([
        active.value.id,
        active.value.epoch,
        providerPolicy(provider).fingerprint,
        resource,
        scopes,
      ]);
      let operation = renewals.get(key);
      if (!operation) {
        const signal = composed(identitySignal(active.value));
        operation = stored(
          () =>
            store.withLock(
              `grant:${active.value.id}:${active.value.epoch}`,
              async () => {
                const latest = await requireIdentity(
                  active.value,
                  signal,
                  provider,
                  resource,
                  scopes,
                );
                const cached = grantFor(latest.value, resource, scopes);
                if (usable(cached)) return { authority: latest, token: cached!.accessToken };
                if (!latest.value.refreshToken || latest.value.refreshing !== undefined)
                  throw interaction(provider, resource, scopes);
                const current = async () => {
                  await requireIdentity(active.value, signal, provider, resource, scopes);
                };
                const transport = providerTransport(fetcher, signal, current);
                const metadata = await waitFor(
                  providerMetadata(provider, transport, current),
                  signal,
                );
                await current();
                // Persist uncertainty before sending a single-use refresh grant. A failed/closed
                // worker must never let another request retry that possibly consumed token.
                const attempt = randomString();
                await stored(
                  () =>
                    store.withLock(
                      `authority:${active.value.id}`,
                      async () => {
                        const beforeExchange = await requireIdentity(
                          active.value,
                          signal,
                          provider,
                          resource,
                          scopes,
                        );
                        if (
                          beforeExchange.value.refreshing !== undefined ||
                          beforeExchange.value.refreshToken !== latest.value.refreshToken
                        )
                          throw interaction(provider, resource, scopes);
                        await commitAuthority(
                          beforeExchange,
                          { ...beforeExchange.value, refreshing: attempt },
                          signal,
                        );
                      },
                      { signal },
                    ),
                  signal,
                );
                const exchangeStart = now();
                const body = new URLSearchParams({
                  grant_type: "refresh_token",
                  refresh_token: latest.value.refreshToken,
                  scope: scopes.join(" "),
                  [providerPolicy(provider).authorizationResourceParameter]: resource,
                });
                const tokens = await exchangeProviderTokens(
                  provider,
                  transport,
                  metadata.token_endpoint,
                  body,
                  scopes,
                  exchangeStart,
                  signal,
                  resource,
                );
                await current();
                if (tokens.idToken !== undefined) {
                  await waitFor(
                    validateProviderIdentity(
                      provider,
                      tokens.idToken,
                      latest.value.nonce!,
                      metadata.jwks_uri,
                      transport,
                      now(),
                      latest.value.principal!.subject!,
                    ),
                    signal,
                  );
                  await current();
                }
                return stored(
                  () =>
                    store.withLock(
                      `authority:${active.value.id}`,
                      async () => {
                        const beforeCommit = await requireIdentity(
                          active.value,
                          signal,
                          provider,
                          resource,
                          scopes,
                        );
                        if (beforeCommit.value.refreshing !== attempt)
                          throw interaction(provider, resource, scopes);
                        const currentGrant = grantFor(beforeCommit.value, resource, scopes);
                        const refreshed: Authority = {
                          ...beforeCommit.value,
                          refreshing: undefined,
                          refreshToken: tokens.refreshToken ?? beforeCommit.value.refreshToken,
                          grants: beforeCommit.value.grants
                            .filter((grant) => grant !== currentGrant)
                            .concat({
                              resource,
                              scopes,
                              accessToken: tokens.accessToken,
                              expiresAt: exchangeStart + tokens.expiresIn * 1000,
                            }),
                        };
                        const committed = await commitAuthority(beforeCommit, refreshed, signal);
                        return { authority: committed.authority, token: tokens.accessToken };
                      },
                      { signal },
                    ),
                  signal,
                );
              },
              { signal },
            ),
          signal,
        );
        renewals.set(key, operation);
        const completed = operation;
        void completed
          .finally(() => {
            if (renewals.get(key) === completed) renewals.delete(key);
          })
          .catch(() => undefined);
      }
      const result = await waitFor(operation, caller);
      await requireIdentity(result.authority.value, caller, provider, resource, scopes);
      stage(
        request,
        await sessionIssuance(result.authority.value, result.authority.record.revision, caller),
      );
      return result.token;
    },
    async logout(request, logoutOptions = {}) {
      live();
      const signal = composed(request.signal);
      if (!logoutOptions || typeof logoutOptions !== "object") throw configurationError();
      if (
        (logoutOptions.providerLogout !== undefined &&
          typeof logoutOptions.providerLogout !== "boolean") ||
        (logoutOptions.revoke !== undefined && typeof logoutOptions.revoke !== "boolean")
      )
        throw configurationError();
      const original = await requestAuthority(request, signal);
      const provider =
        logoutOptions.provider === undefined
          ? original?.value.provider === undefined
            ? undefined
            : currentProvider(original.value.provider)
          : currentProvider(logoutOptions.provider);
      if (
        (logoutOptions.provider !== undefined &&
          original?.value.provider !== logoutOptions.provider) ||
        (logoutOptions.providerLogout && !provider?.capabilities.providerLogout) ||
        (logoutOptions.revoke && !provider?.capabilities.revocation)
      )
        throw configurationError();
      const returnTo = localPath(logoutOptions.returnTo ?? "/", origin);
      if (!logoutPaths.has(returnTo)) throw configurationError();
      const retired = original
        ? await stored(
            () =>
              store.withLock(
                `authority:${original.value.id}`,
                async () => {
                  const current = await loadAuthority(original.value.id, signal);
                  if (!current || current.value.epoch !== original.value.epoch) return null;
                  if (!(await consume(current.value.id, current.record, signal)))
                    throw new ProviderSessionError("invalid-transaction");
                  const owner = {
                    id: current.value.id,
                    revision: current.record.revision + 1,
                    retired: true,
                  };
                  stage(request, {
                    ...owner,
                    name: sessionCookie,
                    line: cookieLine(sessionCookie, "", 0),
                  });
                  for (const configured of providers.values())
                    clearTransaction(request, configured, owner);
                  retireLocal(current.value);
                  for (const id of current.value.pending) {
                    const item = await record(id, signal);
                    if (item && !item.retired) await consume(id, item, signal);
                    transactions.get(id)?.abort();
                  }
                  return current.value;
                },
                { signal },
              ),
            signal,
          )
        : null;
      if (original && !retired) throw new ProviderSessionError("invalid-transaction");
      if (!original) {
        stage(request, { name: sessionCookie, line: cookieLine(sessionCookie, "", 0) });
        for (const configured of providers.values()) clearTransaction(request, configured);
      }
      if (provider && (logoutOptions.revoke || logoutOptions.providerLogout)) {
        const transport = providerTransport(fetcher, signal, async () => {
          live();
          checkCancellation(signal);
        });
        const metadata = await waitFor(providerMetadata(provider, transport), signal);
        if (logoutOptions.revoke && retired) {
          const selected = retired.refreshToken
            ? [retired.refreshToken]
            : [...new Set(retired.grants.map((grant) => grant.accessToken))];
          for (const token of selected) {
            const authentication = await confidentialAuthentication(provider, now(), signal);
            const body = new URLSearchParams({
              token,
              token_type_hint: retired.refreshToken ? "refresh_token" : "access_token",
              client_id: provider.clientId,
            });
            const response = await requestOidcToken(
              transport,
              metadata.revocation_endpoint!,
              provider.clientId,
              body,
              authentication,
              signal,
            );
            if (!response.ok) throw new ProviderSessionError("provider-unavailable");
          }
        }
        if (logoutOptions.providerLogout) {
          const destination = new URL(metadata.end_session_endpoint!);
          destination.searchParams.set("client_id", provider.clientId);
          destination.searchParams.set("post_logout_redirect_uri", new URL(returnTo, origin).href);
          return new Response(null, {
            status: 303,
            headers: { location: destination.href, "cache-control": "no-store" },
          });
        }
      }
      return new Response(null, { status: 204, headers: { "cache-control": "no-store" } });
    },
    async finalize(request, response) {
      live();
      const pending = requests.get(request);
      if (!pending) return response;
      const signal = composed(request.signal);
      checkCancellation(signal);
      const issuances = [...pending.pending.values()];
      const owners = [
        ...new Set(
          issuances.flatMap((issuance) => (issuance.id === undefined ? [] : [issuance.id])),
        ),
      ];
      // Decrypt first, then take one final record view for every staged cookie.
      // No asynchronous work may split attaching session/transaction issuance.
      const current = owners.length === 1 ? await loadAuthority(owners[0]!, signal) : null;
      const finalRecord = owners.length === 1 ? await record(owners[0]!, signal) : null;
      const headers = new Headers(response.headers);
      const applicationCookies = headers
        .getSetCookie()
        .filter((line) => !pending.ownedLines.has(line));
      headers.delete("set-cookie");
      for (const line of applicationCookies) headers.append("set-cookie", line);
      for (const issuance of issuances) {
        if (issuance.id !== undefined) {
          if (issuance.retired) {
            if (
              !finalRecord?.retired ||
              finalRecord.revision !== issuance.revision ||
              finalRecord.expiresAt <= now()
            )
              continue;
          } else if (
            !current ||
            !finalRecord ||
            finalRecord.retired ||
            finalRecord.expiresAt <= now() ||
            current.value.expiresAt <= now() ||
            finalRecord.revision !== current.record.revision ||
            current.value.id !== issuance.id ||
            current.value.epoch !== issuance.epoch ||
            (issuance.revision !== undefined && current.record.revision !== issuance.revision) ||
            (issuance.generation !== undefined && current.value.generation !== issuance.generation)
          )
            continue;
        }
        if (issuance.expiresAt !== undefined && issuance.expiresAt <= now()) continue;
        checkCancellation(signal);
        const line =
          issuance.expiresAt === undefined
            ? issuance.line
            : issuance.line.replace(
                /; Max-Age=\d+$/u,
                `; Max-Age=${Math.max(0, Math.floor((issuance.expiresAt - now()) / 1000))}`,
              );
        pending.ownedLines.add(line);
        headers.append("set-cookie", line);
      }
      live();
      headers.set("cache-control", "no-store");
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers,
      });
    },
    async close() {
      if (closed) return;
      closed = true;
      lifetime.abort();
      for (const owner of identities.values()) owner.controller.abort();
      for (const controller of transactions.values()) controller.abort();
      identities.clear();
      transactions.clear();
      renewals.clear();
    },
  };
  return Object.freeze(engine);
}
