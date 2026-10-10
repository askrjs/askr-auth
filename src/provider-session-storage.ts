import { decodeBase64Url } from "./jwt-encoding";
import {
  cancellationError,
  configurationError,
  ProviderSessionError,
} from "./provider-session-error";
import type { ProviderSessionRecord, ProviderSessionStore } from "./provider-session-types";

export function checkCancellation(signal: AbortSignal): void {
  if (signal.aborted) throw cancellationError();
}
export function waitFor<T>(value: PromiseLike<T>, signal: AbortSignal): Promise<T> {
  checkCancellation(signal);
  return new Promise<T>((resolve, reject) => {
    const abort = () => {
      signal.removeEventListener("abort", abort);
      reject(cancellationError());
    };
    signal.addEventListener("abort", abort, { once: true });
    Promise.resolve(value).then(
      (result) => {
        signal.removeEventListener("abort", abort);
        if (signal.aborted) reject(cancellationError());
        else resolve(result);
      },
      (error) => {
        signal.removeEventListener("abort", abort);
        reject(signal.aborted ? cancellationError() : error);
      },
    );
    if (signal.aborted) abort();
  });
}
export function boundedInteger(
  value: number | undefined,
  fallback: number,
  min: number,
  max: number,
): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < min || result > max) throw configurationError();
  return result;
}
export function memoryAuthority(maxEntries: number, now: () => number): ProviderSessionStore {
  const records = new Map<string, ProviderSessionRecord>();
  const locks = new Map<string, Promise<void>>();
  function prune() {
    const time = now();
    for (const [id, record] of records) if (record.expiresAt <= time) records.delete(id);
  }
  return {
    async read(id, { signal }) {
      checkCancellation(signal);
      prune();
      return records.get(id) ?? null;
    },
    async compareAndSwap(id, expected, next, { signal }) {
      checkCancellation(signal);
      prune();
      const previous = records.get(id);
      if (
        (previous?.revision ?? null) !== expected ||
        previous?.retired ||
        next.revision !== (expected === null ? 0 : expected + 1)
      )
        return false;
      if (!previous && records.size >= maxEntries) throw new ProviderSessionError("capacity");
      records.set(id, Object.freeze({ ...next }));
      return true;
    },
    withLock(key, operation, { signal }) {
      checkCancellation(signal);
      const previous = locks.get(key) ?? Promise.resolve();
      const result = previous.then(() => {
        checkCancellation(signal);
        return operation();
      });
      const tail = result.then(
        () => undefined,
        () => undefined,
      );
      locks.set(key, tail);
      void tail.then(() => {
        if (locks.get(key) === tail) locks.delete(key);
      });
      return waitFor(result, signal);
    },
  };
}

const bytes = (value: string) => new TextEncoder().encode(value);
const encode = (value: Uint8Array) =>
  btoa(Array.from(value, (b) => String.fromCharCode(b)).join(""))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
/** All cookie and store envelopes use independent purpose-bound authenticated data. */
export function sessionSealer(origin: string, secrets: readonly string[]) {
  if (!Array.isArray(secrets) || secrets.length < 1 || secrets.length > 4)
    throw configurationError();
  const raw = Array.from(secrets, (secret) => {
    try {
      if (typeof secret !== "string") throw new Error();
      const key = decodeBase64Url(secret);
      if (key.length !== 32) throw new Error();
      return key;
    } catch {
      throw configurationError();
    }
  });
  if (new Set(secrets).size !== secrets.length) throw configurationError();
  const keys = Promise.all(
    raw.map(async (value) => ({
      id: encode(new Uint8Array(await crypto.subtle.digest("SHA-256", value)).slice(0, 12)),
      key: await crypto.subtle.importKey("raw", value, "AES-GCM", false, ["encrypt", "decrypt"]),
    })),
  );
  const aad = (purpose: string) =>
    bytes(JSON.stringify(["askr-provider-session", 1, origin, purpose]));
  return {
    async seal(purpose: string, value: unknown): Promise<string> {
      const current = (await keys)[0]!;
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: aad(purpose), tagLength: 128 },
        current.key,
        bytes(JSON.stringify(value)),
      );
      return `1.${current.id}.${encode(iv)}.${encode(new Uint8Array(encrypted))}`;
    },
    async open<T>(purpose: string, value: string | null): Promise<T | null> {
      try {
        if (!value || value.length > 1_048_576) return null;
        const parts = value.split(".");
        if (parts.length !== 4 || parts[0] !== "1") return null;
        const key = (await keys).find((k) => k.id === parts[1]);
        if (!key) return null;
        const iv = decodeBase64Url(parts[2]!);
        if (iv.length !== 12) return null;
        const plaintext = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv, additionalData: aad(purpose), tagLength: 128 },
          key.key,
          decodeBase64Url(parts[3]!),
        );
        return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext)) as T;
      } catch {
        return null;
      }
    },
  };
}
