import { MfaValidationError } from "./mfa-error";

export interface CborDecodeOptions {
  maxBytes?: number;
  maxDepth?: number;
  maxCollectionLength?: number;
}

export interface CborFirstResult {
  value: unknown;
  bytesRead: number;
}

const malformed = (message: string): never => {
  throw new MfaValidationError("malformed-input", message);
};

export function decodeCborFirst(
  input: Uint8Array,
  options: CborDecodeOptions = {},
): CborFirstResult {
  const maxBytes = options.maxBytes ?? 65_536;
  const maxDepth = options.maxDepth ?? 16;
  const maxCollection = options.maxCollectionLength ?? 1_024;
  if (!(input instanceof Uint8Array) || input.length > maxBytes) malformed("CBOR input is invalid or too large.");
  const view = new DataView(input.buffer, input.byteOffset, input.byteLength);
  let offset = 0;
  const take = (count: number) => {
    if (count < 0 || offset + count > input.length) malformed("CBOR value is truncated.");
    const start = offset;
    offset += count;
    return input.subarray(start, offset);
  };
  const length = (additional: number): number => {
    if (additional < 24) return additional;
    const width = additional === 24 ? 1 : additional === 25 ? 2 : additional === 26 ? 4 : additional === 27 ? 8 : 0;
    if (!width) malformed("Indefinite or reserved CBOR lengths are unsupported.");
    if (offset + width > input.length) malformed("CBOR length is truncated.");
    let value: number;
    if (width === 8) {
      const large = view.getBigUint64(offset);
      if (large > BigInt(Number.MAX_SAFE_INTEGER)) malformed("CBOR integer exceeds the safe range.");
      value = Number(large);
    } else value = width === 1 ? view.getUint8(offset) : width === 2 ? view.getUint16(offset) : view.getUint32(offset);
    offset += width;
    const minimum = width === 1 ? 24 : width === 2 ? 256 : width === 4 ? 65_536 : 4_294_967_296;
    if (value < minimum) malformed("CBOR length or integer is not minimally encoded.");
    return value;
  };
  const parse = (depth: number): unknown => {
    if (depth > maxDepth) malformed("CBOR nesting is too deep.");
    if (offset >= input.length) malformed("CBOR value is truncated.");
    const initial = input[offset++];
    const major = initial >> 5;
    const count = length(initial & 31);
    if (major === 0) return count;
    if (major === 1) return -1 - count;
    if (major === 2) return take(count).slice();
    if (major === 3) {
      try {
        return new TextDecoder("utf-8", { fatal: true }).decode(take(count));
      } catch {
        malformed("CBOR text is not valid UTF-8.");
      }
    }
    if (major === 4) {
      if (count > maxCollection) malformed("CBOR array is too large.");
      return Array.from({ length: count }, () => parse(depth + 1));
    }
    if (major === 5) {
      if (count > maxCollection) malformed("CBOR map is too large.");
      const map = new Map<unknown, unknown>();
      const keys = new Set<string>();
      for (let index = 0; index < count; index++) {
        const key = parse(depth + 1);
        const identity = typeof key === "string" ? `s:${key}` : typeof key === "number" ? `n:${key}` : "";
        if (!identity) malformed("CBOR map keys must be strings or integers.");
        if (keys.has(identity)) malformed("CBOR map contains a duplicate key.");
        keys.add(identity);
        map.set(key, parse(depth + 1));
      }
      return map;
    }
    if (major === 7 && count === 20) return false;
    if (major === 7 && count === 21) return true;
    if (major === 7 && count === 22) return null;
    malformed("Unsupported CBOR type.");
  };
  return { value: parse(0), bytesRead: offset };
}

export function decodeCbor(input: Uint8Array, options?: CborDecodeOptions): unknown {
  const result = decodeCborFirst(input, options);
  if (result.bytesRead !== input.length) malformed("CBOR input contains trailing data.");
  return result.value;
}
