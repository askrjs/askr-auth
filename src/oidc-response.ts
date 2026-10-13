const DEFAULT_MAX_OIDC_RESPONSE_BYTES = 1_048_576;

export class OidcResponseTooLargeError extends Error {
  constructor() {
    super("OIDC provider response exceeds the configured size limit.");
    this.name = "OidcResponseTooLargeError";
  }
}

interface BoundedJsonOptions {
  readonly maxBytes?: number;
  readonly maxCharacters?: number;
  readonly signal?: AbortSignal;
}

function abortError(): DOMException {
  return new DOMException("OIDC response reading was cancelled.", "AbortError");
}

function cancelReader(reader: ReadableStreamDefaultReader<Uint8Array>): void {
  try {
    void reader.cancel().catch(() => {});
  } catch {
    // Cancellation is best-effort; the original size or abort error is authoritative.
  }
}

export function cancelResponseBody(response: Response): void {
  try {
    const cancellation = response.body?.cancel();
    if (cancellation) void cancellation.catch(() => {});
  } catch {
    // Cancellation is best-effort; the caller's status or abort error is authoritative.
  }
}

function readChunk(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  signal?: AbortSignal,
): Promise<ReadableStreamReadResult<Uint8Array>> {
  if (signal?.aborted) {
    cancelReader(reader);
    return Promise.reject(abortError());
  }
  const pending = reader.read();
  if (!signal) return pending;
  return new Promise((resolve, reject) => {
    const cleanup = () => signal.removeEventListener("abort", abort);
    const abort = () => {
      cleanup();
      cancelReader(reader);
      reject(abortError());
    };
    signal.addEventListener("abort", abort, { once: true });
    pending.then(
      (result) => {
        cleanup();
        if (signal.aborted) reject(abortError());
        else resolve(result);
      },
      (error: unknown) => {
        cleanup();
        reject(signal.aborted ? abortError() : error);
      },
    );
    if (signal.aborted) abort();
  });
}

/** Parse a JSON response while bounding decoded body bytes and optional text length. */
export async function parseBoundedJsonResponse(
  response: Response,
  options: BoundedJsonOptions = {},
): Promise<unknown> {
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_OIDC_RESPONSE_BYTES;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) throw new RangeError("Invalid byte limit.");
  if (
    options.maxCharacters !== undefined &&
    (!Number.isSafeInteger(options.maxCharacters) || options.maxCharacters < 0)
  )
    throw new RangeError("Invalid character limit.");
  if (options.signal?.aborted) {
    cancelResponseBody(response);
    throw abortError();
  }
  if (!response.body) return JSON.parse("") as unknown;

  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8");
  const chunks: Uint8Array[] = [];
  let byteLength = 0;
  let characterLength = 0;
  try {
    while (true) {
      const result = await readChunk(reader, options.signal);
      if (result.done) break;
      const chunk = result.value;
      if (chunk.byteLength > maxBytes - byteLength) {
        cancelReader(reader);
        throw new OidcResponseTooLargeError();
      }
      byteLength += chunk.byteLength;
      characterLength += decoder.decode(chunk, { stream: true }).length;
      if (options.maxCharacters !== undefined && characterLength > options.maxCharacters) {
        cancelReader(reader);
        throw new OidcResponseTooLargeError();
      }
      if (chunk.byteLength > 0) chunks.push(chunk);
    }
    characterLength += decoder.decode().length;
    if (options.maxCharacters !== undefined && characterLength > options.maxCharacters)
      throw new OidcResponseTooLargeError();
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // An aborted pending read can still be settling after cancellation was requested.
    }
  }

  const bytes = new Uint8Array(byteLength);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder("utf-8").decode(bytes)) as unknown;
}
