import { BrowserOidcSessionError } from "./browser-types";
import type { OidcAuthorizationRequest } from "./oidc-types";

export interface BrowserAuthorizationResponse {
  state: string;
  code?: string;
  error?: string;
  error_description?: string;
}

/** Exact provider origin, iframe window and state must all correlate. */
export function authorizeWithWebMessage(
  request: OidcAuthorizationRequest,
  timeoutMs: number,
  signal: AbortSignal,
): Promise<BrowserAuthorizationResponse> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(new BrowserOidcSessionError("cancelled", "Silent authorization was cancelled."));
      return;
    }
    const authorization = new URL(request.url);
    authorization.searchParams.set("prompt", "none");
    authorization.searchParams.set("response_mode", "web_message");
    const frame = document.createElement("iframe");
    frame.hidden = true;
    frame.title = "OIDC silent authorization";
    let timeout: ReturnType<typeof setTimeout>;
    const cleanup = () => {
      clearTimeout(timeout);
      window.removeEventListener("message", receive);
      signal.removeEventListener("abort", abort);
      frame.remove();
    };
    const abort = () => {
      cleanup();
      reject(new BrowserOidcSessionError("cancelled", "Silent authorization was cancelled."));
    };
    const receive = (event: MessageEvent) => {
      if (event.origin !== authorization.origin || event.source !== frame.contentWindow) return;
      const data: unknown = event.data;
      if (!data || typeof data !== "object") return;
      const response = data as Partial<BrowserAuthorizationResponse>;
      if (response.state !== request.state) return;
      if (
        (typeof response.code === "string" &&
          response.code.length > 0 &&
          response.error === undefined) ||
        (typeof response.error === "string" &&
          response.error.length > 0 &&
          response.code === undefined)
      ) {
        cleanup();
        resolve({
          state: request.state,
          code: response.code,
          error: response.error,
          error_description:
            typeof response.error_description === "string" ? response.error_description : undefined,
        });
      }
    };
    window.addEventListener("message", receive);
    signal.addEventListener("abort", abort, { once: true });
    timeout = setTimeout(() => {
      cleanup();
      reject(
        new BrowserOidcSessionError(
          "silent-timeout",
          "Silent authorization timed out; use interactive login.",
        ),
      );
    }, timeoutMs);
    try {
      frame.src = authorization.toString();
      document.body.append(frame);
    } catch (cause) {
      cleanup();
      reject(
        new BrowserOidcSessionError(
          "authorization-error",
          "Could not mount the silent authorization frame.",
          { cause },
        ),
      );
    }
  });
}
