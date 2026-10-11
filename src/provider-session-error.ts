export type ProviderSessionErrorCode =
  | "configuration"
  | "invalid-callback"
  | "invalid-transaction"
  | "session-oversize"
  | "capacity"
  | "store-unavailable"
  | "provider-unavailable"
  | "closed";
const messages: Record<ProviderSessionErrorCode, string> = {
  configuration:
    "Provider session configuration is invalid; check the configured provider and session policy.",
  "invalid-callback": "Provider callback is invalid; start a new sign-in flow.",
  "invalid-transaction":
    "Provider transaction is missing, expired or consumed; start a new sign-in flow.",
  "session-oversize": "Provider session exceeds the cookie budget; configure a session store.",
  capacity:
    "Provider session authority is full; increase its configured capacity or use a session store.",
  "store-unavailable": "Provider session store is unavailable; restore the store before retrying.",
  "provider-unavailable": "Identity provider is unavailable; retry the operation later.",
  closed: "Provider session engine is closed; use a live engine.",
};
export class ProviderSessionError extends Error {
  readonly code: ProviderSessionErrorCode;
  constructor(code: ProviderSessionErrorCode) {
    super(messages[code]);
    this.name = "ProviderSessionError";
    this.code = code;
  }
}
export class InteractionRequiredError extends Error {
  readonly code = "interaction-required";
  readonly reason: "login" | "consent";
  readonly provider: string;
  readonly resource?: string;
  readonly scopes: readonly string[];
  constructor(options: {
    readonly reason: "login" | "consent";
    readonly provider: string;
    readonly resource?: string;
    readonly scopes: readonly string[];
  }) {
    super(options.reason === "login" ? "Sign in is required." : "Additional consent is required.");
    this.name = "InteractionRequiredError";
    this.reason = options.reason;
    this.provider = options.provider;
    this.resource = options.resource;
    this.scopes = Object.freeze([...options.scopes]);
  }
}
export const configurationError = () => new ProviderSessionError("configuration");
export const cancellationError = () =>
  new DOMException("Authentication operation was cancelled.", "AbortError");
