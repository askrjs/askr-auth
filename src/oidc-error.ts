export type OidcClientErrorCode =
  | "discovery-failed"
  | "invalid-metadata"
  | "state-mismatch"
  | "exchange-failed"
  | "invalid-token-response"
  | "invalid-id-token";

export class OidcClientError extends Error {
  readonly name = "OidcClientError";
  constructor(readonly code: OidcClientErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
  }
}
