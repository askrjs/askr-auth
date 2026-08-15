/** Stable failure codes for OIDC client operations. */
export type OidcClientErrorCode =
  | "discovery-failed"
  | "invalid-metadata"
  | "state-mismatch"
  | "exchange-failed"
  | "invalid-token-response"
  | "invalid-id-token";

/** Error raised while discovering, exchanging, or validating OIDC tokens. */
export class OidcClientError extends Error {
  /** Error category used for programmatic handling. */
  readonly name = "OidcClientError";
  constructor(
    /** Error category used for programmatic handling. */
    readonly code: OidcClientErrorCode,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
  }
}
