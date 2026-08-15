/** Stable failure codes for MFA and WebAuthn validation. */
export type MfaValidationErrorCode =
  | "malformed-input"
  | "credential-mismatch"
  | "invalid-challenge"
  | "invalid-origin"
  | "invalid-rp-id"
  | "user-presence-required"
  | "user-verification-required"
  | "unsupported-algorithm"
  | "invalid-attestation"
  | "invalid-signature"
  | "counter-rollback";

/** Error raised when MFA input or credentials fail validation. */
export class MfaValidationError extends Error {
  /** Error category used for programmatic handling. */
  readonly name = "MfaValidationError";
  constructor(
    /** Error category used for programmatic handling. */
    readonly code: MfaValidationErrorCode,
    message: string,
  ) {
    super(message);
  }
}
