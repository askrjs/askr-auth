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

export class MfaValidationError extends Error {
  readonly name = "MfaValidationError";
  constructor(
    readonly code: MfaValidationErrorCode,
    message: string,
  ) {
    super(message);
  }
}
