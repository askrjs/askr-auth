import type { JwtValidationErrorCode } from "./jwt-types";

/** Error raised when a JWT cannot be validated. */
export class JwtValidationError extends Error {
  /** Error category used for programmatic handling. */
  constructor(
    /** Error category used for programmatic handling. */
    readonly code: JwtValidationErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "JwtValidationError";
  }
}
