import type { JwtValidationErrorCode } from "./jwt-types";

export class JwtValidationError extends Error {
  constructor(readonly code: JwtValidationErrorCode, message: string) {
    super(message);
    this.name = "JwtValidationError";
  }
}
