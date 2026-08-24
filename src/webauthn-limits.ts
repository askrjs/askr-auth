import { MfaValidationError } from "./mfa-error";

const limits = {
  clientDataJSON: 8_192,
  attestationObject: 65_536,
  authenticatorData: 65_536,
  signature: 512,
  credentialId: 1_023,
  challenge: 1_024,
} as const;

function bounded(value: Uint8Array, maximum: number, label: string): void {
  if (!(value instanceof Uint8Array) || value.length > maximum)
    throw new MfaValidationError("malformed-input", `${label} is invalid or too large.`);
}

export function assertRegistrationLimits(input: {
  credentialId: Uint8Array;
  clientDataJSON: Uint8Array;
  attestationObject: Uint8Array;
  expectedChallenge: Uint8Array;
}): void {
  bounded(input.credentialId, limits.credentialId, "Credential ID");
  bounded(input.clientDataJSON, limits.clientDataJSON, "Client data JSON");
  bounded(input.attestationObject, limits.attestationObject, "Attestation object");
  bounded(input.expectedChallenge, limits.challenge, "Expected challenge");
}

export function assertAuthenticationLimits(input: {
  credentialId: Uint8Array;
  storedCredentialId: Uint8Array;
  clientDataJSON: Uint8Array;
  authenticatorData: Uint8Array;
  signature: Uint8Array;
  expectedChallenge: Uint8Array;
}): void {
  bounded(input.credentialId, limits.credentialId, "Credential ID");
  bounded(input.storedCredentialId, limits.credentialId, "Stored credential ID");
  bounded(input.clientDataJSON, limits.clientDataJSON, "Client data JSON");
  bounded(input.authenticatorData, limits.authenticatorData, "Authenticator data");
  bounded(input.signature, limits.signature, "Assertion signature");
  bounded(input.expectedChallenge, limits.challenge, "Expected challenge");
}
