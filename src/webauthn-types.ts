import type { CoseAlgorithm } from "./cose";

/** Server-side WebAuthn registration ceremony data. */
export interface WebAuthnRegistrationInput {
  /** Credential identifier returned by the browser. */
  credentialId: Uint8Array;
  /** Browser client-data JSON bytes. */
  clientDataJSON: Uint8Array;
  /** Browser attestation object bytes. */
  attestationObject: Uint8Array;
  /** Challenge originally issued by the server. */
  expectedChallenge: Uint8Array;
  /** Allowed origins for this ceremony. */
  allowedOrigins: readonly string[];
  /** Relying-party identifier. */
  rpId: string;
  /** Require user verification. */
  requireUserVerification?: boolean;
}
/** Server-side WebAuthn authentication ceremony data. */
export interface WebAuthnAuthenticationInput {
  /** Credential identifier returned by the browser. */
  credentialId: Uint8Array;
  /** Credential identifier stored during registration. */
  storedCredentialId: Uint8Array;
  /** Stored public-key JWK. */
  publicKeyJwk: JsonWebKey;
  /** Authenticator data bytes. */
  authenticatorData: Uint8Array;
  /** Browser client-data JSON bytes. */
  clientDataJSON: Uint8Array;
  /** Assertion signature bytes. */
  signature: Uint8Array;
  /** Challenge originally issued by the server. */
  expectedChallenge: Uint8Array;
  /** Allowed origins for this ceremony. */
  allowedOrigins: readonly string[];
  /** Relying-party identifier. */
  rpId: string;
  /** Previously stored signature counter. */
  signCount: number;
  /** Require user verification. */
  requireUserVerification?: boolean;
}
/** Verified credential data persisted after registration. */
export interface WebAuthnRegistrationResult {
  /** Credential identifier to persist. */
  credentialId: Uint8Array;
  /** Public key to persist. */
  publicKeyJwk: JsonWebKey;
  /** COSE algorithm identifier. */
  algorithm: CoseAlgorithm;
  /** Initial signature counter. */
  signCount: number;
  /** Authenticator AAGUID. */
  aaguid: Uint8Array;
  /** Whether the credential may be backed up. */
  backupEligible: boolean;
  /** Whether the credential is currently backed up. */
  backedUp: boolean;
}
