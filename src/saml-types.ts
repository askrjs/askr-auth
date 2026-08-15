import type { Principal } from "./model";

/** Pending SAML authentication request retained for callback validation. */
export interface SamlStoredRequest {
  /** Request identifier. */
  id: string;
  /** Creation time in Unix milliseconds. */
  createdAt: number;
  /** Expiration time in Unix milliseconds. */
  expiresAt: number;
  /** Optional relay state returned by the identity provider. */
  relayState?: string;
}

/** Persistence contract for pending SAML requests. */
export interface SamlRequestStore {
  /** Persist a pending authentication request. @param request Request to persist. */
  save(request: SamlStoredRequest): Promise<void>;
  /** Load a pending authentication request. @param id Request identifier. @returns Stored request or null. */
  get(id: string): Promise<SamlStoredRequest | null>;
  /** Consume a pending request exactly once. @param id Request identifier. @returns Whether a request was consumed. */
  consume(id: string): Promise<boolean>;
}

/** Service-provider metadata, identity-provider details, and validation policy. */
export interface SamlServiceProviderOptions {
  /** Service-provider entity ID. */
  entityId: string;
  /** Assertion-consumer service URL. */
  acsUrl: string;
  /** Identity-provider entity ID, SSO URL, and signing certificates. */
  idp: { entityId: string; ssoUrl: string; certificates: readonly string[] };
  /** Store for pending authentication requests. */
  requestStore: SamlRequestStore;
  /** Optional request-signing key pair. */
  signRequests?: { privateKey: JsonWebKey; certificate: string };
  /** Optional assertion-decryption key pair. */
  decryptAssertions?: { privateKey: JsonWebKey; certificate: string };
  /** Require a valid XML signature on responses. */
  requireSignedResponse?: boolean;
  /** Pending-request lifetime in seconds. */
  requestTtlSeconds?: number;
  /** Maximum assertion age in seconds. */
  maxAssertionAgeSeconds?: number;
  /** Allowed clock skew in seconds. */
  clockSkewSeconds?: number;
  /** Clock returning Unix time in milliseconds. */
  clock?: () => number;
}

/** Principal claims extracted from a validated SAML assertion. */
export interface SamlPrincipal extends Principal {
  /** SAML issuer, subject, session, and attributes. */
  saml: {
    /** Identity-provider issuer. */
    issuer: string;
    /** Assertion NameID. */
    nameId: string;
    /** Optional NameID format. */
    nameIdFormat?: string;
    /** Optional provider session index. */
    sessionIndex?: string;
    /** Assertion attributes grouped by name. */
    attributes: Readonly<Record<string, readonly string[]>>;
  };
}

/** SAML service-provider operations. */
export interface SamlServiceProvider {
  /** Render SAML metadata XML. @returns SAML metadata XML. */
  metadata(): string;
  /** Create a signed authentication request. @param options Optional relay state. @returns Redirect URL and pending request ID. */
  createAuthnRequest(options?: {
    relayState?: string;
  }): Promise<{ url: string; requestId: string }>;
  /** Validate an encoded SAML response. @param input Encoded SAML response and optional relay state. @returns Validated SAML principal. */
  validateResponse(input: { samlResponse: string; relayState?: string }): Promise<SamlPrincipal>;
}

/** Stable failure codes for SAML validation. */
export type SamlValidationErrorCode =
  | "malformed-response"
  | "unsupported-algorithm"
  | "invalid-signature"
  | "invalid-claim"
  | "unknown-request"
  | "replayed-response"
  | "idp-error";

/** Error raised when a SAML response fails validation. */
export class SamlValidationError extends Error {
  /** Error category used for programmatic handling. */
  readonly code: SamlValidationErrorCode;
  constructor(code: SamlValidationErrorCode, message: string) {
    super(message);
    this.name = "SamlValidationError";
    this.code = code;
  }
}
