import type { Principal } from "./model";

export interface SamlStoredRequest {
  id: string;
  createdAt: number;
  expiresAt: number;
  relayState?: string;
}

export interface SamlRequestStore {
  save(request: SamlStoredRequest): Promise<void>;
  get(id: string): Promise<SamlStoredRequest | null>;
  consume(id: string): Promise<boolean>;
}

export interface SamlServiceProviderOptions {
  entityId: string;
  acsUrl: string;
  idp: { entityId: string; ssoUrl: string; certificates: readonly string[] };
  requestStore: SamlRequestStore;
  signRequests?: { privateKey: JsonWebKey; certificate: string };
  decryptAssertions?: { privateKey: JsonWebKey; certificate: string };
  requireSignedResponse?: boolean;
  requestTtlSeconds?: number;
  maxAssertionAgeSeconds?: number;
  clockSkewSeconds?: number;
  clock?: () => number;
}

export interface SamlPrincipal extends Principal {
  saml: {
    issuer: string;
    nameId: string;
    nameIdFormat?: string;
    sessionIndex?: string;
    attributes: Readonly<Record<string, readonly string[]>>;
  };
}

export interface SamlServiceProvider {
  metadata(): string;
  createAuthnRequest(options?: { relayState?: string }): Promise<{ url: string; requestId: string }>;
  validateResponse(input: { samlResponse: string; relayState?: string }): Promise<SamlPrincipal>;
}

export type SamlValidationErrorCode =
  | "malformed-response"
  | "unsupported-algorithm"
  | "invalid-signature"
  | "invalid-claim"
  | "unknown-request"
  | "replayed-response"
  | "idp-error";

export class SamlValidationError extends Error {
  readonly code: SamlValidationErrorCode;
  constructor(code: SamlValidationErrorCode, message: string) {
    super(message);
    this.name = "SamlValidationError";
    this.code = code;
  }
}
