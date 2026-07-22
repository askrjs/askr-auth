export interface CreatePasskeyOptions {
  readonly challenge: string;
  readonly rpId: string;
  readonly rpName: string;
  readonly userId: string;
  readonly userName: string;
  readonly userDisplayName: string;
  readonly userVerification?: UserVerificationRequirement;
}

export interface PasskeyRegistration {
  readonly credentialId: string;
  readonly clientDataJSON: string;
  readonly attestationObject: string;
}

export interface GetPasskeyAssertionOptions {
  readonly challenge: string;
  readonly rpId: string;
  readonly allowCredentials?: readonly string[];
  readonly userVerification?: UserVerificationRequirement;
}

export interface PasskeyAssertion {
  readonly credentialId: string;
  readonly clientDataJSON: string;
  readonly authenticatorData: string;
  readonly signature: string;
}

export function encodeBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const value of bytes) binary += String.fromCharCode(value);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function decodeBase64Url(value: string): ArrayBuffer {
  if (!/^[A-Za-z0-9_-]*$/u.test(value) || value.length % 4 === 1)
    throw new TypeError("Value must be canonical base64url without padding.");
  let binary: string;
  try {
    binary = atob(
      value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "="),
    );
  } catch {
    throw new TypeError("Value must be canonical base64url without padding.");
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  if (encodeBase64Url(buffer) !== value)
    throw new TypeError("Value must be canonical base64url without padding.");
  return buffer;
}

function credentials(): CredentialsContainer {
  const container = globalThis.navigator?.credentials;
  if (!container) throw new TypeError("The WebAuthn Credentials API is unavailable.");
  return container;
}

function publicKeyCredential(value: Credential | null): PublicKeyCredential {
  const candidate = value as Partial<PublicKeyCredential> | null;
  if (!candidate || candidate.type !== "public-key" || !(candidate.rawId instanceof ArrayBuffer))
    throw new TypeError("The WebAuthn response is not a public-key credential.");
  return value as PublicKeyCredential;
}

function arrayBuffer(value: unknown, field: string): ArrayBuffer {
  if (!(value instanceof ArrayBuffer))
    throw new TypeError(`The WebAuthn response ${field} is invalid.`);
  return value;
}

export async function createPasskey(options: CreatePasskeyOptions): Promise<PasskeyRegistration> {
  const credential = publicKeyCredential(
    await credentials().create({
      publicKey: {
        challenge: decodeBase64Url(options.challenge),
        rp: { id: options.rpId, name: options.rpName },
        user: {
          id: decodeBase64Url(options.userId),
          name: options.userName,
          displayName: options.userDisplayName,
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -8 },
          { type: "public-key", alg: -257 },
        ],
        authenticatorSelection: {
          residentKey: "required",
          requireResidentKey: true,
          userVerification: options.userVerification ?? "required",
        },
        attestation: "none",
      },
    }),
  );
  const response = credential.response as Partial<AuthenticatorAttestationResponse>;
  return Object.freeze({
    credentialId: encodeBase64Url(credential.rawId),
    clientDataJSON: encodeBase64Url(arrayBuffer(response.clientDataJSON, "clientDataJSON")),
    attestationObject: encodeBase64Url(arrayBuffer(response.attestationObject, "attestationObject")),
  });
}

export async function getPasskeyAssertion(
  options: GetPasskeyAssertionOptions,
): Promise<PasskeyAssertion> {
  const allowCredentials = options.allowCredentials?.map((id) => ({
    type: "public-key" as const,
    id: decodeBase64Url(id),
  }));
  const credential = publicKeyCredential(
    await credentials().get({
      publicKey: {
        challenge: decodeBase64Url(options.challenge),
        rpId: options.rpId,
        userVerification: options.userVerification ?? "required",
        ...(allowCredentials?.length ? { allowCredentials } : {}),
      },
    }),
  );
  const response = credential.response as Partial<AuthenticatorAssertionResponse>;
  return Object.freeze({
    credentialId: encodeBase64Url(credential.rawId),
    clientDataJSON: encodeBase64Url(arrayBuffer(response.clientDataJSON, "clientDataJSON")),
    authenticatorData: encodeBase64Url(arrayBuffer(response.authenticatorData, "authenticatorData")),
    signature: encodeBase64Url(arrayBuffer(response.signature, "signature")),
  });
}
