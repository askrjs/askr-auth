/** Encode binary data as unpadded base64url. @param buffer Bytes to encode. @returns Canonical base64url text. */
export function encodeBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const value of bytes) binary += String.fromCharCode(value);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

/** Decode canonical unpadded base64url. @param value Base64url text. @returns Decoded bytes. */
export function decodeBase64Url(value: string): ArrayBuffer {
  if (!/^[A-Za-z0-9_-]*$/u.test(value) || value.length % 4 === 1)
    throw new TypeError("Value must be canonical base64url without padding.");
  let binary: string;
  try {
    binary = atob(
      value
        .replaceAll("-", "+")
        .replaceAll("_", "/")
        .padEnd(Math.ceil(value.length / 4) * 4, "="),
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
