declare module "xml-encryption" {
  export function encrypt(
    xml: string,
    options: {
      rsa_pub: string | Buffer;
      pem: string | Buffer;
      encryptionAlgorithm: string;
      keyEncryptionAlgorithm: string;
      keyEncryptionDigest?: string;
      disallowEncryptionWithInsecureAlgorithm?: boolean;
    },
    callback: (error: Error | null, result?: string) => void,
  ): void;
  export function decrypt(
    xml: string,
    options: { key: string | Buffer; disallowDecryptionWithInsecureAlgorithm?: boolean },
    callback: (error: Error | null, result?: string) => void,
  ): void;
}
