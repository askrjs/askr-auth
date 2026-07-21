import { createPrivateKey } from "node:crypto";
import { SignedXml } from "xml-crypto";
import { decrypt } from "xml-encryption";
import { NS, children, elements, parseXml, serialize } from "./saml-dom";
import { SamlValidationError } from "./saml-types";

const signatures = new Set([
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
]);
const digests = new Set([
  "http://www.w3.org/2001/04/xmlenc#sha256",
  "http://www.w3.org/2001/04/xmlenc#sha512",
]);
const transforms = new Set([
  "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
  "http://www.w3.org/2001/10/xml-exc-c14n#",
]);

function algorithm(element: Element, child: string): string {
  const matches = elements(element, NS.ds, child);
  if (matches.length !== 1) unsupported(`Expected one ${child}`);
  return matches[0].getAttribute("Algorithm") ?? "";
}

function validateAlgorithms(signature: Element, expectedId: string): void {
  if (!signatures.has(algorithm(signature, "SignatureMethod"))) unsupported("Signature algorithm is not allowed");
  const canonicalization = algorithm(signature, "CanonicalizationMethod");
  if (canonicalization !== "http://www.w3.org/2001/10/xml-exc-c14n#") unsupported("Canonicalization algorithm is not allowed");
  const references = elements(signature, NS.ds, "Reference");
  if (references.length !== 1 || references[0].getAttribute("URI") !== `#${expectedId}`) unsupported("Signature must reference its containing element");
  if (!digests.has(algorithm(references[0], "DigestMethod"))) unsupported("Digest algorithm is not allowed");
  const values = elements(references[0], NS.ds, "Transform").map((node) => node.getAttribute("Algorithm") ?? "");
  if (values.length < 1 || values.some((value) => !transforms.has(value))) unsupported("Signature transform is not allowed");
}

export function verifySignedElement(documentXml: string, element: Element, certificates: readonly string[]): string {
  const id = element.getAttribute("ID");
  if (!id) throw new SamlValidationError("invalid-claim", "Signed element has no ID");
  const signatureNodes = children(element, NS.ds, "Signature");
  if (signatureNodes.length !== 1) throw new SamlValidationError("invalid-signature", "Expected one direct signature");
  validateAlgorithms(signatureNodes[0], id);
  for (const certificate of certificates) {
    try {
      const verifier = new SignedXml({ publicCert: certificate });
      verifier.loadSignature(signatureNodes[0]);
      if (!verifier.checkSignature(documentXml)) continue;
      const references = verifier.getSignedReferences();
      if (references.length === 1) return references[0];
    } catch { /* certificate rollover */ }
  }
  throw new SamlValidationError("invalid-signature", "SAML signature verification failed");
}

export async function decryptAssertion(encrypted: Element, privateKey: JsonWebKey): Promise<string> {
  const encryptedData = children(encrypted, NS.enc, "EncryptedData");
  const dataAlgorithms = encryptedData.flatMap((data) => children(data, NS.enc, "EncryptionMethod")).map((node) => node.getAttribute("Algorithm"));
  const encryptedKeys = elements(encrypted, NS.enc, "EncryptedKey");
  const keyAlgorithms = encryptedKeys.flatMap((key) => children(key, NS.enc, "EncryptionMethod")).map((node) => node.getAttribute("Algorithm"));
  const rsaOaep = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
  const aes = new Set(["http://www.w3.org/2009/xmlenc11#aes128-gcm", "http://www.w3.org/2009/xmlenc11#aes256-gcm"]);
  if (keyAlgorithms.length !== 1 || keyAlgorithms[0] !== rsaOaep || dataAlgorithms.length !== 1 || !aes.has(dataAlgorithms[0] ?? "")) {
    unsupported("Encryption algorithm is not allowed");
  }
  const pem = createPrivateKey({ key: privateKey, format: "jwk" }).export({ type: "pkcs8", format: "pem" });
  return await new Promise((resolve, reject) => decrypt(serialize(encrypted), { key: pem, disallowDecryptionWithInsecureAlgorithm: true }, (error, result) => {
    if (error || !result) reject(new SamlValidationError("invalid-signature", "Assertion decryption failed"));
    else {
      try { parseXml(result); resolve(result); } catch { reject(new SamlValidationError("malformed-response", "Decrypted assertion is malformed")); }
    }
  }));
}

function unsupported(message: string): never {
  throw new SamlValidationError("unsupported-algorithm", message);
}
