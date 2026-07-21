import { readFileSync } from "node:fs";
import { createPrivateKey, verify } from "node:crypto";
import { inflateRawSync } from "node:zlib";
import { resolve } from "node:path";
import { SignedXml } from "xml-crypto";
import { encrypt } from "xml-encryption";
import { describe, expect, it } from "vitest";
import { createSamlServiceProvider, SamlValidationError, type SamlStoredRequest } from "../src/saml";

const key = readFileSync(resolve(import.meta.dirname, "fixtures/idp-key.pem"), "utf8");
const certificate = readFileSync(resolve(import.meta.dirname, "fixtures/idp-cert.pem"), "utf8");
const now = Date.parse("2026-07-21T12:00:00.000Z");

class Store {
  requests = new Map<string, SamlStoredRequest>();
  consumed = new Set<string>();
  async save(request: SamlStoredRequest) { this.requests.set(request.id, request); }
  async get(id: string) { return this.requests.get(id) ?? null; }
  async consume(id: string) {
    if (!this.requests.has(id) || this.consumed.has(id)) return false;
    this.consumed.add(id); return true;
  }
}

function signedAssertion(requestId: string, overrides: { audience?: string; recipient?: string; issuer?: string } = {}): string {
  const assertion = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion" Version="2.0" IssueInstant="2026-07-21T12:00:00.000Z"><saml:Issuer>${overrides.issuer ?? "https://idp.example"}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="${requestId}" Recipient="${overrides.recipient ?? "https://sp.example/acs"}" NotOnOrAfter="2026-07-21T12:05:00.000Z"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2026-07-21T11:59:00.000Z" NotOnOrAfter="2026-07-21T12:05:00.000Z"><saml:AudienceRestriction><saml:Audience>${overrides.audience ?? "https://sp.example/metadata"}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement SessionIndex="session-1" AuthnInstant="2026-07-21T12:00:00.000Z"/><saml:AttributeStatement><saml:Attribute Name="groups"><saml:AttributeValue>admin</saml:AttributeValue><saml:AttributeValue>billing</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>`;
  const signer = new SignedXml({ privateKey: key, publicCert: certificate });
  signer.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  signer.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
  signer.addReference({
    xpath: "/*[local-name()='Assertion']",
    transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
  });
  signer.computeSignature(assertion, { location: { reference: "/*[local-name()='Assertion']/*[local-name()='Issuer']", action: "after" } });
  return signer.getSignedXml();
}

function response(assertion: string, _requestId: string): string {
  return Buffer.from(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_response" Version="2.0" IssueInstant="2026-07-21T12:00:00.000Z" Destination="https://untrusted.example/ignored" InResponseTo="_untrusted"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${assertion}</samlp:Response>`).toString("base64");
}

function signedResponse(assertion: string, requestId: string): string {
  const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_response" Version="2.0" IssueInstant="2026-07-21T12:00:00.000Z" Destination="https://sp.example/acs" InResponseTo="${requestId}"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${assertion}</samlp:Response>`;
  const signer = new SignedXml({ privateKey: key, publicCert: certificate });
  signer.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  signer.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
  signer.addReference({ xpath: "/*[local-name()='Response']", transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"], digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256" });
  signer.computeSignature(xml, { location: { reference: "/*[local-name()='Response']/*[local-name()='Status']", action: "before" } });
  return Buffer.from(signer.getSignedXml()).toString("base64");
}

function setup(store = new Store()) {
  return { store, service: createSamlServiceProvider({
    entityId: "https://sp.example/metadata", acsUrl: "https://sp.example/acs",
    idp: { entityId: "https://idp.example", ssoUrl: "https://idp.example/sso", certificates: [certificate] },
    requestStore: store, clock: () => now,
  }) };
}

async function encryptedAssertion(assertion: string): Promise<string> {
  const data = await new Promise<string>((resolvePromise, reject) => encrypt(assertion, {
    rsa_pub: certificate, pem: certificate,
    encryptionAlgorithm: "http://www.w3.org/2009/xmlenc11#aes256-gcm",
    keyEncryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
    keyEncryptionDigest: "sha256", disallowEncryptionWithInsecureAlgorithm: true,
  }, (error, result) => error || !result ? reject(error) : resolvePromise(result)));
  return `<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${data}</saml:EncryptedAssertion>`;
}

describe("SAML service provider", () => {
  it("should give signed-assertion metadata when metadata is requested", () => {
    const { service } = setup();
    expect(service.metadata()).toContain("WantAssertionsSigned=\"true\"");
  });

  it("should give a persisted RelayState when an AuthnRequest is created", async () => {
    const { service, store } = setup();
    const created = await service.createAuthnRequest({ relayState: "return / here" });
    expect(store.requests.get(created.requestId)?.relayState).toBe("return / here");
  });

  it("should give a matching request ID when a Redirect-binding request is decoded", async () => {
    const { service } = setup();
    const created = await service.createAuthnRequest({ relayState: "return / here" });
    const url = new URL(created.url);
    const xml = inflateRawSync(Buffer.from(url.searchParams.get("SAMLRequest")!, "base64")).toString();
    expect(xml).toContain(`ID="${created.requestId}"`);
  });

  it("should give a valid RSA-SHA256 signature when request signing is configured", async () => {
    const store = new Store(); const privateKey = createPrivateKey(key).export({ format: "jwk" });
    const service = createSamlServiceProvider({ entityId: "https://sp.example/metadata", acsUrl: "https://sp.example/acs", idp: { entityId: "https://idp.example", ssoUrl: "https://idp.example/sso", certificates: [certificate] }, requestStore: store, clock: () => now, signRequests: { privateKey, certificate } });
    const { url } = await service.createAuthnRequest({ relayState: "state" });
    const query = new URL(url).search.slice(1); const marker = "&Signature=";
    const canonical = query.slice(0, query.indexOf(marker));
    const signature = decodeURIComponent(query.slice(query.indexOf(marker) + marker.length));
    expect(verify("RSA-SHA256", Buffer.from(canonical), certificate, Buffer.from(signature, "base64"))).toBe(true);
  });

  it("should give structured claims when a signed assertion is valid", async () => {
    const { service } = setup();
    const { requestId } = await service.createAuthnRequest({ relayState: "state" });
    await expect(service.validateResponse({ samlResponse: response(signedAssertion(requestId), requestId), relayState: "state" })).resolves.toMatchObject({
      id: "user@example.com", saml: { issuer: "https://idp.example", sessionIndex: "session-1", attributes: { groups: ["admin", "billing"] } },
    });
  });

  it("should give a replay error when a response is validated twice", async () => {
    const { service } = setup();
    const { requestId } = await service.createAuthnRequest({ relayState: "state" });
    const encoded = response(signedAssertion(requestId), requestId);
    await service.validateResponse({ samlResponse: encoded, relayState: "state" });
    await expect(service.validateResponse({ samlResponse: encoded, relayState: "state" })).rejects.toMatchObject({ code: "replayed-response" });
  });

  it("should give one success when responses consume a request concurrently", async () => {
    const { service } = setup(); const { requestId } = await service.createAuthnRequest();
    const encoded = response(signedAssertion(requestId), requestId);
    const settled = await Promise.allSettled([service.validateResponse({ samlResponse: encoded }), service.validateResponse({ samlResponse: encoded })]);
    expect(settled.filter((result) => result.status === "fulfilled")).toHaveLength(1);
  });

  it("should give a principal when an RSA-OAEP and AES-GCM assertion is valid", async () => {
    const store = new Store();
    const privateKey = createPrivateKey(key).export({ format: "jwk" });
    const service = createSamlServiceProvider({
      entityId: "https://sp.example/metadata", acsUrl: "https://sp.example/acs",
      idp: { entityId: "https://idp.example", ssoUrl: "https://idp.example/sso", certificates: [certificate] },
      requestStore: store, clock: () => now, decryptAssertions: { privateKey, certificate },
    });
    const { requestId } = await service.createAuthnRequest();
    const encrypted = await encryptedAssertion(signedAssertion(requestId));
    await expect(service.validateResponse({ samlResponse: response(encrypted, requestId) })).resolves.toMatchObject({ id: "user@example.com" });
  });

  it("should give a principal when a required outer response signature is valid", async () => {
    const store = new Store();
    const service = createSamlServiceProvider({ entityId: "https://sp.example/metadata", acsUrl: "https://sp.example/acs", idp: { entityId: "https://idp.example", ssoUrl: "https://idp.example/sso", certificates: [certificate] }, requestStore: store, clock: () => now, requireSignedResponse: true });
    const { requestId } = await service.createAuthnRequest();
    await expect(service.validateResponse({ samlResponse: signedResponse(signedAssertion(requestId), requestId) })).resolves.toMatchObject({ id: "user@example.com" });
  });

  it.each([
    ["issuer", { issuer: "https://evil.example" }], ["audience", { audience: "https://evil.example" }], ["recipient", { recipient: "https://evil.example" }],
  ])("should give an invalid-claim error when the verified %s is invalid", async (_label, overrides) => {
    const { service } = setup(); const { requestId } = await service.createAuthnRequest();
    await expect(service.validateResponse({ samlResponse: response(signedAssertion(requestId, overrides), requestId) })).rejects.toMatchObject({ code: "invalid-claim" });
  });

  it("should give a malformed-response error when multiple assertions are present", async () => {
    const { service } = setup(); const { requestId } = await service.createAuthnRequest();
    const signed = signedAssertion(requestId);
    const wrapped = response(`${signed}${signed.replaceAll("_assertion", "_other")}`, requestId);
    await expect(service.validateResponse({ samlResponse: wrapped })).rejects.toMatchObject({ code: "malformed-response" });
  });

  it("should give a validation error when base64 is malformed", async () => {
    const { service } = setup();
    await expect(service.validateResponse({ samlResponse: "%%%" })).rejects.toBeInstanceOf(SamlValidationError);
  });

  it("should give an invalid-signature error when an assertion is unsigned", async () => {
    const { service } = setup(); const { requestId } = await service.createAuthnRequest();
    const signed = signedAssertion(requestId);
    await expect(service.validateResponse({ samlResponse: response(signed.replace(/<Signature[\s\S]*<\/Signature>/u, ""), requestId) })).rejects.toMatchObject({ code: "invalid-signature" });
  });
});
