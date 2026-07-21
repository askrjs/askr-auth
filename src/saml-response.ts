import { NS, checkUniqueIds, children, one, parseXml, serialize, textOf } from "./saml-dom";
import { decryptAssertion, verifySignedElement } from "./saml-crypto";
import { SamlValidationError, type SamlPrincipal, type SamlServiceProviderOptions } from "./saml-types";

function decode(value: string): string {
  if (value.length > 1_398_104) malformed("SAML response exceeds 1 MiB");
  if (!/^[A-Za-z0-9+/]*={0,2}$/u.test(value) || value.length % 4 === 1) malformed("Malformed base64");
  const bytes = Buffer.from(value, "base64");
  if (bytes.length > 1024 * 1024) malformed("SAML response exceeds 1 MiB");
  const normalized = value.replace(/=+$/u, "");
  if (bytes.toString("base64").replace(/=+$/u, "") !== normalized) malformed("Malformed base64");
  return bytes.toString("utf8");
}

function instant(value: string | null, label: string): number {
  if (!value || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/u.test(value)) invalid(`Invalid ${label}`);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) invalid(`Invalid ${label}`);
  return parsed;
}

function validateTime(element: Element, now: number, skew: number, maxAge: number): void {
  const issue = instant(element.getAttribute("IssueInstant"), "IssueInstant");
  if (issue > now + skew || issue < now - maxAge - skew) invalid("Assertion IssueInstant is outside the allowed window");
  const conditions = one(element, NS.assertion, "Conditions");
  const before = conditions.getAttribute("NotBefore");
  const after = conditions.getAttribute("NotOnOrAfter");
  if (before && now + skew < instant(before, "NotBefore")) invalid("Assertion is not yet valid");
  if (!after || now - skew >= instant(after, "NotOnOrAfter")) invalid("Assertion has expired");
}

function extract(assertionXml: string, options: SamlServiceProviderOptions, now: number): { principal: SamlPrincipal; requestId: string } {
  const doc = parseXml(assertionXml); checkUniqueIds(doc);
  const assertion = doc.documentElement;
  if (assertion.namespaceURI !== NS.assertion || assertion.localName !== "Assertion") malformed("Signed reference is not an assertion");
  const issuer = textOf(one(assertion, NS.assertion, "Issuer"));
  if (issuer !== options.idp.entityId) invalid("Unexpected assertion issuer");
  validateTime(assertion, now, (options.clockSkewSeconds ?? 60) * 1000, (options.maxAssertionAgeSeconds ?? 300) * 1000);
  const conditions = one(assertion, NS.assertion, "Conditions");
  const restrictions = children(conditions, NS.assertion, "AudienceRestriction");
  if (restrictions.length < 1 || !restrictions.every((r) => children(r, NS.assertion, "Audience").some((a) => textOf(a) === options.entityId))) invalid("Unexpected audience");
  const subject = one(assertion, NS.assertion, "Subject");
  const nameId = one(subject, NS.assertion, "NameID");
  const confirmations = children(subject, NS.assertion, "SubjectConfirmation").filter((node) => node.getAttribute("Method") === "urn:oasis:names:tc:SAML:2.0:cm:bearer");
  if (confirmations.length !== 1) invalid("Expected one bearer SubjectConfirmation");
  const data = one(confirmations[0], NS.assertion, "SubjectConfirmationData");
  if (data.getAttribute("Recipient") !== options.acsUrl) invalid("Unexpected assertion recipient");
  const requestId = data.getAttribute("InResponseTo"); if (!requestId) invalid("Missing signed InResponseTo");
  const expires = instant(data.getAttribute("NotOnOrAfter"), "SubjectConfirmationData NotOnOrAfter");
  if (now - (options.clockSkewSeconds ?? 60) * 1000 >= expires) invalid("Subject confirmation has expired");
  const statements = children(assertion, NS.assertion, "AuthnStatement");
  if (statements.length !== 1) invalid("Expected one AuthnStatement");
  const attributes: Record<string, string[]> = {};
  for (const statement of children(assertion, NS.assertion, "AttributeStatement")) for (const attribute of children(statement, NS.assertion, "Attribute")) {
    const name = attribute.getAttribute("Name"); if (!name || Object.hasOwn(attributes, name)) invalid("Invalid or duplicate attribute name");
    attributes[name] = children(attribute, NS.assertion, "AttributeValue").map((value) => value.textContent ?? "");
  }
  const id = textOf(nameId, "NameID");
  return { requestId, principal: { id, subject: id, saml: { issuer, nameId: id, ...(nameId.getAttribute("Format") ? { nameIdFormat: nameId.getAttribute("Format")! } : {}), ...(statements[0].getAttribute("SessionIndex") ? { sessionIndex: statements[0].getAttribute("SessionIndex")! } : {}), attributes } } };
}

export async function validate(input: { samlResponse: string; relayState?: string }, options: SamlServiceProviderOptions): Promise<SamlPrincipal> {
  const responseXml = decode(input.samlResponse); const doc = parseXml(responseXml); checkUniqueIds(doc);
  let response = doc.documentElement;
  if (response.namespaceURI !== NS.protocol || response.localName !== "Response") malformed("Expected one SAML Response root");
  const status = one(one(response, NS.protocol, "Status"), NS.protocol, "StatusCode").getAttribute("Value");
  if (status !== "urn:oasis:names:tc:SAML:2.0:status:Success") throw new SamlValidationError("idp-error", "Identity provider returned an error");
  const responseSignatures = children(response, NS.ds, "Signature");
  if (responseSignatures.length > 1) malformed("Multiple response signatures");
  const responseSigned = responseSignatures.length === 1;
  const originalSignatureCount = elementsIn(response, NS.ds, "Signature").length;
  if (options.requireSignedResponse && !responseSigned) throw new SamlValidationError("invalid-signature", "Signed response required");
  if (responseSigned) {
    const verifiedResponse = parseXml(verifySignedElement(responseXml, response, options.idp.certificates));
    checkUniqueIds(verifiedResponse); response = verifiedResponse.documentElement;
  }
  const assertions = children(response, NS.assertion, "Assertion");
  const encrypted = children(response, NS.assertion, "EncryptedAssertion");
  if (assertions.length + encrypted.length !== 1) malformed("Expected exactly one assertion");
  const maximumSignatures = encrypted.length ? Number(responseSigned) : 1 + Number(responseSigned);
  if (originalSignatureCount > maximumSignatures) malformed("Unexpected signature placement or count");
  let assertionXml: string;
  if (encrypted.length) {
    if (!options.decryptAssertions) throw new SamlValidationError("invalid-signature", "Encrypted assertion is not configured");
    assertionXml = await decryptAssertion(encrypted[0], options.decryptAssertions.privateKey);
  } else assertionXml = serialize(assertions[0]);
  const assertionDoc = parseXml(assertionXml); checkUniqueIds(assertionDoc);
  const verified = encrypted.length
    ? verifySignedElement(assertionXml, assertionDoc.documentElement, options.idp.certificates)
    : verifySignedElement(serialize(response), assertions[0], options.idp.certificates);
  const result = extract(verified, options, (options.clock ?? Date.now)());
  if (responseSigned) {
    const destination = response.getAttribute("Destination"); const correlation = response.getAttribute("InResponseTo");
    if (destination !== options.acsUrl || correlation !== result.requestId) invalid("Signed response correlation mismatch");
  }
  const stored = await options.requestStore.get(result.requestId);
  if (!stored || stored.expiresAt <= (options.clock ?? Date.now)()) throw new SamlValidationError("unknown-request", "Unknown or expired SAML request");
  if (stored.relayState !== input.relayState) invalid("RelayState mismatch");
  if (!(await options.requestStore.consume(result.requestId))) throw new SamlValidationError("replayed-response", "SAML response has already been consumed");
  return result.principal;
}

function malformed(message: string): never { throw new SamlValidationError("malformed-response", message); }
function invalid(message: string): never { throw new SamlValidationError("invalid-claim", message); }

function elementsIn(parent: Element, namespace: string, localName: string): Element[] {
  return Array.from(parent.getElementsByTagNameNS(namespace, localName));
}
