import { DOMParser, XMLSerializer } from "@xmldom/xmldom";
import { SamlValidationError } from "./saml-types";

export const NS = {
  assertion: "urn:oasis:names:tc:SAML:2.0:assertion",
  protocol: "urn:oasis:names:tc:SAML:2.0:protocol",
  metadata: "urn:oasis:names:tc:SAML:2.0:metadata",
  ds: "http://www.w3.org/2000/09/xmldsig#",
  enc: "http://www.w3.org/2001/04/xmlenc#",
} as const;

export const serialize = (node: Node): string => new XMLSerializer().serializeToString(node);

export function parseXml(xml: string): Document {
  if (/<!DOCTYPE|<!ENTITY/iu.test(xml)) fail("DTD and entity declarations are forbidden");
  const errors: string[] = [];
  const document = new DOMParser({
    errorHandler: { warning: () => undefined, error: (e) => errors.push(String(e)), fatalError: (e) => errors.push(String(e)) },
  }).parseFromString(xml, "application/xml");
  if (errors.length || !document.documentElement || document.getElementsByTagName("parsererror").length) {
    fail("Malformed XML");
  }
  return document;
}

export function elements(parent: Node, namespace: string, localName: string): Element[] {
  return Array.from((parent as Document | Element).getElementsByTagNameNS(namespace, localName));
}

export function children(parent: Node, namespace: string, localName: string): Element[] {
  return Array.from(parent.childNodes).filter(
    (node): node is Element => {
      if (node.nodeType !== 1) return false;
      const element = node as Element;
      return element.namespaceURI === namespace && element.localName === localName;
    },
  );
}

export function one(parent: Node, namespace: string, localName: string): Element {
  const matches = children(parent, namespace, localName);
  if (matches.length !== 1) fail(`Expected exactly one ${localName}`);
  return matches[0];
}

export function optional(parent: Node, namespace: string, localName: string): Element | undefined {
  const matches = children(parent, namespace, localName);
  if (matches.length > 1) fail(`Expected at most one ${localName}`);
  return matches[0];
}

export function textOf(element: Element, label = element.localName): string {
  const value = element.textContent?.trim();
  if (!value) fail(`Missing ${label}`);
  return value;
}

export function checkUniqueIds(document: Document): void {
  const seen = new Set<string>();
  for (const element of Array.from(document.getElementsByTagName("*"))) {
    for (const name of ["ID", "Id", "id"]) {
      const value = element.getAttribute(name);
      if (value && (seen.has(value) || (seen.add(value), false))) fail("Duplicate XML ID");
    }
  }
}

export function fail(message: string): never {
  throw new SamlValidationError("malformed-response", message);
}
