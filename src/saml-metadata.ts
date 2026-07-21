import { DOMImplementation, XMLSerializer } from "@xmldom/xmldom";
import { NS } from "./saml-dom";
import type { SamlServiceProviderOptions } from "./saml-types";

function certificateBody(pem: string): string {
  return pem.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s/gu, "");
}

export function createMetadata(options: SamlServiceProviderOptions): string {
  const doc = new DOMImplementation().createDocument(NS.metadata, "md:EntityDescriptor", null);
  const root = doc.documentElement;
  root.setAttribute("entityID", options.entityId);
  root.setAttribute("xmlns:md", NS.metadata);
  root.setAttribute("xmlns:ds", NS.ds);
  const descriptor = doc.createElementNS(NS.metadata, "md:SPSSODescriptor");
  descriptor.setAttribute("AuthnRequestsSigned", String(Boolean(options.signRequests)));
  descriptor.setAttribute("WantAssertionsSigned", "true");
  descriptor.setAttribute("protocolSupportEnumeration", NS.protocol);
  for (const config of [options.signRequests && { use: "signing", ...options.signRequests }, options.decryptAssertions && { use: "encryption", ...options.decryptAssertions }]) {
    if (!config) continue;
    const key = doc.createElementNS(NS.metadata, "md:KeyDescriptor");
    key.setAttribute("use", config.use);
    const info = doc.createElementNS(NS.ds, "ds:KeyInfo");
    const data = doc.createElementNS(NS.ds, "ds:X509Data");
    const cert = doc.createElementNS(NS.ds, "ds:X509Certificate");
    cert.appendChild(doc.createTextNode(certificateBody(config.certificate)));
    data.appendChild(cert); info.appendChild(data); key.appendChild(info); descriptor.appendChild(key);
  }
  const acs = doc.createElementNS(NS.metadata, "md:AssertionConsumerService");
  acs.setAttribute("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
  acs.setAttribute("Location", options.acsUrl);
  acs.setAttribute("index", "0"); acs.setAttribute("isDefault", "true");
  descriptor.appendChild(acs); root.appendChild(descriptor);
  return new XMLSerializer().serializeToString(doc);
}
