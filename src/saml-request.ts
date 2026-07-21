import { createPrivateKey, randomBytes, sign } from "node:crypto";
import { deflateRawSync } from "node:zlib";
import { DOMImplementation, XMLSerializer } from "@xmldom/xmldom";
import { NS } from "./saml-dom";
import type { SamlServiceProviderOptions } from "./saml-types";

const signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const encode = (value: string): string => encodeURIComponent(value).replace(/[!'()*]/gu, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

export async function createRequest(options: SamlServiceProviderOptions, relayState?: string): Promise<{ url: string; requestId: string }> {
  const now = (options.clock ?? Date.now)();
  const requestId = `_askr_${randomBytes(20).toString("hex")}`;
  const doc = new DOMImplementation().createDocument(NS.protocol, "samlp:AuthnRequest", null);
  const root = doc.documentElement;
  root.setAttribute("xmlns:samlp", NS.protocol); root.setAttribute("xmlns:saml", NS.assertion);
  root.setAttribute("ID", requestId); root.setAttribute("Version", "2.0");
  root.setAttribute("IssueInstant", new Date(now).toISOString()); root.setAttribute("Destination", options.idp.ssoUrl);
  root.setAttribute("AssertionConsumerServiceURL", options.acsUrl);
  root.setAttribute("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
  const issuer = doc.createElementNS(NS.assertion, "saml:Issuer"); issuer.appendChild(doc.createTextNode(options.entityId)); root.appendChild(issuer);
  const xml = new XMLSerializer().serializeToString(doc);
  const samlRequest = deflateRawSync(Buffer.from(xml)).toString("base64");
  let query = `SAMLRequest=${encode(samlRequest)}`;
  if (relayState !== undefined) query += `&RelayState=${encode(relayState)}`;
  if (options.signRequests) {
    query += `&SigAlg=${encode(signatureAlgorithm)}`;
    const key = createPrivateKey({ key: options.signRequests.privateKey, format: "jwk" });
    query += `&Signature=${encode(sign("RSA-SHA256", Buffer.from(query), key).toString("base64"))}`;
  }
  const ttl = (options.requestTtlSeconds ?? 600) * 1000;
  await options.requestStore.save({ id: requestId, createdAt: now, expiresAt: now + ttl, ...(relayState === undefined ? {} : { relayState }) });
  const separator = options.idp.ssoUrl.includes("?") ? "&" : "?";
  return { url: `${options.idp.ssoUrl}${separator}${query}`, requestId };
}
