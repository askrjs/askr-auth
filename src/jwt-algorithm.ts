import type { AskrJsonWebKey } from "./jwt-types";

export type JwtAlgorithmName = "RS256" | "ES256";

interface JwtAlgorithm {
  readonly jwt: JwtAlgorithmName;
  readonly kty: string;
  readonly crv?: string;
  readonly import: RsaHashedImportParams | EcKeyImportParams;
  readonly operation: AlgorithmIdentifier | EcdsaParams;
}

const algorithms: readonly JwtAlgorithm[] = [
  {
    jwt: "RS256",
    kty: "RSA",
    import: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    operation: { name: "RSASSA-PKCS1-v1_5" },
  },
  {
    jwt: "ES256",
    kty: "EC",
    crv: "P-256",
    import: { name: "ECDSA", namedCurve: "P-256" },
    operation: { name: "ECDSA", hash: "SHA-256" },
  },
] as const;

export function resolveJwtAlgorithm(key: AskrJsonWebKey): JwtAlgorithm {
  const algorithm = algorithms.find(
    (candidate) => candidate.kty === key.kty && candidate.crv === key.crv,
  );
  if (!algorithm)
    throw new TypeError(
      `Unsupported JWT key shape: ${key.kty ?? "missing"}/${key.crv ?? "none"}.`,
    );

  if (key.alg !== undefined && key.alg !== algorithm.jwt)
    throw new TypeError(`JWK alg ${key.alg} conflicts with ${algorithm.jwt} key shape.`);
  return algorithm;
}
