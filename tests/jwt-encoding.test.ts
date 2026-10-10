import { afterEach, describe, expect, it, vi } from "vite-plus/test";
import { decodeBase64Url, decodeJson } from "../src/jwt-encoding";

afterEach(() => vi.unstubAllGlobals());

describe("JWT browser-native encoding", () => {
  it("should decode canonical bytes without a Buffer global", () => {
    vi.stubGlobal("Buffer", undefined);
    expect(decodeBase64Url("_w")).toEqual(new Uint8Array([255]));
    expect(decodeBase64Url("__8")).toEqual(new Uint8Array([255, 255]));
    expect(decodeBase64Url("AAEC_f7_")).toEqual(new Uint8Array([0, 1, 2, 253, 254, 255]));
    expect(decodeBase64Url("")).toEqual(new Uint8Array());
    expect(decodeJson("eyJzdWIiOiJ1c2VyIn0")).toEqual({ sub: "user" });
  });

  it.each(["a", "abcde", "_x", "__9", "_w=", "/w", "a+b", "AA\n", "AA "])(
    "should reject malformed or noncanonical base64url %s without Buffer",
    (value) => {
      vi.stubGlobal("Buffer", undefined);
      expect(() => decodeBase64Url(value)).toThrow("JWT contains invalid base64url data.");
    },
  );

  it("should preserve UTF-8 claims without Buffer", () => {
    const encoded = btoa(
      String.fromCharCode(
        ...new TextEncoder().encode(JSON.stringify({ name: "Zo\u00eb \u6771\u4eac" })),
      ),
    )
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replaceAll("=", "");
    vi.stubGlobal("Buffer", undefined);
    expect(decodeJson(encoded)).toEqual({ name: "Zo\u00eb \u6771\u4eac" });
  });

  it.each(["ww", "e30A", "W10", "bnVsbA", "MQ"])(
    "should reject invalid UTF-8 or non-object JSON %s",
    (value) => {
      vi.stubGlobal("Buffer", undefined);
      expect(() => decodeJson(value)).toThrow("JWT contains invalid JSON.");
    },
  );
});
