import { describe, expect, test } from "vitest";
import {
  R2_ENDPOINT_SUFFIX,
  R2_REGION,
  endpointTargetsR2,
  parseEndpoint,
  parseR2Endpoint,
} from "../src/asset-endpoint.js";

describe("parseEndpoint", () => {
  test("decomposes scheme / authority / path prefix and lowercases the host", () => {
    const parts = parseEndpoint("HTTPS://Bucket.Example.COM:9000/Storage/v1/s3/");
    expect(parts.scheme).toBe("https");
    expect(parts.authority).toBe("bucket.example.com:9000");
    expect(parts.pathPrefix).toBe("/Storage/v1/s3"); // path case preserved, trailing / trimmed
    expect(parts.signingHost()).toBe("bucket.example.com:9000");
    expect(parts.hostName()).toBe("bucket.example.com");
  });

  test("defaults to https and treats ? and # as authority terminators", () => {
    expect(parseEndpoint("host.example.com?x=1").pathPrefix).toBe("?x=1");
    expect(parseEndpoint("host.example.com").scheme).toBe("https");
  });

  test("strips userinfo from signingHost but keeps it in authority", () => {
    const parts = parseEndpoint("https://user:pass@host.example.com");
    expect(parts.authority).toBe("user:pass@host.example.com");
    expect(parts.signingHost()).toBe("host.example.com");
    expect(parts.hostName()).toBe("host.example.com");
  });

  test("throws on an endpoint with no host", () => {
    expect(() => parseEndpoint("https://")).toThrow(/has no host/);
  });
});

describe("R2 detection", () => {
  test("R2_REGION / suffix constants match the invariant", () => {
    expect(R2_REGION).toBe("auto");
    expect(R2_ENDPOINT_SUFFIX).toBe("r2.cloudflarestorage.com");
  });

  test("endpointTargetsR2 is permissive (matches even malformed R2 shapes)", () => {
    expect(endpointTargetsR2("https://abc123.r2.cloudflarestorage.com")).toBe(true);
    expect(endpointTargetsR2("https://ABC.R2.CLOUDFLARESTORAGE.COM:9000/x")).toBe(true);
    expect(endpointTargetsR2("https://supabase.co/storage")).toBe(false);
  });

  test("parseR2Endpoint accepts the bare account host and jurisdiction labels", () => {
    expect(parseR2Endpoint("https://abc123.r2.cloudflarestorage.com")).toEqual({
      accountId: "abc123",
      jurisdiction: null,
    });
    expect(parseR2Endpoint("https://acct.eu.r2.cloudflarestorage.com")).toEqual({
      accountId: "acct",
      jurisdiction: "eu",
    });
    expect(parseR2Endpoint("https://acct.fedramp.r2.cloudflarestorage.com")).toEqual({
      accountId: "acct",
      jurisdiction: "fedramp",
    });
  });

  test("parseR2Endpoint rejects http, port, path, userinfo, and multi-label/empty account", () => {
    expect(parseR2Endpoint("http://abc.r2.cloudflarestorage.com")).toBeNull(); // plaintext
    expect(parseR2Endpoint("https://abc.r2.cloudflarestorage.com:9000")).toBeNull(); // port
    expect(parseR2Endpoint("https://abc.r2.cloudflarestorage.com/bucket")).toBeNull(); // path
    expect(parseR2Endpoint("https://u@abc.r2.cloudflarestorage.com")).toBeNull(); // userinfo
    expect(parseR2Endpoint("https://a.b.r2.cloudflarestorage.com")).toBeNull(); // multi-label account
    expect(parseR2Endpoint("https://r2.cloudflarestorage.com")).toBeNull(); // empty account
  });
});
