import { describe, expect, test } from "vitest";
import { buildAuthnRequestRedirect } from "../src/index.js";
import { fromBase64, singleChunkStream } from "./support.js";

async function inflateRaw(bytes: Uint8Array): Promise<string> {
  const stream = singleChunkStream(bytes).pipeThrough(new DecompressionStream("deflate-raw"));
  return new Response(stream).text();
}

function queryValue(url: string, key: string): string {
  const query = url.split("?")[1] ?? "";
  for (const pair of query.split("&")) {
    const [name, value] = pair.split("=");
    if (name === key) return value ?? "";
  }
  throw new Error(`no ${key} in ${url}`);
}

describe("SP-initiated AuthnRequest (HTTP-Redirect binding)", () => {
  test("the request round-trips through DEFLATE and carries the SP identity", async () => {
    const url = await buildAuthnRequestRedirect({
      idpSsoUrl: "https://idp.example/sso",
      acsUrl: "https://sp.example/acs",
      spEntityId: "sp-entity-id",
      requestId: "_req-1",
      relayState: "state-token",
      nowUnix: 1_704_067_200,
    });
    expect(url.startsWith("https://idp.example/sso?SAMLRequest=")).toBe(true);
    expect(url).toContain("&RelayState=state-token");

    const xml = await inflateRaw(fromBase64(decodeURIComponent(queryValue(url, "SAMLRequest"))));
    expect(xml).toContain("AuthnRequest");
    expect(xml).toContain('ID="_req-1"');
    expect(xml).toContain('Version="2.0"');
    expect(xml).toContain('IssueInstant="2024-01-01T00:00:00Z"');
    expect(xml).toContain('Destination="https://idp.example/sso"');
    expect(xml).toContain('AssertionConsumerServiceURL="https://sp.example/acs"');
    expect(xml).toContain('ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"');
    expect(xml).toContain("<saml:Issuer>sp-entity-id</saml:Issuer>");
  });

  test("an IdP URL that already has a query gets `&`, not a second `?`", async () => {
    const url = await buildAuthnRequestRedirect({
      idpSsoUrl: "https://idp.example/sso?tenant=acme",
      acsUrl: "https://sp.example/acs",
      spEntityId: "sp",
      requestId: "_r",
      relayState: "s",
      nowUnix: 0,
    });
    expect(url).toContain("?tenant=acme&SAMLRequest=");
    expect(url.split("?").length).toBe(2);
  });

  test("values are XML-escaped, so a hostile SP entity id cannot inject elements", async () => {
    const url = await buildAuthnRequestRedirect({
      idpSsoUrl: "https://idp.example/sso",
      acsUrl: "https://sp.example/acs",
      spEntityId: '"><saml:Issuer>evil</saml:Issuer><x y="',
      requestId: "_r",
      relayState: "s",
      nowUnix: 0,
    });
    const xml = await inflateRaw(fromBase64(decodeURIComponent(queryValue(url, "SAMLRequest"))));
    expect(xml).not.toContain("<saml:Issuer>evil</saml:Issuer>");
    expect(xml).toContain("&lt;saml:Issuer&gt;evil&lt;/saml:Issuer&gt;");
  });

  test("the RelayState is percent-encoded with the unreserved set only", async () => {
    const url = await buildAuthnRequestRedirect({
      idpSsoUrl: "https://idp.example/sso",
      acsUrl: "https://sp.example/acs",
      spEntityId: "sp",
      requestId: "_r",
      relayState: "a b&c=d~e",
      nowUnix: 0,
    });
    expect(queryValue(url, "RelayState")).toBe("a%20b%26c%3Dd~e");
  });
});
