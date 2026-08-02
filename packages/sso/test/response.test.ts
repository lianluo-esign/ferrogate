import { describe, expect, test } from "vitest";
import {
  type AssertionExpectations,
  MAX_DEFLATE_EXPANSION_RATIO,
  MAX_INFLATED_SAML_RESPONSE_BYTES,
  MAX_SAML_RESPONSE_B64_CHARS,
  SamlError,
  parseAndValidateResponse,
  parseSamlInstant,
} from "../src/index.js";
import {
  deflateRaw,
  encodedResponse,
  sampleResponseXml,
  singleChunkStream,
  toBase64,
} from "./support.js";

const NOW = parseSamlInstant("2024-01-01T00:00:00Z");

function expectations(overrides: Partial<AssertionExpectations> = {}): AssertionExpectations {
  return {
    spEntityId: "sp-entity-id",
    idpEntityId: "https://idp.example/entity",
    inResponseTo: "_req-123",
    emailAttribute: "email",
    nameAttribute: "displayName",
    groupsAttribute: "groups",
    nowUnix: NOW,
    clockSkewSecs: 300,
    ...overrides,
  };
}

async function expectRefusal(
  work: Promise<unknown>,
  code: string,
  message?: string | RegExp,
): Promise<SamlError> {
  const error = await work.then(
    () => null,
    (caught: unknown) => caught,
  );
  expect(error, "the assertion must be REFUSED, not accepted").toBeInstanceOf(SamlError);
  const samlError = error as SamlError;
  expect(samlError.code).toBe(code);
  if (typeof message === "string") expect(samlError.message).toBe(message);
  else if (message) expect(samlError.message).toMatch(message);
  return samlError;
}

describe("assertion validation — the accepting case", () => {
  test("a valid assertion yields the identity, lowercased email and groups", async () => {
    const assertion = await parseAndValidateResponse(await encodedResponse(), expectations());
    expect(assertion.email).toBe("user@example.com");
    expect(assertion.displayName).toBe("Ada Lovelace");
    expect(assertion.groups).toEqual(["Engineering", "Admins"]);
  });

  test("with no email attribute the Subject NameID is used", async () => {
    const assertion = await parseAndValidateResponse(
      await encodedResponse({ email: null }),
      expectations(),
    );
    expect(assertion.email).toBe("subject@example.com");
  });

  test("an unconfigured idpEntityId skips the issuer check (Rust `Option` parity)", async () => {
    const assertion = await parseAndValidateResponse(
      await encodedResponse({ issuer: "https://whoever.example/entity" }),
      expectations({ idpEntityId: null }),
    );
    expect(assertion.email).toBe("user@example.com");
  });
});

describe("assertion validation — every refusal is fail-closed", () => {
  test("an UNKNOWN ISSUER is refused", async () => {
    await expectRefusal(
      parseAndValidateResponse(
        await encodedResponse({ issuer: "https://evil-idp.example/entity" }),
        expectations(),
      ),
      "issuer_mismatch",
      "assertion Issuer does not match the configured IdP entity id",
    );
  });

  test("a wrong audience (this SP is not the intended recipient) is refused", async () => {
    await expectRefusal(
      parseAndValidateResponse(await encodedResponse(), expectations({ spEntityId: "other-sp" })),
      "audience_mismatch",
      "assertion audience does not include this SP",
    );
  });

  test("an EXPIRED assertion is refused", async () => {
    await expectRefusal(
      parseAndValidateResponse(
        await encodedResponse({
          notBefore: "2020-01-01T00:00:00Z",
          notOnOrAfter: "2020-01-01T01:00:00Z",
        }),
        expectations(),
      ),
      "assertion_expired",
      "assertion has expired (NotOnOrAfter)",
    );
  });

  test("a NOT-YET-VALID assertion is refused", async () => {
    await expectRefusal(
      parseAndValidateResponse(
        await encodedResponse({ notBefore: "2030-01-01T00:00:00Z" }),
        expectations(),
      ),
      "assertion_not_yet_valid",
      "assertion is not yet valid (NotBefore)",
    );
  });

  test("clock skew is bounded: 299s of skew passes, 301s does not", async () => {
    const notOnOrAfter = "2024-01-01T00:00:00Z";
    const encoded = await encodedResponse({ notBefore: "2020-01-01T00:00:00Z", notOnOrAfter });
    const deadline = parseSamlInstant(notOnOrAfter);
    await expect(
      parseAndValidateResponse(
        encoded,
        expectations({ nowUnix: deadline + 299, clockSkewSecs: 300 }),
      ),
    ).resolves.toMatchObject({ email: "user@example.com" });
    await expectRefusal(
      parseAndValidateResponse(
        encoded,
        expectations({ nowUnix: deadline + 301, clockSkewSecs: 300 }),
      ),
      "assertion_expired",
    );
  });

  test("an InResponseTo that does not match the pending AuthnRequest is refused", async () => {
    await expectRefusal(
      parseAndValidateResponse(
        await encodedResponse(),
        expectations({ inResponseTo: "_a-different-request" }),
      ),
      "in_response_to_mismatch",
      "InResponseTo does not match the pending AuthnRequest",
    );
  });

  test("an UNSOLICITED response (no InResponseTo at all) is refused when one is pending", async () => {
    const xml = sampleResponseXml().replace(' InResponseTo="_req-123"', "");
    expect(xml).not.toContain('InResponseTo="_req-123"');
    await expectRefusal(
      parseAndValidateResponse(toBase64(await deflateRaw(xml)), expectations()),
      "in_response_to_mismatch",
    );
  });

  test("a non-Success status is refused", async () => {
    await expectRefusal(
      parseAndValidateResponse(
        await encodedResponse({ status: "urn:oasis:names:tc:SAML:2.0:status:Requester" }),
        expectations(),
      ),
      "status_not_success",
      'status is not Success (got Some("urn:oasis:names:tc:SAML:2.0:status:Requester"))',
    );
  });

  test("a response with NO status element at all is refused", async () => {
    const xml = sampleResponseXml().replace(/<samlp:Status>.*?<\/samlp:Status>/, "");
    expect(xml).not.toContain("StatusCode");
    await expectRefusal(
      parseAndValidateResponse(toBase64(await deflateRaw(xml)), expectations()),
      "status_not_success",
      "status is not Success (got None)",
    );
  });

  test("an assertion with no usable email is refused", async () => {
    await expectRefusal(
      parseAndValidateResponse(
        await encodedResponse({ email: null, nameId: null }),
        expectations(),
      ),
      "no_usable_email",
      "assertion did not include a usable email",
    );
  });

  test("a syntactically invalid email is refused rather than provisioned", async () => {
    await expectRefusal(
      parseAndValidateResponse(
        await encodedResponse({ email: "not-an-email", nameId: null }),
        expectations(),
      ),
      "no_usable_email",
    );
  });
});

describe("DEFLATE decoding is fail-closed and bounded", () => {
  test("a payload that is not valid base64 is refused", async () => {
    await expectRefusal(
      parseAndValidateResponse("@@@not base64@@@", expectations()),
      "saml_response_not_base64",
      /^SAMLResponse is not valid base64: /,
    );
  });

  test("a MALFORMED deflate stream is refused, not treated as empty", async () => {
    await expectRefusal(
      parseAndValidateResponse(toBase64(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])), expectations()),
      "saml_response_inflate_failed",
      /^SAMLResponse could not be inflated: /,
    );
  });

  test("a TRUNCATED deflate stream is refused", async () => {
    const full = await deflateRaw(sampleResponseXml());
    await expectRefusal(
      parseAndValidateResponse(toBase64(full.slice(0, full.length - 5)), expectations()),
      "saml_response_inflate_failed",
    );
  });

  test("a zlib-wrapped (not raw) deflate stream is refused — the binding mandates raw", async () => {
    const zlib = singleChunkStream(new TextEncoder().encode(sampleResponseXml())).pipeThrough(
      new CompressionStream("deflate"),
    );
    const bytes = new Uint8Array(await new Response(zlib).arrayBuffer());
    await expectRefusal(
      parseAndValidateResponse(toBase64(bytes), expectations()),
      "saml_response_inflate_failed",
    );
  });

  test("a DECOMPRESSION BOMB is refused without hanging or reaching the XML scanner", async () => {
    // 8 MiB of zeros deflates to a few KiB — small enough to slip past the
    // ENCODED cap, so this is the case the inflated cap exists for. An
    // unbounded inflate (what the Rust port did) would hand 8 MiB of nulls to
    // the parser.
    const bomb = await deflateRaw(new Uint8Array(8 * 1024 * 1024));
    expect(bomb.length).toBeLessThan(MAX_SAML_RESPONSE_B64_CHARS / 2);
    const started = Date.now();
    const error = await expectRefusal(
      parseAndValidateResponse(toBase64(bomb), expectations()),
      "saml_response_too_large",
    );
    expect(error.message).toMatch(/inflated/);
    expect(Date.now() - started, "must refuse promptly").toBeLessThan(10_000);
  });

  test("an OVERSIZED encoded payload is refused before it is even decoded", async () => {
    const oversized = "A".repeat(MAX_SAML_RESPONSE_B64_CHARS + 4);
    const error = await expectRefusal(
      parseAndValidateResponse(oversized, expectations()),
      "saml_response_too_large",
    );
    expect(error.message).toMatch(/encoded/);
  });

  test("the caps bound worst-case memory", () => {
    expect(MAX_INFLATED_SAML_RESPONSE_BYTES).toBe(1024 * 1024);
    expect(MAX_SAML_RESPONSE_B64_CHARS).toBe(32 * 1024);
    // The ENCODED cap is the one that actually bounds memory, because the
    // inflated size can only be measured after inflating. Raising it without
    // re-deriving this bound is how a bomb gets back in.
    const worstCaseBytes = ((MAX_SAML_RESPONSE_B64_CHARS * 3) / 4) * MAX_DEFLATE_EXPANSION_RATIO;
    expect(worstCaseBytes).toBeLessThan(32 * 1024 * 1024);
  });
});

describe("XML parsing is fail-closed", () => {
  test("malformed XML is refused", async () => {
    await expectRefusal(
      parseAndValidateResponse(toBase64(await deflateRaw("<a><b></a>")), expectations()),
      "malformed_saml_xml",
      /^malformed SAML XML: /,
    );
  });

  test("MIS-NESTED elements are refused even when the tag counts balance", async () => {
    // `</Subject></NameID>` instead of `</NameID></Subject>`: every tag still
    // has a partner and the stack still empties at EOF, so the ONLY thing that
    // can catch this is the check that an end tag closes the element it says it
    // closes. Without it the NameID text would be attributed to whatever the
    // corrupted stack happened to point at — which is how a value gets read as
    // an Audience, an Issuer or a NameID it was never inside.
    const xml = sampleResponseXml().replace(
      "<saml:Subject><saml:NameID>subject@example.com</saml:NameID></saml:Subject>",
      "<saml:Subject><saml:NameID>subject@example.com</saml:Subject></saml:NameID>",
    );
    expect(xml).toContain("</saml:Subject></saml:NameID>");
    expect((xml.match(/<saml:NameID>/g) ?? []).length).toBe(
      (xml.match(/<\/saml:NameID>/g) ?? []).length,
    );
    await expectRefusal(
      parseAndValidateResponse(toBase64(await deflateRaw(xml)), expectations()),
      "malformed_saml_xml",
      /does not close/,
    );
  });

  test("an unterminated tag is refused", async () => {
    await expectRefusal(
      parseAndValidateResponse(toBase64(await deflateRaw("<a attr=")), expectations()),
      "malformed_saml_xml",
    );
  });

  test("a DOCTYPE is refused outright (XXE / entity-expansion fail-closed)", async () => {
    const xml = `<!DOCTYPE Response [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]>${sampleResponseXml()}`;
    await expectRefusal(
      parseAndValidateResponse(toBase64(await deflateRaw(xml)), expectations()),
      "malformed_saml_xml",
      /DOCTYPE/,
    );
  });

  test("an unknown entity reference is refused rather than passed through", async () => {
    const xml = sampleResponseXml().replace("Ada Lovelace", "Ada &xxe; Lovelace");
    await expectRefusal(
      parseAndValidateResponse(toBase64(await deflateRaw(xml)), expectations()),
      "malformed_saml_xml",
      /entity/,
    );
  });

  test("the five predefined entities and numeric references still decode", async () => {
    const xml = sampleResponseXml().replace(
      "Ada Lovelace",
      "Ada &amp; &lt;Lovelace&gt; &#65;&#x42;",
    );
    const assertion = await parseAndValidateResponse(
      toBase64(await deflateRaw(xml)),
      expectations(),
    );
    expect(assertion.displayName).toBe("Ada & <Lovelace> AB");
  });

  test("XML comments and CDATA do not smuggle values past the parser", async () => {
    const xml = sampleResponseXml().replace(
      "<saml:Audience>sp-entity-id</saml:Audience>",
      "<saml:Audience><!-- sp-entity-id -->attacker-sp</saml:Audience>",
    );
    await expectRefusal(
      parseAndValidateResponse(toBase64(await deflateRaw(xml)), expectations()),
      "audience_mismatch",
    );
  });

  test("namespace PREFIXES are ignored — only local names are matched", async () => {
    // Real IdPs pick their own prefixes (`saml2p:`, `ns0:`, none at all). The
    // Rust port matched on quick-xml's `local_name()`; a port that matched the
    // literal `samlp:Response` would reject half the IdPs in the world.
    const xml = sampleResponseXml()
      .replaceAll("<samlp:", "<zz:")
      .replaceAll("</samlp:", "</zz:")
      .replaceAll("<saml:", "<q:")
      .replaceAll("</saml:", "</q:")
      .replaceAll("xmlns:samlp=", "xmlns:zz=")
      .replaceAll("xmlns:saml=", "xmlns:q=");
    expect(xml).not.toContain("samlp:");
    const assertion = await parseAndValidateResponse(
      toBase64(await deflateRaw(xml)),
      expectations(),
    );
    expect(assertion.email).toBe("user@example.com");
  });
});
