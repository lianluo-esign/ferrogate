/**
 * Cloudflare for SaaS CUSTOM HOSTNAMES (slice **S6**) — the provisioning half of
 * #738.
 *
 * `apps/gateway` serves a verified custom domain through the same `SiteServer`
 * the slug route uses, but a Worker only ever SEES a request for
 * `docs.acme.com` if Cloudflare terminated TLS for that hostname first. Nothing
 * in this tree asked Cloudflare to do that, and nothing told an operator whether
 * the certificate had issued — so the first request on a freshly bound domain
 * failed in a way the product could not explain.
 *
 * Everything here runs against {@link ScriptedTransport}: no network, no zone,
 * no live account. What that proves is the REQUEST SHAPES, the pagination walk,
 * the duplicate reconcile and the status fold. What it cannot prove is that
 * Cloudflare answers this way — see the module docblock in
 * `../src/custom-hostnames.ts` and the PR for #738.
 */
import { describe, expect, test } from "vitest";
import { CloudflareClient, EnvTokenResolver } from "../src/client.js";
import {
  CUSTOM_HOSTNAME_DUPLICATE_CODES,
  CustomHostnamesClient,
  customHostnameCertificateState,
} from "../src/custom-hostnames.js";
import { RecordingClock, ScriptedTransport, errorResponse, okResponse } from "./support.js";

const ZONE = "0123456789abcdef0123456789abcdef";

function hostnames(transport: ScriptedTransport, zone = ZONE) {
  return new CustomHostnamesClient(
    new CloudflareClient({
      config: { accountId: "acct_123", tokenReference: "inline-token" },
      resolver: new EnvTokenResolver({}),
      transport,
      clock: new RecordingClock(),
    }),
    zone,
  );
}

/** A Cloudflare `custom_hostnames` result, in the shape the API really sends. */
function record(
  hostname: string,
  status: string,
  sslStatus: string,
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    id: `ch-${hostname}`,
    hostname,
    status,
    ssl: { id: "ssl-1", type: "dv", method: "txt", status: sslStatus, ...extra },
    created_at: "2026-08-01T00:00:00.000000Z",
  };
}

describe("createCustomHostname — the request shape", () => {
  test("POSTs the zone-scoped collection with a DV/TXT ssl block", async () => {
    const transport = new ScriptedTransport([
      okResponse(record("docs.acme.com", "pending", "pending_validation")),
    ]);
    const created = await hostnames(transport).createCustomHostname({
      hostname: "docs.acme.com",
    });
    expect(created.id).toBe("ch-docs.acme.com");
    expect(transport.requests[0]?.method).toBe("POST");
    expect(transport.requests[0]?.url).toBe(
      `https://api.cloudflare.com/client/v4/zones/${ZONE}/custom_hostnames`,
    );
    expect(JSON.parse(transport.requests[0]?.body ?? "{}")).toEqual({
      hostname: "docs.acme.com",
      ssl: {
        method: "txt",
        type: "dv",
        bundle_method: "ubiquitous",
        settings: { min_tls_version: "1.2" },
      },
    });
  });

  test("carries the caller's overrides and custom_metadata when given", async () => {
    const transport = new ScriptedTransport([
      okResponse(record("docs.acme.com", "pending", "initializing")),
    ]);
    await hostnames(transport).createCustomHostname({
      hostname: "docs.acme.com",
      validationMethod: "http",
      minTlsVersion: "1.3",
      bundleMethod: "optimal",
      customMetadata: { tenant_id: "acme" },
    });
    expect(JSON.parse(transport.requests[0]?.body ?? "{}")).toEqual({
      hostname: "docs.acme.com",
      ssl: {
        method: "http",
        type: "dv",
        bundle_method: "optimal",
        settings: { min_tls_version: "1.3" },
      },
      custom_metadata: { tenant_id: "acme" },
    });
  });
});

describe("path-segment and hostname safety — refused BEFORE any request", () => {
  test("a zone id that could escape the path segment is refused", async () => {
    for (const zone of ["", "../accounts", "a/b", "a?x=1", "a b", "a_b"]) {
      const transport = new ScriptedTransport([]);
      await expect(
        hostnames(transport, zone).createCustomHostname({ hostname: "docs.acme.com" }),
      ).rejects.toThrowError(/cloudflare config error/);
      expect(transport.callCount).toBe(0);
    }
  });

  test("a hostname that is not a plain DNS name is refused", async () => {
    // `*.acme.com` is refused for a REASON, not for tidiness: the #488 ownership
    // proof is minted per exact hostname, so a wildcard certificate would cover
    // names nobody proved control of.
    for (const hostname of [
      "",
      "*.acme.com",
      "DOCS.acme.com",
      "https://docs.acme.com",
      "docs.acme.com:443",
      "docs.acme.com/path",
      "docs.acme.com.",
      ".acme.com",
      "localhost",
      "docs..acme.com",
      "docs.acme.com?x=1",
      "docs acme.com",
    ]) {
      const transport = new ScriptedTransport([]);
      await expect(hostnames(transport).createCustomHostname({ hostname })).rejects.toThrowError(
        /cloudflare config error/,
      );
      expect(transport.callCount).toBe(0);
    }
  });

  test("an ordinary hostname is accepted", async () => {
    const transport = new ScriptedTransport([
      okResponse(record("docs.acme.com", "pending", "pending_validation")),
    ]);
    await expect(
      hostnames(transport).createCustomHostname({ hostname: "docs.acme.com" }),
    ).resolves.toBeDefined();
  });
});

describe("findCustomHostname — the exact-match re-check", () => {
  test("filters server-side AND rejects Cloudflare's PARTIAL match client-side", async () => {
    // `?hostname=` on this endpoint is a CONTAINS filter, not an equality one.
    // Trusting it would let `acme.com` resolve to a row for `evil-acme.com`,
    // and the certificate state of somebody else's hostname would then be
    // reported as this binding's.
    const transport = new ScriptedTransport([
      okResponse([
        record("evil-acme.com", "active", "active"),
        record("docs.acme.com.attacker.test", "active", "active"),
      ]),
    ]);
    expect(await hostnames(transport).findCustomHostname("docs.acme.com")).toBeNull();
    expect(transport.requests[0]?.url).toContain("hostname=docs.acme.com");
  });

  test("returns the row whose hostname is exactly equal", async () => {
    const transport = new ScriptedTransport([
      okResponse([
        record("evil-acme.com", "active", "active"),
        record("docs.acme.com", "pending", "pending_validation"),
      ]),
    ]);
    const found = await hostnames(transport).findCustomHostname("docs.acme.com");
    expect(found?.id).toBe("ch-docs.acme.com");
  });

  test("walks past page 1 — 'absent' must not mean 'not on page 1'", async () => {
    const full = Array.from({ length: 50 }, (_, i) => record(`h${i}.acme.com`, "active", "active"));
    const transport = new ScriptedTransport([
      okResponse(full),
      okResponse([record("docs.acme.com", "pending", "pending_validation")]),
    ]);
    const found = await hostnames(transport).findCustomHostname("docs.acme.com");
    expect(found?.hostname).toBe("docs.acme.com");
    expect(transport.callCount).toBe(2);
    expect(transport.requests[0]?.url).toContain("page=1");
    expect(transport.requests[1]?.url).toContain("page=2");
  });

  test("an empty zone yields null, not an error", async () => {
    const transport = new ScriptedTransport([okResponse([])]);
    expect(await hostnames(transport).findCustomHostname("docs.acme.com")).toBeNull();
  });
});

describe("ensureCustomHostname — idempotent, and NOT by absorbing the duplicate", () => {
  test("a clean create reports created: true and the issued state", async () => {
    const transport = new ScriptedTransport([
      okResponse(
        record("docs.acme.com", "pending", "pending_validation", {
          validation_records: [
            { txt_name: "_acme-challenge.docs.acme.com", txt_value: "dcv-token" },
          ],
        }),
      ),
    ]);
    const provision = await hostnames(transport).ensureCustomHostname("docs.acme.com");
    expect(provision.created).toBe(true);
    expect(provision.id).toBe("ch-docs.acme.com");
    expect(provision.certificate.state).toBe("pending_validation");
    expect(provision.certificate.validationRecords).toEqual([
      { name: "_acme-challenge.docs.acme.com", type: "txt", value: "dcv-token" },
    ]);
    expect(transport.callCount).toBe(1);
  });

  test("a duplicate this zone already holds RECONCILES to the existing row", async () => {
    const transport = new ScriptedTransport([
      errorResponse(409, [{ code: 1406, message: "Duplicate custom hostname found." }]),
      okResponse([record("docs.acme.com", "active", "active")]),
    ]);
    const provision = await hostnames(transport).ensureCustomHostname("docs.acme.com");
    expect(provision.created).toBe(false);
    expect(provision.certificate.state).toBe("active");
    expect(transport.callCount).toBe(2);
    expect(transport.requests[1]?.method).toBe("GET");
  });

  test("a duplicate held OUTSIDE this zone is an ERROR, never a provision", async () => {
    // Custom hostnames are globally unique ACROSS Cloudflare, so 1406 does not
    // mean "you already own it" the way R2's 10004 does. Absorbing it would tell
    // an operator their certificate is on its way while the name is held by
    // another account and no certificate will ever issue.
    const transport = new ScriptedTransport([
      errorResponse(409, [{ code: 1406, message: "Duplicate custom hostname found." }]),
      okResponse([]),
    ]);
    await expect(hostnames(transport).ensureCustomHostname("docs.acme.com")).rejects.toThrowError(
      /held by another Cloudflare account/,
    );
    expect(transport.callCount).toBe(2);
  });

  test("a bare 409 with no duplicate code is NOT reconciled", async () => {
    const transport = new ScriptedTransport([
      errorResponse(409, [{ code: 1234, message: "something else entirely" }]),
    ]);
    await expect(hostnames(transport).ensureCustomHostname("docs.acme.com")).rejects.toThrowError(
      /cloudflare API error \(HTTP 409\)/,
    );
    expect(transport.callCount).toBe(1);
  });

  test("the duplicate code set is narrow and pinned", () => {
    expect([...CUSTOM_HOSTNAME_DUPLICATE_CODES]).toEqual([1406]);
  });
});

describe("deleteCustomHostname", () => {
  test("DELETEs the id-addressed row", async () => {
    const transport = new ScriptedTransport([okResponse({ id: "ch-1" })]);
    await hostnames(transport).deleteCustomHostname("ch-1");
    expect(transport.requests[0]?.method).toBe("DELETE");
    expect(transport.requests[0]?.url).toContain(`/zones/${ZONE}/custom_hostnames/ch-1`);
  });

  test("an id that could escape the path segment is refused before any request", async () => {
    const transport = new ScriptedTransport([]);
    for (const id of ["", "../zones", "a/b", "a?x=1", "a b"]) {
      await expect(hostnames(transport).deleteCustomHostname(id)).rejects.toThrowError(
        /cloudflare config error/,
      );
    }
    expect(transport.callCount).toBe(0);
  });
});

describe("customHostnameCertificateState — the operator-facing fold", () => {
  test("issued AND routing is the only `active`", () => {
    expect(customHostnameCertificateState(record("h.acme.com", "active", "active")).state).toBe(
      "active",
    );
    expect(
      customHostnameCertificateState(record("h.acme.com", "active_redeploying", "active")).state,
    ).toBe("active");
  });

  test("a live certificate on a hostname that is not routing is its OWN state", () => {
    // The case a single boolean erases: TLS is fine, the tenant's CNAME is not
    // pointed at the fallback origin, and the operator's next action is a DNS
    // change rather than waiting for a certificate.
    for (const status of ["pending", "pending_provisioned", "pending_migration", "moved"]) {
      expect(customHostnameCertificateState(record("h.acme.com", status, "active")).state).toBe(
        "issued_not_routing",
      );
    }
  });

  test("waiting on the tenant to publish DCV is `pending_validation`", () => {
    const folded = customHostnameCertificateState(
      record("h.acme.com", "pending", "pending_validation", {
        validation_records: [{ txt_name: "_acme-challenge.h.acme.com", txt_value: "v" }],
      }),
    );
    expect(folded.state).toBe("pending_validation");
    expect(folded.validationRecords).toEqual([
      { name: "_acme-challenge.h.acme.com", type: "txt", value: "v" },
    ]);
  });

  test("Cloudflare's own work in progress is `provisioning` — no operator action", () => {
    for (const ssl of [
      "initializing",
      "pending_issuance",
      "pending_deployment",
      "staging_deployment",
      "staging_active",
      "pending_cleanup",
    ]) {
      expect(customHostnameCertificateState(record("h.acme.com", "pending", ssl)).state).toBe(
        "provisioning",
      );
    }
  });

  test("every *_timed_out is `timed_out` — validation must be RESTARTED", () => {
    for (const ssl of [
      "initializing_timed_out",
      "validation_timed_out",
      "issuance_timed_out",
      "deployment_timed_out",
      "deletion_timed_out",
    ]) {
      expect(customHostnameCertificateState(record("h.acme.com", "pending", ssl)).state).toBe(
        "timed_out",
      );
    }
  });

  test("expiry and teardown are distinct from each other", () => {
    for (const ssl of ["expired", "pending_expiration"]) {
      expect(customHostnameCertificateState(record("h.acme.com", "active", ssl)).state).toBe(
        "expired",
      );
    }
    for (const ssl of ["deleted", "pending_deletion", "deactivating", "inactive"]) {
      expect(customHostnameCertificateState(record("h.acme.com", "active", ssl)).state).toBe(
        "inactive",
      );
    }
  });

  test("a blocked hostname is not folded into 'not ready yet'", () => {
    for (const status of ["blocked", "pending_blocked"]) {
      expect(customHostnameCertificateState(record("h.acme.com", status, "active")).state).toBe(
        "blocked",
      );
    }
  });

  test("an unrecognised status is `unknown` and is NEVER `active`", () => {
    const states = [
      customHostnameCertificateState(record("h.acme.com", "active", "warp_speed")).state,
      customHostnameCertificateState(record("h.acme.com", "test_active", "active")).state,
      customHostnameCertificateState(record("h.acme.com", "provisioned", "active")).state,
      customHostnameCertificateState({ hostname: "h.acme.com" }).state,
      customHostnameCertificateState(record("h.acme.com", "active", "backup_issued")).state,
      customHostnameCertificateState(record("h.acme.com", "active", "holding_deployment")).state,
    ];
    expect(states).toEqual(["unknown", "unknown", "unknown", "unknown", "unknown", "unknown"]);
  });

  test("the raw Cloudflare pair is carried through for triage", () => {
    const folded = customHostnameCertificateState(
      record("h.acme.com", "pending", "pending_validation", {
        validation_errors: [{ message: "record not found" }],
      }),
    );
    expect(folded.hostnameStatus).toBe("pending");
    expect(folded.sslStatus).toBe("pending_validation");
    expect(folded.detail).toContain("record not found");
  });
});

describe("error mapping flows through the shared client", () => {
  test("an under-scoped token names the permission groups to grant", async () => {
    const transport = new ScriptedTransport([
      errorResponse(403, [{ code: 9109, message: "Unauthorized to access requested resource" }]),
    ]);
    const error = await hostnames(transport)
      .createCustomHostname({ hostname: "docs.acme.com" })
      .then(
        () => undefined,
        (e: { kind: string; message: string }) => e,
      );
    expect(error?.kind).toBe("missing_scope");
    expect(error?.message).toContain("SSL and Certificates");
  });
});
