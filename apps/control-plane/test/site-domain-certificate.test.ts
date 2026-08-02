import { SELF, env } from "cloudflare:test";
/**
 * #738, the second "Done when" bullet: `GET /admin/v1/site-domains/{hostname}`
 * must surface a CERTIFICATE STATUS.
 *
 * Serving a verified custom domain was already built and already pinned. The
 * half that was missing is the one an operator hits first: a hostname whose
 * Cloudflare certificate has not issued fails at the edge, the request never
 * reaches this platform at all, and before this the admin API had no field that
 * could say so. "It does not work" and "it does not work YET, publish this TXT
 * record" are different sentences.
 *
 * Most of these drive the real Worker over `SELF.fetch` with the DETERMINISTIC
 * certificate backend, whose input is Cloudflare's own `custom_hostnames` result
 * shape and whose fold is the one `@ferrogate/cloudflare` uses for the live
 * backend. So what is proved there is the SURFACING and the STATE DISTINCTIONS.
 *
 * The last block drives `CloudflareForSaasCertificates` — the backend that
 * answers in PRODUCTION — directly, over a scripted HTTP transport. Every state
 * the deterministic backend pins is pinned on a class that is not the live one,
 * so without this block the live backend's own answers would rest on nothing.
 *
 * What is not proved — because `workerd` under vitest has no TLS terminator, no
 * zone and no certificate authority — is that Cloudflare really answers with
 * these payloads. What IS proved is what this code does with them. See
 * `src/site_domain_certificates.ts`.
 */
import {
  CloudflareClient,
  CustomHostnamesClient,
  EnvTokenResolver,
  type HttpRequest,
  type HttpResponse,
  type HttpTransport,
} from "@ferrogate/cloudflare";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  CloudflareForSaasCertificates,
  StaticSiteDomainCertificates,
} from "../src/site_domain_certificates.js";
import { BASE, arm, bearer, jsonRequest, tenantKey } from "./harness.js";

const HOST = "docs.acme.test";
const OTHER = "www.beta.test";
const A = { tenant: "tenant_a", key: "key-tenant-a" };
const B = { tenant: "tenant_b", key: "key-tenant-b" };

type MutableEnv = Record<string, string | undefined>;

/** A Cloudflare `custom_hostnames` row, in the shape the API really sends. */
function row(
  status: string,
  sslStatus: string,
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    id: "ch-1",
    status,
    ssl: { id: "ssl-1", type: "dv", method: "txt", status: sslStatus, ...extra },
  };
}

/** Point the certificate seam at a curated table, or at nothing at all. */
function certificates(records: Record<string, unknown> | string | undefined): void {
  const bindings = env as unknown as MutableEnv;
  if (records === undefined) {
    bindings.SITE_DOMAIN_CERTIFICATES = undefined;
    bindings.SITE_DOMAIN_CERTIFICATE_RECORDS = undefined;
    return;
  }
  bindings.SITE_DOMAIN_CERTIFICATES = "static";
  bindings.SITE_DOMAIN_CERTIFICATE_RECORDS =
    typeof records === "string" ? records : JSON.stringify(records);
}

async function bind(who: { tenant: string; key: string }, hostname: string): Promise<void> {
  const response = await SELF.fetch(
    `${BASE}/admin/v1/site-domains`,
    jsonRequest(who.key, "POST", { hostname, site_id: "acme" }),
  );
  expect(response.status).toBe(201);
}

interface CertificateBody {
  certificate_status?: string;
  certificate?: {
    backend?: string;
    hostname_status?: string | null;
    ssl_status?: string | null;
    detail?: string | null;
    validation_records?: { name: string; type: string; value: string }[] | null;
  };
  site_domain?: Record<string, unknown>;
  data?: Record<string, unknown>[];
}

async function read(
  who: { tenant: string; key: string },
  hostname: string,
): Promise<{ status: number; body: CertificateBody }> {
  const response = await SELF.fetch(`${BASE}/admin/v1/site-domains/${hostname}`, {
    headers: bearer(who.key),
  });
  return { status: response.status, body: (await response.json()) as CertificateBody };
}

beforeEach(() => {
  arm({ nativeKeys: [tenantKey(A.key, A.tenant), tenantKey(B.key, B.tenant)] });
  certificates(undefined);
});

describe("the states an operator has to tell apart", () => {
  it("PENDING VALIDATION names the record the tenant must publish", async () => {
    certificates({
      [HOST]: row("pending", "pending_validation", {
        validation_records: [
          { txt_name: "_acme-challenge.docs.acme.test", txt_value: "dcv-token-value" },
        ],
      }),
    });
    await bind(A, HOST);

    const { status, body } = await read(A, HOST);
    expect(status).toBe(200);
    expect(body.certificate_status).toBe("pending_validation");
    expect(body.certificate?.ssl_status).toBe("pending_validation");
    // The actionable part. Without it the operator is told to wait for
    // something that will never happen on its own.
    expect(body.certificate?.validation_records).toEqual([
      { name: "_acme-challenge.docs.acme.test", type: "txt", value: "dcv-token-value" },
    ]);
  });

  it("ACTIVE is a DIFFERENT value from pending validation, on the same field", async () => {
    certificates({
      [HOST]: row("active", "active"),
      [OTHER]: row("pending", "pending_validation"),
    });
    await bind(A, HOST);
    await bind(A, OTHER);

    const live = await read(A, HOST);
    const waiting = await read(A, OTHER);
    expect(live.body.certificate_status).toBe("active");
    expect(waiting.body.certificate_status).toBe("pending_validation");
    // The assertion a boolean would make impossible: one bound domain serves
    // and one does not, and the API says which.
    expect(live.body.certificate_status).not.toBe(waiting.body.certificate_status);
  });

  it("a LIVE certificate on a hostname that is not routing is neither of those", async () => {
    // TLS is fine; the tenant's CNAME does not point at the fallback origin.
    // Reported as `active` it would send the operator to Cloudflare support;
    // reported as `pending_validation` it would send them to publish a record
    // that already validated.
    certificates({ [HOST]: row("pending", "active") });
    await bind(A, HOST);

    const { body } = await read(A, HOST);
    expect(body.certificate_status).toBe("issued_not_routing");
    expect(body.certificate?.hostname_status).toBe("pending");
    expect(body.certificate?.ssl_status).toBe("active");
  });

  it("a bound hostname Cloudflare has never heard of is NOT_PROVISIONED", async () => {
    certificates({});
    await bind(A, HOST);

    const { body } = await read(A, HOST);
    expect(body.certificate_status).toBe("not_provisioned");
  });

  it("an UNREADABLE backend is `unavailable`, never `not_provisioned`", async () => {
    // "We could not look" must not read as "there is nothing there" — the second
    // tells the operator to re-provision a hostname that may already be live.
    certificates("{{{ not json");
    await bind(A, HOST);

    const { body } = await read(A, HOST);
    expect(body.certificate_status).toBe("unavailable");
    expect(body.certificate?.detail ?? "").toContain("SITE_DOMAIN_CERTIFICATE_RECORDS");
  });

  it("a deployment with NO backend says UNCONFIGURED and still returns the binding", async () => {
    // The default. `unconfigured` is not `not_provisioned`: FerroGate did not
    // look, which is a statement about this deployment and not about the domain.
    await bind(A, HOST);

    const { status, body } = await read(A, HOST);
    expect(status).toBe(200);
    expect(body.certificate_status).toBe("unconfigured");
    expect(body.certificate?.backend).toBe("unconfigured");
    expect(body.site_domain?.hostname).toBe(HOST);
  });
});

describe("the certificate is independent of the FerroGate ownership proof", () => {
  it("an ACTIVE certificate does not make an unverified binding verified", async () => {
    // Two different proofs of two different things. A live certificate says a
    // certificate authority is satisfied; it says nothing about whether this
    // tenant controls the name, which is what gates serving. Folding them into
    // one field is the bug this separation exists to prevent.
    certificates({ [HOST]: row("active", "active") });
    await bind(A, HOST);

    const { body } = await read(A, HOST);
    expect(body.certificate_status).toBe("active");
    expect(body.site_domain?.verified).not.toBe(true);
    expect(body.site_domain?.verification_status).not.toBe("verified");
  });
});

describe("the certificate lookup is fenced by tenancy", () => {
  it("tenant B cannot read tenant A's certificate state — 404, and no reading", async () => {
    certificates({ [HOST]: row("active", "active") });
    await bind(A, HOST);

    const { status, body } = await read(B, HOST);
    expect(status).toBe(404);
    // Not merely "not 200": the certificate state must be ABSENT from the body.
    // Answering 404 while still describing the hostname's certificate would
    // turn this route into a cross-tenant probe of who has provisioned what.
    expect(body.certificate_status).toBeUndefined();
    expect(body.certificate).toBeUndefined();
  });

  it("the backend is never CALLED on the 404 — the row is resolved first", async () => {
    // `src/routes/site_domain.ts` states this ordering as a security property:
    // a tenant that cannot see the binding must not make this Worker perform a
    // certificate lookup at all. An absent field in the body cannot hold that —
    // a lookup whose result is then discarded produces the identical response
    // and the identical body. Only a CALL COUNT can fail on it, so here is one.
    //
    // The spy is installed on the class the Worker itself constructs
    // (`resolveSiteDomainCertificates` under `SITE_DOMAIN_CERTIFICATES=static`),
    // and `SELF.fetch` dispatches into this isolate, so what is counted is the
    // real route's real calls and not a stand-in's.
    certificates({ [HOST]: row("active", "active") });
    await bind(A, HOST);
    const lookups = vi.spyOn(StaticSiteDomainCertificates.prototype, "certificateFor");

    try {
      const forbidden = await read(B, HOST);
      expect(forbidden.status).toBe(404);
      expect(lookups.mock.calls.map(([hostname]) => hostname)).toEqual([]);

      // And the counter is LIVE, not a spy that was never wired up: the owner's
      // own read of the same hostname goes through it exactly once. Without
      // this half, deleting the lookup entirely would leave the assertion above
      // green.
      const owner = await read(A, HOST);
      expect(owner.status).toBe(200);
      expect(owner.body.certificate_status).toBe("active");
      expect(lookups.mock.calls.map(([hostname]) => hostname)).toEqual([HOST]);
    } finally {
      lookups.mockRestore();
    }
  });
});

describe("the LIST operation is deliberately unchanged", () => {
  it("does not carry a per-row certificate — N bindings would be N outbound calls", async () => {
    certificates({ [HOST]: row("active", "active") });
    await bind(A, HOST);

    const response = await SELF.fetch(`${BASE}/admin/v1/site-domains`, {
      headers: bearer(A.key),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as CertificateBody;
    expect(body.data?.length).toBe(1);
    expect(body.data?.[0]?.certificate_status).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// The backend that answers in PRODUCTION, driven directly.
// ---------------------------------------------------------------------------

/**
 * A `HttpTransport` that never touches a network, in the shape
 * `packages/cloudflare`'s own `ScriptedTransport` uses: it records every
 * request and answers (or throws) from a supplied function. Declared here
 * rather than imported because `@ferrogate/cloudflare` exports only `./src`,
 * and reaching into another workspace's `test/` directory across a package
 * boundary is worse than eight lines.
 */
class StubTransport implements HttpTransport {
  readonly requests: HttpRequest[] = [];

  constructor(private readonly answer: (request: HttpRequest) => HttpResponse) {}

  async execute(request: HttpRequest): Promise<HttpResponse> {
    this.requests.push(request);
    return this.answer(request);
  }
}

/** No real sleeping: the client retries a GET, and the schedule is not on trial here. */
const INSTANT_CLOCK = { sleep: async (): Promise<void> => undefined };

/** A Cloudflare `success: true` envelope carrying `result`. */
function envelope(result: unknown): HttpResponse {
  return {
    status: 200,
    body: JSON.stringify({ success: true, errors: [], messages: [], result }),
  };
}

/** The LIVE backend over a scripted transport — a real client, no network. */
function liveBackend(transport: StubTransport): CloudflareForSaasCertificates {
  return new CloudflareForSaasCertificates(
    new CustomHostnamesClient(
      new CloudflareClient({
        config: { accountId: "acct_placeholder", tokenReference: "inline-placeholder-token" },
        resolver: new EnvTokenResolver({}),
        transport,
        clock: INSTANT_CLOCK,
      }),
      "zoneplaceholder0000000000000000",
    ),
  );
}

describe("CloudflareForSaasCertificates — the backend that answers in production", () => {
  it("names itself, so a reading is traceable to the backend that produced it", async () => {
    const backend = liveBackend(new StubTransport(() => envelope([])));
    expect(backend.backendName).toBe("cloudflare_for_saas");
    expect((await backend.certificateFor(HOST)).backend).toBe("cloudflare_for_saas");
  });

  it("a lookup that FAILS is `unavailable`, never `not_provisioned`", async () => {
    // The distinction this class's docblock argues is load-bearing, asserted on
    // the class itself. `not_provisioned` tells an operator to provision a
    // hostname that may already be live and serving; an expired token or a
    // Cloudflare 5xx must never produce that sentence.
    const transport = new StubTransport(() => {
      throw new Error("connect ECONNREFUSED api.cloudflare.com");
    });

    const reading = await liveBackend(transport).certificateFor(HOST);
    expect(reading.status).toBe("unavailable");
    expect(reading.status).not.toBe("not_provisioned");
    // The operator is told WHY, not merely that something went wrong.
    expect(reading.detail ?? "").toContain("ECONNREFUSED");
    expect(transport.requests.length).toBeGreaterThan(0);
  });

  it("a 5xx from Cloudflare is `unavailable` too, not an absent certificate", async () => {
    const transport = new StubTransport(() => ({
      status: 503,
      body: JSON.stringify({ success: false, errors: [{ code: 1000, message: "boom" }] }),
    }));

    const reading = await liveBackend(transport).certificateFor(HOST);
    expect(reading.status).toBe("unavailable");
    expect(reading.status).not.toBe("not_provisioned");
  });

  it("a zone with NO row for the hostname is `not_provisioned`", async () => {
    // The other side of the same distinction: Cloudflare answered, and the
    // answer is that nothing is there. That IS actionable — provision it.
    const transport = new StubTransport(() => envelope([]));

    const reading = await liveBackend(transport).certificateFor(HOST);
    expect(reading.status).toBe("not_provisioned");
    expect(reading.status).not.toBe("unavailable");
    expect(reading.detail ?? "").toContain(HOST);
    // One GET, on the zone's custom-hostname collection, filtered by hostname.
    expect(transport.requests.length).toBe(1);
    expect(transport.requests[0]?.method).toBe("GET");
    expect(transport.requests[0]?.url).toContain(
      "/zones/zoneplaceholder0000000000000000/custom_hostnames",
    );
    expect(transport.requests[0]?.url).toContain(`hostname=${HOST}`);
  });

  it("a row Cloudflare returns is folded — and `active` survives the round trip", async () => {
    const transport = new StubTransport(() =>
      envelope([{ id: "ch-1", hostname: HOST, status: "active", ssl: { status: "active" } }]),
    );

    const reading = await liveBackend(transport).certificateFor(HOST);
    expect(reading.status).toBe("active");
    expect(reading.hostnameStatus).toBe("active");
    expect(reading.sslStatus).toBe("active");
  });

  it("a PARTIAL-match row is not this hostname's certificate", async () => {
    // Cloudflare's `?hostname=` filter is a CONTAINS match. Reporting the first
    // row of a filtered page would attribute `docs.acme.test.attacker.test`'s
    // certificate to `docs.acme.test` — a live `active` for a name we hold no
    // proof over. The absence must read as `not_provisioned`, not as `active`.
    const transport = new StubTransport(() =>
      envelope([
        {
          id: "ch-9",
          hostname: `${HOST}.attacker.test`,
          status: "active",
          ssl: { status: "active" },
        },
      ]),
    );

    const reading = await liveBackend(transport).certificateFor(HOST);
    expect(reading.status).toBe("not_provisioned");
    expect(reading.status).not.toBe("active");
  });
});
