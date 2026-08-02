/**
 * Billing microservice HTTP boundary — clean-room port of
 * `ferrogate-billing`'s `service.rs`.
 *
 * PORT-TODO(L: §2.4 / §2.5) — PLATFORM LIMIT, NOT CLOSED (routes/auth/errors ARE).
 *
 * The exact limitation: **a Worker cannot bind a listening socket.** The Rust
 * service is a hand-rolled blocking HTTP/1.1 server — `TcpListener::bind`,
 * thread-per-connection, its own slowloris and load-shed guards. workerd has no
 * `listen()`: `cloudflare:sockets`' `connect()` is OUTBOUND only, there is no
 * thread to dedicate to a connection, and the request lifecycle starts at a
 * `fetch` handler the runtime calls. So `serve(listen, ...)` and its
 * accept-loop guards have no equivalent and are deliberately NOT ported —
 * a fake `serve()` that ignored its bind address would be worse than its
 * absence.
 *
 * Per the inventory CF/TS mapping (§2.5) that transport is DROPPED on purpose,
 * not merely blocked: on Workers, connection limits, read timeouts and load
 * shedding are the PLATFORM's job, and reimplementing them in the isolate would
 * duplicate them badly.
 *
 * What IS fully ported: every route, the constant-time bearer auth, the
 * pagination/filter semantics, the 1 MiB body cap (the ONE accept-loop guard
 * that survives, because it is enforceable inside the isolate), and the
 * error→status taxonomy — exposed as a framework-agnostic **Web Fetch handler**
 * ({@link createBillingService}) ready to mount as a Hono route group.
 * `test/service.test.ts` drives it end to end and
 * `test/platform-limits.test.ts` pins the approximation.
 *
 * Ported WITH one deliberate widening: {@link LedgerSink}'s methods are
 * `MaybePromise`-valued and this handler AWAITS them. The Rust trait is
 * synchronous, which is free there (a blocking DB call on a thread that may
 * block) and unimplementable here — on Workers every durable store is
 * promise-returning, so a synchronous seam would admit no sink but the
 * in-memory one. See the {@link LedgerSink} doc for the failure a fire-and-
 * forget `record` would produce (a 200 shipped before the write settles, and a
 * `billing_idempotency_conflict` that never reaches the client as 409).
 *
 * Routes (unchanged semantics):
 *  - `GET  /healthz` | `/v1/healthz`   — open readiness probe.
 *  - `POST /v1/billing/charge`         — price + record → {@link LedgerEntry}.
 *  - `GET  /v1/billing/ledger`         — paginated, tenant-filtered (#136/#149).
 *  - `GET  /v1/billing/ledger/{id}`    — single entry by idempotency id.
 */
import {
  charge,
  ledgerEntryToWire,
  ledgerTotals,
  type LedgerEntry,
  type LedgerListFilter,
  type LedgerSink,
} from "./ledger.js";
import { BillingError, parseBillingEvent, type BillingEvent } from "./event.js";
import { PriceBook } from "./pricing.js";

/** Max accepted request body (1 MiB), mirrors `MAX_REQUEST_BYTES`. */
export const MAX_REQUEST_BYTES = 1024 * 1024;
const DEFAULT_LEDGER_PAGE_LIMIT = 100;
const MAX_LEDGER_PAGE_LIMIT = 1000;

/** Runtime configuration for {@link createBillingService}. */
export interface BillingServiceConfig {
  price_book: PriceBook;
  sink: LedgerSink;
  /** Optional shared secret (issue #136); when set, all non-health routes require it. */
  token?: string;
}

/**
 * Stable HTTP classification for billing-domain failures (port of
 * `billing_error_http_status`).
 */
export function billingErrorHttpStatus(error: BillingError): number {
  switch (error.code) {
    case "price_not_found":
      return 422;
    case "billing_idempotency_conflict":
      return 409;
    default:
      return 500;
  }
}

/** Constant-time byte comparison (port of `constant_time_eq`). */
export function constantTimeEq(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i += 1) {
    diff |= (left[i] as number) ^ (right[i] as number);
  }
  return diff === 0;
}

const UTF8 = new TextEncoder();

/** Constant-time check that the request presents `Authorization: Bearer <expected>`. */
function requestIsAuthorized(header: string | null, expected: string): boolean {
  if (header === null) return false;
  let presented: string;
  if (header.startsWith("Bearer ")) {
    presented = header.slice("Bearer ".length);
  } else if (header.startsWith("bearer ")) {
    presented = header.slice("bearer ".length);
  } else {
    presented = "";
  }
  presented = presented.trim();
  return constantTimeEq(UTF8.encode(presented), UTF8.encode(expected));
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", connection: "close" },
  });
}

function billingErrorResponse(error: BillingError): Response {
  return json(billingErrorHttpStatus(error), {
    error: { code: error.code, message: error.message },
  });
}

function badRequest(message: string): Response {
  return json(400, { error: { code: "invalid_json", message } });
}

function tenantFilterFromParams(params: URLSearchParams): LedgerListFilter {
  const filter: LedgerListFilter = {};
  const org = params.get("organization_id");
  const project = params.get("project_id");
  const apiKey = params.get("api_key_id");
  if (org !== null) filter.organization_id = org;
  if (project !== null) filter.project_id = project;
  if (apiKey !== null) filter.api_key_id = apiKey;
  return filter;
}

function parseUsizeParam(params: URLSearchParams, key: string): number | undefined {
  const raw = params.get(key);
  if (raw === null) return undefined;
  if (!/^\d+$/.test(raw)) return undefined;
  const value = Number.parseInt(raw, 10);
  return Number.isSafeInteger(value) ? value : undefined;
}

function clamp(value: number, lo: number, hi: number): number {
  return Math.min(Math.max(value, lo), hi);
}

/**
 * Price a usage event and persist the resulting ledger entry (port of
 * `BillingService::charge_and_record`). Throws {@link BillingError}.
 */
export async function chargeAndRecord(
  config: BillingServiceConfig,
  event: BillingEvent,
): Promise<LedgerEntry> {
  const entry = charge(config.price_book, event);
  // AWAITED, not fire-and-forget: on Workers every durable sink is
  // promise-valued, and an unawaited `record` would let the 200 ship before the
  // write settled — turning a `billing_idempotency_conflict` (409) into an
  // unhandled rejection the caller never sees.
  await config.sink.record(entry);
  return entry;
}

/**
 * Build the billing service's Web Fetch handler. The returned function is a
 * `(request: Request) => Promise<Response>` that can be mounted directly or
 * wrapped by Hono.
 *
 * ## DECISION RECORDED (inventory-data-billing §2.4/§2.5) — option (b), NOT a
 * ## PORT-TODO
 *
 * The audit asked whether these four routes should be mounted on a Worker or
 * declared out of the Cloudflare topology. **Declared out of it**, for three
 * reasons that are each independently checkable:
 *
 *  1. The committed 259-operation route contract
 *     (`docs/openapi/runtime-api-contract.json`) carries NO `/v1/billing/*`
 *     operation. Mounting these would mean ADDING operations to the contract —
 *     a product change, not a port.
 *  2. The gateway does not settle over HTTP on this platform. It calls
 *     {@link charge} directly (`apps/gateway/src/metering/*`) and drains
 *     `billing_report_outbox`; both are mounted and tested. An intra-account
 *     HTTP hop to a second Worker would add a failure mode and a network
 *     round-trip to the money path and buy nothing.
 *  3. In Rust this is a SEPARATE PROCESS (`ferrogate-billing serve`, its own
 *     `TcpListener`), deliberately deployable away from the data plane. The
 *     Cloudflare equivalent of "a separate process" is a separate Worker with
 *     its own account resources, which is a deployment decision an operator
 *     makes, not something this port should presume.
 *
 * So this stays a PORTABLE Fetch handler — complete, tested, and directly
 * mountable by a self-hosted or standalone deployment — and it is mounted on no
 * Worker in this repo. That is a decision, not a defect, and it differs from
 * `@ferrogate/policy`'s `BasicPolicyEngine` / `preflightWorkflowBudget` markers,
 * which describe guarantees an operator BELIEVES are in force and are not.
 *
 * The half that could have become a silent lie is `[billing_service] endpoint /
 * token / token_env`: an operator pointing that at a real host would otherwise
 * get a clean load and no traffic. `@ferrogate/config`'s
 * `inertBillingServiceWarnings` now reports it as INERT through
 * `loadConfigFromObject`, exactly the way `[tls]`/`[tls.acme]` announce
 * themselves, and `packages/config/test/platform-limits.test.ts` asserts that
 * warning through the LOADER so an implemented-but-unmounted warning fails.
 * `billing_service.enabled` itself is NOT inert — it still gates the issue-#146
 * refusal that every model and fallback route carries a price.
 */
export function createBillingService(
  config: BillingServiceConfig,
): (request: Request) => Promise<Response> {
  return async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    const method = request.method.toUpperCase();
    const path = url.pathname;

    const isHealth =
      method === "GET" && (path === "/healthz" || path === "/v1/healthz");

    // Every route except the readiness probe requires the shared secret when
    // one is configured (issue #136).
    if (!isHealth && config.token !== undefined) {
      const authorized = requestIsAuthorized(
        request.headers.get("authorization"),
        config.token,
      );
      if (!authorized) {
        return json(401, {
          error: { code: "unauthorized", message: "missing or invalid bearer token" },
        });
      }
    }

    if (isHealth) {
      return json(200, { service: "ferrogate-billing", status: "ok" });
    }

    if (method === "POST" && path === "/v1/billing/charge") {
      const raw = await request.text();
      if (UTF8.encode(raw).length > MAX_REQUEST_BYTES) {
        return json(413, {
          error: {
            code: "payload_too_large",
            message: `request exceeds ${MAX_REQUEST_BYTES} bytes`,
          },
        });
      }
      let event: BillingEvent;
      try {
        event = parseBillingEvent(JSON.parse(raw));
      } catch (error) {
        return badRequest(error instanceof Error ? error.message : String(error));
      }
      try {
        const entry = await chargeAndRecord(config, event);
        return json(200, ledgerEntryToWire(entry));
      } catch (error) {
        if (error instanceof BillingError) return billingErrorResponse(error);
        throw error;
      }
    }

    if (method === "GET" && path === "/v1/billing/ledger") {
      const offset = parseUsizeParam(url.searchParams, "offset") ?? 0;
      const limit = clamp(
        parseUsizeParam(url.searchParams, "limit") ?? DEFAULT_LEDGER_PAGE_LIMIT,
        1,
        MAX_LEDGER_PAGE_LIMIT,
      );
      const filter = tenantFilterFromParams(url.searchParams);
      try {
        const entries = await config.sink.list(filter, offset, limit);
        return json(200, {
          entries: entries.map(ledgerEntryToWire),
          page_totals: ledgerTotals(entries),
        });
      } catch (error) {
        if (error instanceof BillingError) return billingErrorResponse(error);
        throw error;
      }
    }

    if (method === "GET" && path.startsWith("/v1/billing/ledger/")) {
      const id = path.slice("/v1/billing/ledger/".length);
      try {
        const entry = await config.sink.get(id);
        if (entry) return json(200, ledgerEntryToWire(entry));
        return json(404, {
          error: {
            code: "ledger_entry_not_found",
            message: "no ledger entry with that id",
          },
        });
      } catch (error) {
        if (error instanceof BillingError) return billingErrorResponse(error);
        throw error;
      }
    }

    return json(404, {
      error: { code: "not_found", message: "billing service endpoint not found" },
    });
  };
}
