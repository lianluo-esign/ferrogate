import { HttpResponse, http } from "msw";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  adminDelete,
  adminGet,
  adminPost,
  adminPut,
  PresignedUploadRejectedError,
  putPresignedObject,
} from "@/lib/gateway-client";
import { ApiError } from "@/types/auth";
import { gatewayUrl, mockAdminError, server } from "@/test/msw";

const API_KEY = "fg-test-key";

describe("typed OpenAPI client (adminGet/adminPost/...)", () => {
  it("adminGet returns the contract-typed list body", async () => {
    server.use(
      http.get(gatewayUrl("/admin/v1/plans"), () =>
        HttpResponse.json({
          object: "list",
          data: [
            {
              id: "p1",
              name: "Free",
              slug: "free",
              mcp_enabled: false,
              self_hosted_workers_enabled: false,
              default_model_allowlist: [],
              asset_hosting_enabled: false,
              extension_tools_enabled: false,
              created_at_unix: 1,
              updated_at_unix: 1,
            },
          ],
        }),
      ),
    );

    const page = await adminGet(API_KEY, "/admin/v1/plans");
    // `page` is typed from the generated contract: `.data[].slug` compiles,
    // a typo like `.data[0].slugg` would be a build error.
    expect(page.object).toBe("list");
    expect(page.data[0].slug).toBe("free");
  });

  it("adminPut substitutes {path} params from the contract template", async () => {
    let hitPath: string | null = null;
    let body: unknown = null;
    server.use(
      http.put(gatewayUrl("/admin/v1/plans/:planId"), async ({ request }) => {
        hitPath = new URL(request.url).pathname;
        body = await request.json();
        return HttpResponse.json({
          object: "plan",
          plan: {
            id: "plan-1",
            name: "Pro",
            slug: "pro",
            mcp_enabled: true,
            self_hosted_workers_enabled: false,
            default_model_allowlist: [],
            asset_hosting_enabled: false,
            extension_tools_enabled: false,
            created_at_unix: 1,
            updated_at_unix: 2,
          },
        });
      }),
    );

    const response = await adminPut(
      API_KEY,
      "/admin/v1/plans/{plan_id}",
      { name: "Pro" },
      { params: { plan_id: "plan-1" } },
    );

    expect(hitPath).toBe("/admin/v1/plans/plan-1");
    expect(body).toEqual({ name: "Pro" });
    expect(response.plan.name).toBe("Pro");
  });

  it("adminPost sends the typed request body and returns the mutation response", async () => {
    let body: unknown = null;
    server.use(
      http.post(gatewayUrl("/admin/v1/tenant-accounts"), async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({
          object: "tenant_account",
          tenant: {
            id: "t1",
            name: "Acme",
            slug: "acme",
            status: "active",
            plan_id: "free",
            created_at_unix: 1,
            updated_at_unix: 1,
          },
        });
      }),
    );

    const response = await adminPost(API_KEY, "/admin/v1/tenant-accounts", {
      name: "Acme",
      slug: "acme",
    });

    expect(body).toEqual({ name: "Acme", slug: "acme" });
    expect(response.tenant.id).toBe("t1");
  });

  it("adminDelete substitutes {key_id} and returns the delete acknowledgement", async () => {
    let hitPath: string | null = null;
    server.use(
      http.delete(gatewayUrl("/admin/v1/virtual-keys/:keyId"), ({ request }) => {
        hitPath = new URL(request.url).pathname;
        return HttpResponse.json({ object: "virtual_api_key.deleted", id: "vk-1" });
      }),
    );

    await expect(
      adminDelete(API_KEY, "/admin/v1/virtual-keys/{key_id}", {
        params: { key_id: "vk-1" },
      }),
    ).resolves.toEqual({ object: "virtual_api_key.deleted", id: "vk-1" });
    expect(hitPath).toBe("/admin/v1/virtual-keys/vk-1");
  });

  it("throws the typed ApiError with code/status from the error envelope", async () => {
    mockAdminError("get", "/admin/v1/plans", 429, "rate_limited", "slow down");

    const error = await adminGet(API_KEY, "/admin/v1/plans").catch((e) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 429, code: "rate_limited", message: "slow down" });
  });
});

/**
 * #368: the direct-to-bucket PUT is authorized by a SigV4 signature that binds
 * `content-length` and `x-amz-content-sha256` as SignedHeaders. Forwarding them
 * is not cosmetic — omit or alter one and every real S3-compatible bucket
 * answers 403.
 *
 * These drive `putPresignedObject` directly against a stubbed `fetch` instead
 * of through the page, because the page-level assertion on this behavior lives
 * inside a test that is red on the unrelated `object.stream` jsdom/msw issue
 * (#510) and therefore never executes. Delete the `requiredHeaders` loop and
 * these fail.
 */
describe("putPresignedObject (#368 bound direct upload)", () => {
  const UPLOAD_URL = "https://bucket.example.test/staging/obj_1?X-Amz-Signature=abc";
  const SIGNED_SHA = "a".repeat(64);

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function stubFetch(response: Response): ReturnType<typeof vi.fn> {
    const fetchMock = vi.fn(async () => response);
    vi.stubGlobal("fetch", fetchMock);
    return fetchMock;
  }

  it("forwards the signed payload hash verbatim and never sets content-length", async () => {
    const fetchMock = stubFetch(new Response(null, { status: 200 }));
    const body = new Blob(["0123456789"]);

    await putPresignedObject(UPLOAD_URL, body, "application/gzip", {
      "content-length": String(body.size),
      "x-amz-content-sha256": SIGNED_SHA,
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(UPLOAD_URL);
    expect(init.method).toBe("PUT");
    const headers = init.headers as Record<string, string>;
    // The signed VALUE, not merely the header's presence: the signature binds
    // the digest, so a constant or stale hash is a 403.
    expect(headers["x-amz-content-sha256"]).toBe(SIGNED_SHA);
    expect(headers["Content-Type"]).toBe("application/gzip");
    // Fetch forbids a page setting content-length; the browser derives the
    // signed value from the body instead.
    expect(Object.keys(headers).map((name) => name.toLowerCase())).not.toContain(
      "content-length",
    );
  });

  it("refuses to PUT bytes whose length differs from the signed content-length", async () => {
    const fetchMock = stubFetch(new Response(null, { status: 200 }));
    const body = new Blob(["0123456789"]);

    await expect(
      putPresignedObject(UPLOAD_URL, body, "application/gzip", {
        "content-length": String(body.size + 1),
        "x-amz-content-sha256": SIGNED_SHA,
      }),
    ).rejects.toThrow(/signed for 11 bytes/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("distinguishes a bucket refusal from a local one so abort cannot over-claim", async () => {
    stubFetch(
      new Response("<Error><Code>SignatureDoesNotMatch</Code></Error>", {
        status: 403,
        statusText: "Forbidden",
      }),
    );
    const body = new Blob(["0123456789"]);

    const rejected = await putPresignedObject(UPLOAD_URL, body, "application/gzip", {
      "x-amz-content-sha256": SIGNED_SHA,
    }).catch((error: unknown) => error);

    // Only THIS error type justifies reporting `reason: "bucket_rejected"` to
    // the abort endpoint — that class is caller-asserted, and the local
    // length refusal above must never be able to mint one.
    expect(rejected).toBeInstanceOf(PresignedUploadRejectedError);
    expect(rejected).toMatchObject({ status: 403 });
    expect((rejected as Error).message).toContain("SignatureDoesNotMatch");

    const localRefusal = await putPresignedObject(UPLOAD_URL, body, "application/gzip", {
      "content-length": String(body.size + 1),
      "x-amz-content-sha256": SIGNED_SHA,
    }).catch((error: unknown) => error);
    expect(localRefusal).not.toBeInstanceOf(PresignedUploadRejectedError);
  });

  /**
   * #344: the direct bucket PUT carries the whole object, so it is the leg an
   * operator most needs to be able to cancel. Asserted here rather than through
   * the page because the page-level presigned tests that reach a real PUT are
   * red on the unrelated `object.stream` jsdom/msw issue (#510).
   */
  it("forwards an AbortSignal to the bucket PUT so a cancel stops the transfer", async () => {
    const fetchMock = stubFetch(new Response(null, { status: 200 }));
    const controller = new AbortController();
    const body = new Blob(["0123456789"]);

    await putPresignedObject(
      UPLOAD_URL,
      body,
      "application/gzip",
      { "x-amz-content-sha256": SIGNED_SHA },
      controller.signal,
    );

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    // Drop the `signal` pass-through and Cancel can only ever stop the short
    // JSON legs around a multi-gigabyte upload that keeps running.
    expect(init.signal).toBe(controller.signal);
  });

  it("rejects with an AbortError once the signal is aborted mid-PUT", async () => {
    const controller = new AbortController();
    // A fetch double that honours the signal the way the platform does.
    vi.stubGlobal(
      "fetch",
      vi.fn(
        (_url: string, init: RequestInit) =>
          new Promise<Response>((_resolve, reject) => {
            init.signal?.addEventListener("abort", () => {
              const error = new Error("The operation was aborted.");
              error.name = "AbortError";
              reject(error);
            });
          }),
      ),
    );
    const pending = putPresignedObject(
      UPLOAD_URL,
      new Blob(["0123456789"]),
      "application/gzip",
      { "x-amz-content-sha256": SIGNED_SHA },
      controller.signal,
    );
    controller.abort();

    const rejected = await pending.catch((error: unknown) => error);
    expect((rejected as Error).name).toBe("AbortError");
    // A cancel is not a bucket refusal: reporting it as one would mint a
    // fabricated `bucket_rejected` abort in the gateway's audit trail.
    expect(rejected).not.toBeInstanceOf(PresignedUploadRejectedError);
  });
});
