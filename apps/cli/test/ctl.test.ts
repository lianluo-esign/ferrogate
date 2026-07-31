import { describe, expect, test } from "vitest";
import type { ContextStore } from "../src/context.js";
import { main } from "../src/index.js";
import { createTestRuntime, ok } from "./helpers.js";

const STORE: ContextStore = {
  contexts: [
    {
      name: "prod",
      endpoint: "https://cp.example",
      tlsInsecureSkipVerify: false,
      auth: { kind: "env", var: "TOK" },
    },
  ],
  current: "prod",
};

const ENV = { TOK: "bearer-value" };

describe("ctl dispatch end to end", () => {
  test("a read renders the body on stdout and correlation ids on stderr", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: {
        "GET /admin/v1/projects": {
          status: 200,
          body: { data: [{ id: "p1", name: "one" }], total: 1 },
          requestId: "req-1",
          traceId: "trace-1",
        },
      },
    });
    expect(await main(["ctl", "projects", "list"], runtime)).toBe(0);
    expect(runtime.stdout()).toContain("ID");
    expect(runtime.stdout()).toContain("p1");
    expect(runtime.stderr()).toContain("request-id: req-1");
    expect(runtime.stderr()).toContain("trace-id: trace-1");
  });

  test("--output json emits the raw document", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: { "GET /admin/v1/projects": ok({ data: [{ id: "p1" }], total: 1 }) },
    });
    expect(await main(["ctl", "projects", "list", "--output", "json"], runtime)).toBe(0);
    expect(JSON.parse(runtime.stdout())).toEqual({ data: [{ id: "p1" }], total: 1 });
  });

  test("the resolved credential rides the Authorization header", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: { "GET /admin/v1/projects": ok({ data: [] }) },
    });
    await main(["ctl", "projects", "list"], runtime);
    expect(runtime.client.requests[0]?.context.token).toBe("bearer-value");
  });

  test("a missing credential env var is an auth error (exit 3)", async () => {
    const runtime = createTestRuntime({ store: STORE, env: {} });
    expect(await main(["ctl", "projects", "list"], runtime)).toBe(3);
    expect(runtime.stderr()).toContain("TOK is not set");
  });

  test("an unknown group exits 2 and lists the groups", async () => {
    const runtime = createTestRuntime();
    expect(await main(["ctl", "nope", "list"], runtime)).toBe(2);
    expect(runtime.stderr()).toContain("unknown resource group 'nope'");
  });

  test("`ctl` alone exits 2 with the group list", async () => {
    const runtime = createTestRuntime();
    expect(await main(["ctl"], runtime)).toBe(2);
    expect(runtime.stderr()).toContain("guardrail-policies");
  });

  test("`ctl <group>` alone exits 2 with the verb list", async () => {
    const runtime = createTestRuntime();
    expect(await main(["ctl", "wallets"], runtime)).toBe(2);
    expect(runtime.stderr()).toContain("needs --yes");
  });

  test("`ctl <group> --help` exits 0", async () => {
    const runtime = createTestRuntime();
    expect(await main(["ctl", "wallets", "--help"], runtime)).toBe(0);
    expect(runtime.stdout()).toContain("verbs:");
  });

  test("a server error maps onto its exit class", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: { "GET /admin/v1/projects": { status: 503 } },
    });
    expect(await main(["ctl", "projects", "list"], runtime)).toBe(7);
  });

  test("a 404 maps to the not-found class", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: { "GET /admin/v1/projects/ghost": { status: 404 } },
    });
    expect(await main(["ctl", "projects", "get", "ghost"], runtime)).toBe(4);
  });
});

describe("the mutation receipt render gate", () => {
  test("a mutating verb emits a receipt, never the server's document", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: {
        "POST /admin/v1/projects": {
          status: 201,
          body: { id: "p9", name: "new", server_only_field: "SHOULD-NOT-BE-THE-OUTPUT" },
          requestId: "req-9",
        },
      },
    });
    expect(
      await main(
        ["ctl", "projects", "create", "--data", '{"name":"new"}', "--output", "json"],
        runtime,
      ),
    ).toBe(0);
    const receipt = JSON.parse(runtime.stdout());
    expect(receipt.object).toBe("mutation_receipt");
    expect(receipt.receipt_version).toBe(1);
    expect(receipt.outcome).toBe("applied");
    expect(receipt.group).toBe("projects");
    expect(receipt.verb).toBe("create");
    expect(receipt.operation_id.value).toBe("createProject");
    expect(receipt.http_status.value).toBe(201);
    expect(receipt.correlation.request_id.value).toBe("req-9");
  });

  test("every optional receipt field is attested (value XOR absent_reason)", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: { "POST /admin/v1/projects": ok({ id: "p9" }) },
    });
    await main(["ctl", "projects", "create", "--data", "{}", "--output", "json"], runtime);
    const receipt = JSON.parse(runtime.stdout());
    for (const field of [
      receipt.operation_id,
      receipt.audit_id,
      receipt.approval_id,
      receipt.rollback,
      receipt.decision,
      receipt.idempotency_key,
      receipt.actor.subject,
      receipt.actor.tenant,
      receipt.target.object_version,
    ]) {
      expect((field.value !== null) !== (field.absent_reason !== null)).toBe(true);
    }
    expect(receipt.audit_id.absent_reason.code).toBe("endpoint_returns_no_audit_id");
  });

  test("the action fingerprint is a canonical sha256 of the target", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: { "POST /admin/v1/projects": ok({ id: "p9" }) },
    });
    await main(["ctl", "projects", "create", "--data", "{}", "--output", "json"], runtime);
    const receipt = JSON.parse(runtime.stdout());
    expect(receipt.target.action_fingerprint).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(receipt.target.action_fingerprint_contract).toBe("canonical_target_sha256");
    // The CLIENT fingerprint is not a digest, and must not look like one.
    expect(receipt.client_identity.client_fingerprint).toMatch(/^v1;/);
    expect(receipt.client_identity.client_fingerprint).not.toMatch(/^sha256:/);
  });

  test("--dry-run builds a receipt without opening a socket", async () => {
    const runtime = createTestRuntime({ store: STORE, env: ENV });
    expect(
      await main(["ctl", "projects", "delete", "p1", "--dry-run", "--output", "json"], runtime),
    ).toBe(0);
    const receipt = JSON.parse(runtime.stdout());
    expect(receipt.dry_run).toBe(true);
    expect(receipt.outcome).toBe("not_sent");
    expect(receipt.http_status.absent_reason.code).toBe("request_not_sent");
    expect(runtime.client.requests).toHaveLength(0);
  });

  test("--dry-run on a read verb refuses (nothing to plan)", async () => {
    const runtime = createTestRuntime({ store: STORE, env: ENV });
    expect(await main(["ctl", "projects", "list", "--dry-run"], runtime)).toBe(2);
    expect(runtime.stderr()).toContain("--dry-run applies to mutating verbs");
  });

  test("--all-pages on a mutating verb refuses", async () => {
    const runtime = createTestRuntime({ store: STORE, env: ENV });
    expect(await main(["ctl", "projects", "create", "--data", "{}", "--all-pages"], runtime)).toBe(
      2,
    );
    expect(runtime.stderr()).toContain("--all-pages is a list-walking flag");
  });

  test("a rejected mutation still emits a receipt AND the failing exit code", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: { "DELETE /admin/v1/projects/p1": { status: 409 } },
    });
    expect(await main(["ctl", "projects", "delete", "p1", "--output", "json"], runtime)).toBe(4);
    const receipt = JSON.parse(runtime.stdout());
    expect(receipt.outcome).toBe("rejected");
    expect(receipt.failure.value.code).toBe("scripted_error");
    expect(receipt.http_status.value).toBe(409);
  });

  test("a guardrail rollback pointer is derived only from server evidence", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: {
        "POST /admin/v1/guardrail-policies/g1/activate": ok({
          policy_id: "g1",
          active_revision: 5,
          previous_active_revision: 4,
        }),
      },
    });
    await main(
      ["ctl", "guardrail-policies", "activate", "g1", "--data", "{}", "--output", "json"],
      runtime,
    );
    const receipt = JSON.parse(runtime.stdout());
    expect(receipt.rollback.value.command).toContain("rollback");
    expect(receipt.rollback.value.restores_revision.value).toBe("4");
  });

  test("a non-revisioned family reports no rollback rather than a wrong one", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: { "PATCH /admin/v1/gateway-configs/prod": ok({ id: "prod", revision: 4 }) },
    });
    await main(
      ["ctl", "gateway-configs", "update", "prod", "--data", "{}", "--output", "json"],
      runtime,
    );
    const receipt = JSON.parse(runtime.stdout());
    expect(receipt.rollback.value).toBeNull();
    expect(receipt.rollback.absent_reason.code).toBe("resource_has_no_revisions");
  });
});

describe("confirmation gate", () => {
  test("a guarded verb refuses without --yes when non-interactive", async () => {
    const runtime = createTestRuntime({ store: STORE, env: ENV });
    expect(
      await main(["ctl", "wallets", "adjust", "w1", "--data", "{}", "--non-interactive"], runtime),
    ).toBe(2);
    expect(runtime.stderr()).toContain("rerun with --yes");
    expect(runtime.client.requests).toHaveLength(0);
  });

  test("a guarded verb refuses when stdin is not a terminal", async () => {
    const runtime = createTestRuntime({ store: STORE, env: ENV, isTty: false });
    expect(await main(["ctl", "wallets", "adjust", "w1", "--data", "{}"], runtime)).toBe(2);
    expect(runtime.stderr()).toContain("stdin is not a terminal");
  });

  test("--yes lets a guarded verb through", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: { "POST /admin/v1/wallets/w1/adjust": ok({ id: "w1" }) },
    });
    expect(
      await main(["ctl", "wallets", "adjust", "w1", "--data", '{"credits":5}', "--yes"], runtime),
    ).toBe(0);
    expect(runtime.client.requests).toHaveLength(1);
  });

  test("--dry-run needs no confirmation and sends nothing", async () => {
    const runtime = createTestRuntime({ store: STORE, env: ENV });
    expect(
      await main(["ctl", "wallets", "adjust", "w1", "--data", "{}", "--dry-run"], runtime),
    ).toBe(0);
    expect(runtime.client.requests).toHaveLength(0);
  });

  test("an unguarded mutation needs no confirmation", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: { "DELETE /admin/v1/projects/p1": ok({ id: "p1" }) },
    });
    expect(await main(["ctl", "projects", "delete", "p1"], runtime)).toBe(0);
  });
});

describe("action identity", () => {
  test("one action id is minted per invocation and shared by every page", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: { "GET /admin/v1/projects": ok({ data: [{ id: "p1" }], total: 1 }) },
    });
    await main(["ctl", "projects", "list", "--all-pages"], runtime);
    const ids = runtime.client.requests.map(
      (recorded) => recorded.context.headers["x-ferrogate-action-id"],
    );
    expect(ids.length).toBeGreaterThan(0);
    expect(new Set(ids).size).toBe(1);
    expect(ids[0]).toMatch(/^fgact_[0-9a-f]{32}$/);
  });

  test("the fingerprint describes the client and never the token", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: { ...ENV, FERROGATE_CLIENT_HOST_LABEL: "laptop-7" },
      script: { "GET /admin/v1/projects": ok({ data: [] }) },
    });
    await main(["ctl", "projects", "list"], runtime);
    const headers = runtime.client.requests[0]?.context.headers ?? {};
    const fingerprint = headers["x-ferrogate-client-fingerprint"] ?? "";
    expect(fingerprint).toContain("cred=env:TOK");
    expect(fingerprint).toContain("host=laptop-7");
    expect(fingerprint).not.toContain("bearer-value");
  });

  test("a disclosed client IP rides its own header, not the fingerprint blob", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: { ...ENV, FERROGATE_CLIENT_REPORTED_IP: "203.0.113.9" },
      script: { "GET /admin/v1/projects": ok({ data: [] }) },
    });
    await main(["ctl", "projects", "list"], runtime);
    const headers = runtime.client.requests[0]?.context.headers ?? {};
    expect(headers["x-ferrogate-client-reported-ip"]).toBe("203.0.113.9");
    expect(headers["x-ferrogate-client-fingerprint"]).not.toContain("203.0.113.9");
  });
});

describe("pagination honesty", () => {
  test("--offset on a cursor endpoint REFUSES rather than returning page one", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: {
        "GET /admin/v1/payment-attempts": ok({
          data: [{ id: "pa1" }],
          has_more: true,
          next_cursor: "cur-2",
        }),
      },
    });
    expect(await main(["ctl", "payment-attempts", "list", "--offset", "10"], runtime)).toBe(2);
    expect(runtime.stderr()).toContain("it is cursor-paginated");
    expect(runtime.stderr()).toContain("next_cursor=cur-2");
  });

  test("a truncated offset page says how many rows remain", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: { "GET /admin/v1/projects": ok({ data: [{ id: "p1" }], total: 9, limit: 1 }) },
    });
    await main(["ctl", "projects", "list", "--limit", "1"], runtime);
    expect(runtime.stderr()).toContain("showing 1 of 9 rows");
  });

  test("a cursor page reports the real continuation and never invents one", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: {
        "GET /admin/v1/payment-attempts": ok({ data: [{ id: "pa1" }], next_cursor: "cur-2" }),
      },
    });
    await main(["ctl", "payment-attempts", "list"], runtime);
    expect(runtime.stderr()).toContain("next_cursor=cur-2");
  });

  test("an exhausted cursor page emits no continuation notice", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: {
        "GET /admin/v1/payment-attempts": ok({
          data: [{ id: "pa1" }],
          has_more: false,
          next_cursor: null,
        }),
      },
    });
    await main(["ctl", "payment-attempts", "list"], runtime);
    expect(runtime.stderr()).not.toContain("more rows exist");
  });

  test("--all-pages refuses to walk a cursor endpoint", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: {
        "GET /admin/v1/payment-attempts": ok({ data: [{ id: "pa1" }], next_cursor: "cur-2" }),
      },
    });
    expect(await main(["ctl", "payment-attempts", "list", "--all-pages"], runtime)).toBe(2);
    expect(runtime.stderr()).toContain("cannot walk a cursor-paginated endpoint");
  });

  test("--sort warns that no operation honors it", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: { "GET /admin/v1/projects": ok({ data: [] }) },
    });
    await main(["ctl", "projects", "list", "--sort", "-created_at"], runtime);
    expect(runtime.stderr()).toContain("no Control Plane API operation declares a 'sort'");
    expect(runtime.client.requests[0]?.spec.query).toContainEqual(["sort", "-created_at"]);
  });

  test("--filter must be KEY=VALUE", async () => {
    const runtime = createTestRuntime({ store: STORE, env: ENV });
    expect(await main(["ctl", "projects", "list", "--filter", "broken"], runtime)).toBe(2);
    expect(runtime.stderr()).toContain("--filter must be KEY=VALUE");
  });
});

describe("raw export path", () => {
  test("the JSONL export writes bytes and refuses --output", async () => {
    const bytes = new TextEncoder().encode('{"a":1}\n');
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: { "GET /admin/v1/request-log-exports": { status: 200, bytes } },
    });
    expect(await main(["ctl", "request-logs", "export"], runtime)).toBe(0);
    expect(runtime.stdoutBytes()[0]).toEqual(bytes);
    expect(runtime.client.requests[0]?.mediaType).toBe("application/x-ndjson");

    const second = createTestRuntime({ store: STORE, env: ENV });
    expect(await main(["ctl", "request-logs", "export", "--output", "json"], second)).toBe(2);
    expect(second.stderr()).toContain("--output does not apply");
  });
});

describe("ops status shares the ctl code path", () => {
  test("ops status reads the admin status endpoint", async () => {
    const runtime = createTestRuntime({
      store: STORE,
      env: ENV,
      script: { "GET /admin/v1/status": ok({ status: "ok" }) },
    });
    expect(await main(["ops", "status"], runtime)).toBe(0);
    expect(runtime.client.requests[0]?.spec.path).toBe("/admin/v1/status");
  });

  test("ops status honors the same global flags", async () => {
    const runtime = createTestRuntime({
      env: {},
      script: { "GET /admin/v1/status": ok({ status: "ok" }) },
    });
    await main(["ops", "status", "--endpoint", "https://other.example"], runtime);
    expect(runtime.client.requests[0]?.context.endpoint).toBe("https://other.example");
  });
});
