/**
 * The admin-console SESSION surface — `/v1/admin/{register,login,refresh,logout,me,team*}`.
 *
 * ## Why this file exists
 *
 * `crates/ferrogate-auth-service/src/admin_console.rs` is 1481 lines and
 * `admin_console_test.rs` is 3780 — the biggest test file in the Rust tree.
 * NONE of it had a TypeScript counterpart: `grep -rl "admin/login" apps/` found
 * zero files, the nine routes are absent from the 281-operation contract (they
 * are the auth SERVICE's surface, not the gateway runtime's), and
 * `src/index.ts`'s own docblock lists them under "Still to come on this
 * Worker". The control migration has shipped `admin_users`,
 * `admin_user_tenant_memberships` and `admin_user_refresh_tokens` since day one
 * and NOTHING read or wrote any of the three.
 *
 * The Rust test module is the specification. Every assertion below is one of
 * its behaviours, and the ones that encode a SECURITY decision are called out
 * by the issue number the Rust comment cites:
 *
 *  - #157 register provisions the whole hierarchy + a once-shown gateway key;
 *  - #232 refresh re-issues for the token's STAMPED tenant, never
 *    `memberships.first()`;
 *  - #514 a suspended tenancy refuses the mint (403 `tenancy_suspended`) and
 *    must not hand back a live `fg_...` secret, on login AND on refresh AND on
 *    every session-JWT route;
 *  - #517 the minted key's scopes come from the caller's membership TIER, an
 *    unrecognised stored role resolves to `viewer` (fail closed), and a
 *    demotion/removal REVOKES the session keys already in a browser's hands.
 *
 * ## There are no cookies, and that is the port, not an omission
 *
 * `grep -c 'Set-Cookie\|SameSite\|HttpOnly\|Secure' admin_console.rs` is 0. The
 * Rust surface is a pure bearer-token API: the access token is a JWT the client
 * sends as `Authorization: Bearer`, and the refresh token travels in a JSON
 * body. So there are no cookie attributes to preserve — and the assertion that
 * pins that is `no route sets a cookie`, below, so a future "improvement" that
 * starts issuing a session cookie has to come with the attributes.
 *
 * CSRF is not absent, it is inherited: `adminCrossSiteRejection`
 * (`middleware/auth.ts`, ported from `server/handlers.rs`) already guards every
 * state-changing admin request, and the session routes opt into it explicitly
 * because `contractAuth` waves through any path that is not one of the 209.
 *
 * ## The app under test
 *
 * Composed here with the REAL `resolveDeps`, the REAL middleware chain from
 * `src/index.ts` and the REAL `env.DB`, in `src/index.ts`'s exact order. It
 * differs from the deployed composition root by exactly ONE line — the
 * `mountAdminConsoleSession(app)` call the integrate step owns — which is
 * documented in `src/session/index.ts`. Nothing here fakes a dependency.
 */
import { SELF, env } from "cloudflare:test";
import { Hono } from "hono";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { resolveDeps } from "../src/adapters.js";
import { contractAuth } from "../src/middleware/auth.js";
import { adminCorsPreflight, corsResponseHeaders } from "../src/middleware/cors.js";
import {
  controlPlaneErrorHandler,
  controlPlaneNotFoundHandler,
  requestId,
} from "../src/middleware/errors.js";
import type { ControlPlaneEnv } from "../src/ports.js";
import {
  ADMIN_CONSOLE_SESSION_KEY_NAME,
  ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS,
  ADMIN_SESSION_REFRESH_TOKEN_TTL_SECS,
  type MembershipRole,
  gatewayApiKeyScopes,
  membershipRoleFromStored,
  mountAdminConsoleSession,
  parseMembershipRole,
  signAdminAccessToken,
} from "../src/session/index.js";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm } from "./harness.js";
import { applyTenantSchema, resetTenantD1 } from "./tenant-db.js";

// ---------------------------------------------------------------------------
// The app, composed the way `src/index.ts` composes it
// ---------------------------------------------------------------------------

function buildApp(): Hono<ControlPlaneEnv> {
  const app = new Hono<ControlPlaneEnv>();
  app.onError(controlPlaneErrorHandler);
  app.notFound(controlPlaneNotFoundHandler);
  app.use("*", requestId);
  app.use("*", async (c, next) => {
    c.set("deps", resolveDeps(c.env, { requestId: c.get("requestId") }));
    await next();
  });
  app.use("*", corsResponseHeaders);
  app.use("*", adminCorsPreflight);
  app.use("*", contractAuth());
  mountAdminConsoleSession(app);
  return app;
}

const app = buildApp();

const JWT_SECRET = "console-signing-secret-for-tests";

/** `arm()` plus the two bindings the session surface adds. */
function armConsole(world: Parameters<typeof arm>[0] = {}): void {
  arm({ ...world, store: "d1" });
  (env as unknown as Record<string, string | undefined>).ADMIN_CONSOLE_JWT_SECRET = JWT_SECRET;
}

interface Json {
  readonly [field: string]: unknown;
}

async function call(
  method: string,
  path: string,
  options: { body?: unknown; token?: string; headers?: Record<string, string> } = {},
): Promise<{ status: number; body: Json; response: Response }> {
  const headers: Record<string, string> = { ...(options.headers ?? {}) };
  if (options.body !== undefined) headers["content-type"] = "application/json";
  if (options.token !== undefined) headers.authorization = `Bearer ${options.token}`;
  const response = await app.request(
    `${BASE}${path}`,
    {
      method,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    },
    env,
  );
  const text = await response.text();
  let body: Json = {};
  try {
    body = JSON.parse(text) as Json;
  } catch {
    body = { __raw: text };
  }
  return { status: response.status, body, response };
}

function errorOf(body: Json): { code: string; message: string } {
  const error = body.error as { code?: string; message?: string } | undefined;
  return { code: error?.code ?? "<none>", message: error?.message ?? "<none>" };
}

interface Session {
  readonly access_token: string;
  readonly refresh_token: string;
  readonly expires_in: number;
  readonly gateway_api_key: string;
  readonly user: { id: string; email: string; display_name: string };
  readonly tenant: { id: string; name: string; role: string };
}

async function register(
  email: string,
  password = "correct horse battery",
  organization = "Acme",
): Promise<Session> {
  const { status, body } = await call("POST", "/v1/admin/register", {
    body: { organization_name: organization, email, password },
  });
  expect(status, JSON.stringify(body)).toBe(201);
  return body as unknown as Session;
}

/** Raw rows, read straight out of the typed tables the migration ships. */
async function adminUserRow(email: string): Promise<Record<string, unknown> | null> {
  return await db()
    .prepare("SELECT * FROM admin_users WHERE email = ?")
    .bind(email)
    .first<Record<string, unknown>>();
}

async function refreshTokenRows(): Promise<Record<string, unknown>[]> {
  const rows = await db()
    .prepare("SELECT * FROM admin_user_refresh_tokens")
    .all<Record<string, unknown>>();
  return rows.results;
}

async function membershipRows(): Promise<Record<string, unknown>[]> {
  const rows = await db()
    .prepare("SELECT * FROM admin_user_tenant_memberships")
    .all<Record<string, unknown>>();
  return rows.results;
}

/**
 * Rewrite a membership's stored tier straight in SQL.
 *
 * Only the four CHECK-legal values can be written: `admin_user_tenant_memberships`
 * carries `CHECK (role IN ('owner','admin','member','viewer'))` and D1 enforces
 * it, so the "legacy row the validator never saw" that Rust's
 * `MembershipRole::from_stored` exists for is UNREACHABLE through this database
 * — the migration kept the CHECK precisely so it would be. That resolver's
 * fail-closed behaviour is therefore pinned at the unit level above
 * ("resolves an UNRECOGNISED stored role to viewer"), and what is proven
 * end-to-end here is the LADDER: the tier in the column decides the scopes on
 * the minted key.
 */
async function setStoredRole(userId: string, role: MembershipRole): Promise<void> {
  await db()
    .prepare("UPDATE admin_user_tenant_memberships SET role = ? WHERE user_id = ?")
    .bind(role, userId)
    .run();
}

/**
 * Point a tenant at `TENANT_DB_A`, the way the provisioning flow would.
 *
 * An UPSERT since #820, not an INSERT: registration now provisions the tenant's
 * storage and writes a `tenant_databases` row of its own, so a bare INSERT here
 * fails the primary key. Re-pointing that row at a D1 binding is what this
 * fixture means, and `storage_backend` must move with it — a row still saying
 * `durable_object` is one the binding router refuses, correctly.
 *
 * A console session key is TWO rows — `api_key_directory` in the control
 * database and `api_keys` in the tenant's own — and the second one is only
 * writable once that tenant has a database. Registration mints the tenant id
 * itself, so a tenant cannot have been provisioned at register time; the
 * end-to-end "this key really authenticates" probes therefore run against the
 * key LOGIN mints, after this call. Register's key is asserted on its document.
 */
async function provisionTenantDatabase(tenantId: string): Promise<void> {
  await db()
    .prepare(
      `INSERT INTO tenant_databases
         (tenant_id, database_uuid, database_name, binding_name, schema_version,
          migration_state, provisioned_at_unix, updated_at_unix)
       VALUES (?, 'uuid-a', 'ferrogate-tenant-a', 'TENANT_DB_A', 1, 'done', 1, 1)
       ON CONFLICT (tenant_id) DO UPDATE SET
         database_uuid = excluded.database_uuid,
         database_name = excluded.database_name,
         binding_name = excluded.binding_name,
         storage_backend = 'native_binding',
         migration_state = 'done',
         provisioning_status = 'ready'`,
    )
    .bind(tenantId)
    .run();
}

/** The virtual-key document the console minted for this user in this tenant. */
async function sessionKeyDocuments(): Promise<Record<string, unknown>[]> {
  const rows = await db()
    .prepare(
      `SELECT document_json FROM control_plane_resources WHERE resource_kind = 'virtual-keys'`,
    )
    .all<{ document_json: string }>();
  return rows.results
    .map((row) => JSON.parse(row.document_json) as Record<string, unknown>)
    .filter((document) => document.name === ADMIN_CONSOLE_SESSION_KEY_NAME);
}

beforeAll(async () => {
  await applySchema();
  await applyTenantSchema();
});

beforeEach(async () => {
  armConsole();
  await resetD1();
  await resetTenantD1();
  await db().batch([
    db().prepare("DELETE FROM admin_users"),
    db().prepare("DELETE FROM admin_user_tenant_memberships"),
    db().prepare("DELETE FROM admin_user_refresh_tokens"),
    db().prepare("DELETE FROM api_key_directory"),
  ]);
});

// ---------------------------------------------------------------------------
// MembershipRole — the tier ladder (#517)
// ---------------------------------------------------------------------------

describe("MembershipRole (crates/ferrogate-auth-service/src/membership_role.rs)", () => {
  it("parses the four canonical tiers and NOTHING else, case-sensitively", () => {
    expect(parseMembershipRole("owner")).toBe("owner");
    expect(parseMembershipRole("admin")).toBe("admin");
    expect(parseMembershipRole("member")).toBe("member");
    expect(parseMembershipRole("viewer")).toBe("viewer");
    // Rust: "accepting `Owner` here would GRANT owner authority to a stored
    // value that is denied today".
    expect(parseMembershipRole("Owner")).toBeNull();
    expect(parseMembershipRole("OWNER")).toBeNull();
    expect(parseMembershipRole("superuser")).toBeNull();
    expect(parseMembershipRole("")).toBeNull();
  });

  it("resolves an UNRECOGNISED stored role to viewer — never owner", () => {
    expect(membershipRoleFromStored("superuser")).toBe("viewer");
    expect(membershipRoleFromStored("Owner")).toBe("viewer");
    expect(membershipRoleFromStored("root")).toBe("viewer");
    expect(membershipRoleFromStored("owner")).toBe("owner");
  });

  it("hands admin.write to owner/admin only — viewer holds no .write scope", () => {
    expect([...gatewayApiKeyScopes("owner")]).toEqual([
      "admin.read",
      "admin.write",
      "assets.read",
      "assets.write",
    ]);
    expect([...gatewayApiKeyScopes("admin")]).toEqual([
      "admin.read",
      "admin.write",
      "assets.read",
      "assets.write",
    ]);
    expect([...gatewayApiKeyScopes("member")]).toEqual([
      "admin.read",
      "assets.read",
      "assets.write",
    ]);
    expect([...gatewayApiKeyScopes("viewer")]).toEqual(["admin.read", "assets.read"]);
    for (const role of ["member", "viewer"] as const) {
      expect(gatewayApiKeyScopes(role)).not.toContain("admin.write");
    }
  });
});

// ---------------------------------------------------------------------------
// POST /v1/admin/register  (#157)
// ---------------------------------------------------------------------------

describe("POST /v1/admin/register", () => {
  it("provisions tenant + project + workspace + owner user and issues a session", async () => {
    const session = await register("owner@acme.test");

    expect(session.access_token).not.toBe("");
    expect(session.refresh_token).not.toBe("");
    expect(session.expires_in).toBe(ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS);
    expect(session.expires_in).toBe(3600);
    expect(session.tenant.role).toBe("owner");
    expect(session.user.email).toBe("owner@acme.test");
    // Rust: `display_name` defaults to the email when absent.
    expect(session.user.display_name).toBe("owner@acme.test");
    expect(session.gateway_api_key.startsWith("fg_")).toBe(true);

    const memberships = await membershipRows();
    expect(memberships).toHaveLength(1);
    expect(memberships[0]?.role).toBe("owner");
    expect(memberships[0]?.tenant_id).toBe(session.tenant.id);
  });

  it("NEVER stores the plaintext password", async () => {
    const password = "correct horse battery";
    await register("owner@acme.test", password);
    const row = await adminUserRow("owner@acme.test");
    expect(row).not.toBeNull();
    const hash = String(row?.password_hash ?? "");
    expect(hash).not.toBe("");
    expect(hash).not.toContain(password);
    // A salted, iterated KDF — not a bare digest of the password.
    expect(hash.split("$")).toHaveLength(4);
  });

  it("lowercases and trims the email, and refuses a duplicate with 409", async () => {
    await register("Owner@Acme.test");
    const row = await adminUserRow("owner@acme.test");
    expect(row).not.toBeNull();

    const second = await call("POST", "/v1/admin/register", {
      body: { organization_name: "Acme", email: "  OWNER@acme.test ", password: "another one!!" },
    });
    expect(second.status).toBe(409);
    expect(errorOf(second.body).code).toBe("conflict");
  });

  it("rejects a bad email, a blank organization and a short password with 422", async () => {
    const bad = [
      { organization_name: "Acme", email: "not-an-email", password: "longenough1" },
      { organization_name: "   ", email: "a@b.test", password: "longenough1" },
      { organization_name: "Acme", email: "a@b.test", password: "short" },
    ];
    for (const body of bad) {
      const result = await call("POST", "/v1/admin/register", { body });
      expect(result.status, JSON.stringify(body)).toBe(422);
      expect(errorOf(result.body).code).toBe("invalid_request");
    }
  });

  it("mints ONE console-session key, attributed and scoped to OWNER", async () => {
    const session = await register("owner@acme.test");
    const documents = await sessionKeyDocuments();
    expect(documents).toHaveLength(1);
    const document = documents[0] as Record<string, unknown>;
    expect(document.user_id).toBe(session.user.id);
    expect(document.tenant_id).toBe(session.tenant.id);
    expect(document.scopes).toEqual(["admin.read", "admin.write", "assets.read", "assets.write"]);
    // The secret itself is never persisted — only its tagged digest.
    expect(JSON.stringify(document)).not.toContain(session.gateway_api_key);
    expect(String(document.key_hash).startsWith("sha256:")).toBe(true);
  });

  it("the minted key REALLY authenticates on this Worker's own native leg", async () => {
    const session = await register("owner@acme.test");
    await provisionTenantDatabase(session.tenant.id);
    // Proven by USING the credential, not by reading the row back: an
    // `api_key_directory` entry whose tenant `api_keys` row is missing resolves
    // to nothing at all, so a row-shaped assertion would pass on a dead key.
    const login = await call("POST", "/v1/admin/login", {
      body: { email: "owner@acme.test", password: "correct horse battery" },
    });
    const key = (login.body as unknown as Session).gateway_api_key;
    const probe = await SELF.fetch(`${BASE}/admin/v1/status`, {
      headers: { authorization: `Bearer ${key}` },
    });
    expect(probe.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// POST /v1/admin/login
// ---------------------------------------------------------------------------

describe("POST /v1/admin/login", () => {
  it("issues a session for the right password", async () => {
    await register("owner@acme.test");
    const { status, body } = await call("POST", "/v1/admin/login", {
      body: { email: "owner@acme.test", password: "correct horse battery" },
    });
    expect(status).toBe(200);
    const session = body as unknown as Session;
    expect(session.tenant.role).toBe("owner");
    expect(session.expires_in).toBe(ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS);
    expect(session.gateway_api_key.startsWith("fg_")).toBe(true);
  });

  it("gives a wrong password and an unknown email the SAME 401 — no user enumeration", async () => {
    await register("owner@acme.test");
    const wrongPassword = await call("POST", "/v1/admin/login", {
      body: { email: "owner@acme.test", password: "not the password" },
    });
    const unknownEmail = await call("POST", "/v1/admin/login", {
      body: { email: "nobody@acme.test", password: "correct horse battery" },
    });
    expect(wrongPassword.status).toBe(401);
    expect(unknownEmail.status).toBe(401);
    expect(errorOf(wrongPassword.body)).toEqual(errorOf(unknownEmail.body));
    expect(errorOf(wrongPassword.body).message).toBe("invalid email or password");
  });

  it("refuses a disabled account with 401", async () => {
    await register("owner@acme.test");
    await db()
      .prepare("UPDATE admin_users SET disabled_at_unix = 1 WHERE email = ?")
      .bind("owner@acme.test")
      .run();
    const result = await call("POST", "/v1/admin/login", {
      body: { email: "owner@acme.test", password: "correct horse battery" },
    });
    expect(result.status).toBe(401);
    expect(errorOf(result.body).message).toBe("this account has been disabled");
  });

  it("mints a VIEWER key for a viewer membership — no admin.write (#517)", async () => {
    const first = await register("owner@acme.test");
    await setStoredRole(first.user.id, "viewer");
    await provisionTenantDatabase(first.tenant.id);

    const { status, body } = await call("POST", "/v1/admin/login", {
      body: { email: "owner@acme.test", password: "correct horse battery" },
    });
    expect(status).toBe(200);
    const session = body as unknown as Session;
    // The reported tier is the RESOLVED one — never a tier the key does not
    // carry. Login and the minted key must agree, always.
    expect(session.tenant.role).toBe("viewer");

    // …and the key really cannot write. `admin.write` is the self-escalation
    // scope, so this is the whole point of the ladder.
    const write = await SELF.fetch(`${BASE}/admin/v1/virtual-keys`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${session.gateway_api_key}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ id: "vk_probe", tenant_id: session.tenant.id }),
    });
    expect(write.status).toBe(403);
    expect(errorOf((await write.json()) as Json).code).toBe("scope_denied");
  });

  it("REVOKES the caller's previous console session key on every login (#517)", async () => {
    const registered = await register("owner@acme.test");
    await provisionTenantDatabase(registered.tenant.id);
    const first = await call("POST", "/v1/admin/login", {
      body: { email: "owner@acme.test", password: "correct horse battery" },
    });
    const firstKey = (first.body as unknown as Session).gateway_api_key;

    const before = await SELF.fetch(`${BASE}/admin/v1/status`, {
      headers: { authorization: `Bearer ${firstKey}` },
    });
    expect(before.status).toBe(200);

    const { body } = await call("POST", "/v1/admin/login", {
      body: { email: "owner@acme.test", password: "correct horse battery" },
    });
    const second = (body as unknown as Session).gateway_api_key;
    expect(second).not.toBe(firstKey);

    const after = await SELF.fetch(`${BASE}/admin/v1/status`, {
      headers: { authorization: `Bearer ${firstKey}` },
    });
    expect(after.status).toBe(401);
    expect(errorOf((await after.json()) as Json).code).toBe("invalid_api_key");
  });

  it("refuses a SUSPENDED tenancy with 403 and hands back NO key (#514)", async () => {
    const session = await register("owner@acme.test");
    await db()
      .prepare(
        `UPDATE control_plane_resources
           SET document_json = json_set(document_json, '$.status', 'suspended')
         WHERE resource_kind = 'tenant-accounts' AND resource_id = ?`,
      )
      .bind(session.tenant.id)
      .run();

    const result = await call("POST", "/v1/admin/login", {
      body: { email: "owner@acme.test", password: "correct horse battery" },
    });
    expect(result.status).toBe(403);
    expect(errorOf(result.body).code).toBe("tenancy_suspended");
    // The defect the Rust comment names verbatim: this path used to return a
    // live `fg_...` secret. Assert on the WHOLE body, so no field can carry one.
    expect(JSON.stringify(result.body)).not.toContain("fg_");
  });

  it("still lets a DISABLED tenancy in — `disabled` is the tenant's own off switch", async () => {
    const session = await register("owner@acme.test");
    await db()
      .prepare(
        `UPDATE control_plane_resources
           SET document_json = json_set(document_json, '$.status', 'disabled')
         WHERE resource_kind = 'tenant-accounts' AND resource_id = ?`,
      )
      .bind(session.tenant.id)
      .run();

    const result = await call("POST", "/v1/admin/login", {
      body: { email: "owner@acme.test", password: "correct horse battery" },
    });
    // Rust: the Recovery seam. Refusing here would lock the tenant out of the
    // console it needs to re-enable itself.
    expect(result.status).toBe(200);
  });

  it("refuses a cross-site browser mutation (CSRF)", async () => {
    await register("owner@acme.test");
    const result = await call("POST", "/v1/admin/login", {
      body: { email: "owner@acme.test", password: "correct horse battery" },
      headers: { "sec-fetch-site": "cross-site" },
    });
    expect(result.status).toBe(403);
    expect(errorOf(result.body).code).toBe("cross_site_admin_denied");
  });

  it("sets NO cookie on any session response — this is a bearer-token API", async () => {
    const registered = await call("POST", "/v1/admin/register", {
      body: { organization_name: "Acme", email: "owner@acme.test", password: "correct horse b" },
    });
    expect(registered.response.headers.get("set-cookie")).toBeNull();
    const login = await call("POST", "/v1/admin/login", {
      body: { email: "owner@acme.test", password: "correct horse b" },
    });
    expect(login.response.headers.get("set-cookie")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// The access token itself
// ---------------------------------------------------------------------------

describe("the session access token", () => {
  it("expires exactly ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS after issue", async () => {
    const session = await register("owner@acme.test");
    const claims = JSON.parse(atob(session.access_token.split(".")[1] ?? "")) as {
      iat: number;
      exp: number;
      sub: string;
      tenant_id: string;
      role: string;
    };
    expect(claims.exp - claims.iat).toBe(ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS);
    expect(claims.sub).toBe(session.user.id);
    expect(claims.tenant_id).toBe(session.tenant.id);
    expect(claims.role).toBe("owner");
  });

  it("is rejected when signed with a DIFFERENT secret", async () => {
    const session = await register("owner@acme.test");
    const forged = await signAdminAccessToken("a different signing secret", {
      sub: session.user.id,
      email: session.user.email,
      tenant_id: session.tenant.id,
      role: "owner",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const result = await call("GET", "/v1/admin/me", { token: forged });
    expect(result.status).toBe(401);
    expect(errorOf(result.body).message).toBe("invalid or expired access token");
  });

  it("is rejected once EXPIRED", async () => {
    const session = await register("owner@acme.test");
    const now = Math.floor(Date.now() / 1000);
    const expired = await signAdminAccessToken(JWT_SECRET, {
      sub: session.user.id,
      email: session.user.email,
      tenant_id: session.tenant.id,
      role: "owner",
      iat: now - 7200,
      exp: now - 1,
    });
    const result = await call("GET", "/v1/admin/me", { token: expired });
    expect(result.status).toBe(401);
  });

  it("is rejected when the payload is tampered with but the signature is kept", async () => {
    const session = await register("owner@acme.test");
    const [header, payload, signature] = session.access_token.split(".");
    const claims = JSON.parse(atob(payload ?? "")) as Record<string, unknown>;
    claims.role = "owner";
    claims.sub = "user-somebody-else";
    const tampered = `${header}.${btoa(JSON.stringify(claims))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "")}.${signature}`;
    const result = await call("GET", "/v1/admin/me", { token: tampered });
    expect(result.status).toBe(401);
  });

  it("is rejected when the header claims a DIFFERENT algorithm, even though the HMAC verifies", async () => {
    // The isolating case for the `alg` pin. `alg: none` is not one: its
    // signature is empty, so the HMAC check rejects it on its own and a
    // verifier with no `alg` check at all still passes that test (measured —
    // mutation M2 left the `alg: none` assertion green).
    //
    // This token is signed with the REAL key over the REAL bytes, so
    // `crypto.subtle.verify` says yes; only the header disagrees. A verifier
    // that trusts the token's own `alg` — the algorithm-confusion shape — has
    // no reason to reject it. Ours must, because the algorithm is a constant
    // and the header is CHECKED against it.
    const session = await register("owner@acme.test");
    const b64 = (value: unknown) =>
      btoa(JSON.stringify(value)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const now = Math.floor(Date.now() / 1000);
    const signingInput = `${b64({ alg: "HS512", typ: "JWT" })}.${b64({
      sub: session.user.id,
      email: session.user.email,
      tenant_id: session.tenant.id,
      role: "owner",
      iat: now,
      exp: now + 3600,
    })}`;
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(JWT_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const signature = new Uint8Array(
      await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signingInput)),
    );
    let binary = "";
    for (const byte of signature) binary += String.fromCharCode(byte);
    const confused = `${signingInput}.${btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "")}`;

    const result = await call("GET", "/v1/admin/me", { token: confused });
    expect(result.status).toBe(401);
    expect(errorOf(result.body).message).toBe("invalid or expired access token");
  });

  it("is rejected when the header claims `alg: none`", async () => {
    const session = await register("owner@acme.test");
    const b64 = (value: unknown) =>
      btoa(JSON.stringify(value)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const now = Math.floor(Date.now() / 1000);
    const unsigned = `${b64({ alg: "none", typ: "JWT" })}.${b64({
      sub: session.user.id,
      email: session.user.email,
      tenant_id: session.tenant.id,
      role: "owner",
      iat: now,
      exp: now + 3600,
    })}.`;
    const result = await call("GET", "/v1/admin/me", { token: unsigned });
    expect(result.status).toBe(401);
  });
});

// ---------------------------------------------------------------------------
// GET /v1/admin/me
// ---------------------------------------------------------------------------

describe("GET /v1/admin/me", () => {
  it("rehydrates the session and reports the RESOLVED tier (#517)", async () => {
    const session = await register("owner@acme.test");
    const { status, body } = await call("GET", "/v1/admin/me", { token: session.access_token });
    expect(status).toBe(200);
    expect((body.user as Json).email).toBe("owner@acme.test");
    const memberships = body.memberships as { id: string; role: string }[];
    expect(memberships).toHaveLength(1);
    expect(memberships[0]?.role).toBe("owner");
  });

  it("reports the same tier login would, for the same session", async () => {
    const session = await register("owner@acme.test");
    await setStoredRole(session.user.id, "member");
    const { body } = await call("GET", "/v1/admin/me", { token: session.access_token });
    const memberships = body.memberships as { role: string }[];
    expect(memberships[0]?.role).toBe("member");
  });

  it("401s without a bearer token", async () => {
    const result = await call("GET", "/v1/admin/me");
    expect(result.status).toBe(401);
  });

  it("401s once the session's membership is gone", async () => {
    const session = await register("owner@acme.test");
    await db().prepare("DELETE FROM admin_user_tenant_memberships").run();
    const result = await call("GET", "/v1/admin/me", { token: session.access_token });
    expect(result.status).toBe(401);
    expect(errorOf(result.body).message).toBe("session tenant membership no longer exists");
  });

  it("403s once the session's tenant is SUSPENDED, mid-TTL (#514)", async () => {
    const session = await register("owner@acme.test");
    const before = await call("GET", "/v1/admin/me", { token: session.access_token });
    expect(before.status).toBe(200);

    await db()
      .prepare(
        `UPDATE control_plane_resources
           SET document_json = json_set(document_json, '$.status', 'suspended')
         WHERE resource_kind = 'tenant-accounts' AND resource_id = ?`,
      )
      .bind(session.tenant.id)
      .run();

    const after = await call("GET", "/v1/admin/me", { token: session.access_token });
    expect(after.status).toBe(403);
    expect(errorOf(after.body).code).toBe("tenancy_suspended");
  });
});

// ---------------------------------------------------------------------------
// POST /v1/admin/refresh
// ---------------------------------------------------------------------------

describe("POST /v1/admin/refresh", () => {
  it("stores the refresh token HASHED, with the 30-day expiry", async () => {
    const session = await register("owner@acme.test");
    const rows = await refreshTokenRows();
    expect(rows).toHaveLength(1);
    const row = rows[0] as Record<string, unknown>;
    expect(String(row.token_hash)).not.toBe(session.refresh_token);
    expect(String(row.token_hash).startsWith("sha256:")).toBe(true);
    expect(Number(row.expires_at_unix) - Number(row.created_at_unix)).toBe(
      ADMIN_SESSION_REFRESH_TOKEN_TTL_SECS,
    );
    expect(ADMIN_SESSION_REFRESH_TOKEN_TTL_SECS).toBe(60 * 60 * 24 * 30);
    // The stamped tenant + role (#232).
    expect(row.tenant_id).toBe(session.tenant.id);
    expect(row.role).toBe("owner");
  });

  it("mints a new pair and ROTATES — the presented token is single-use", async () => {
    const session = await register("owner@acme.test");
    const first = await call("POST", "/v1/admin/refresh", {
      body: { refresh_token: session.refresh_token },
    });
    expect(first.status).toBe(200);
    expect(first.body.expires_in).toBe(ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS);
    expect(first.body.refresh_token).not.toBe(session.refresh_token);
    // The refresh response deliberately carries NO gateway key — Rust returns
    // only the three token fields here.
    expect(first.body.gateway_api_key).toBeUndefined();

    const replay = await call("POST", "/v1/admin/refresh", {
      body: { refresh_token: session.refresh_token },
    });
    expect(replay.status).toBe(401);
    expect(errorOf(replay.body).message).toBe("refresh token has expired or been revoked");
  });

  it("re-issues for the token's STAMPED tenant, not the oldest membership (#232)", async () => {
    // Two tenants; the user's FIRST membership is tenant A, the session is
    // for tenant B. `memberships.first()` would silently swap them.
    const a = await register("multi@acme.test", "correct horse battery", "Alpha");
    const b = await register("owner-b@beta.test", "correct horse battery", "Beta");

    // Invite the tenant-A user into tenant B as a member.
    const invited = await call("POST", "/v1/admin/team/invite", {
      token: b.access_token,
      body: { email: "multi@acme.test", role: "member" },
    });
    expect(invited.status, JSON.stringify(invited.body)).toBe(201);

    // A session ISSUED for tenant B (stamped on the refresh row).
    const forB = await signAdminAccessToken(JWT_SECRET, {
      sub: a.user.id,
      email: a.user.email,
      tenant_id: b.tenant.id,
      role: "member",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const me = await call("GET", "/v1/admin/me", { token: forB });
    expect(me.status).toBe(200);

    // Log in — that stamps tenant A (the oldest membership) — then verify the
    // refresh of a B-stamped row comes back as B.
    await db()
      .prepare("UPDATE admin_user_refresh_tokens SET tenant_id = ?, role = ? WHERE user_id = ?")
      .bind(b.tenant.id, "member", a.user.id)
      .run();

    const refreshed = await call("POST", "/v1/admin/refresh", {
      body: { refresh_token: a.refresh_token },
    });
    expect(refreshed.status, JSON.stringify(refreshed.body)).toBe(200);
    const claims = JSON.parse(
      atob(String(refreshed.body.access_token).split(".")[1] ?? ""),
    ) as Record<string, unknown>;
    expect(claims.tenant_id).toBe(b.tenant.id);
    expect(claims.role).toBe("member");
  });

  it("re-reads the CURRENT membership, so a demotion takes effect on refresh", async () => {
    const session = await register("owner@acme.test");
    await setStoredRole(session.user.id, "member");
    const refreshed = await call("POST", "/v1/admin/refresh", {
      body: { refresh_token: session.refresh_token },
    });
    expect(refreshed.status).toBe(200);
    const claims = JSON.parse(
      atob(String(refreshed.body.access_token).split(".")[1] ?? ""),
    ) as Record<string, unknown>;
    expect(claims.role).toBe("member");
  });

  it("ends the session when the membership in the stamped tenant is gone", async () => {
    const session = await register("owner@acme.test");
    await db().prepare("DELETE FROM admin_user_tenant_memberships").run();
    const result = await call("POST", "/v1/admin/refresh", {
      body: { refresh_token: session.refresh_token },
    });
    expect(result.status).toBe(401);
    expect(errorOf(result.body).message).toBe(
      "this account is no longer a member of the session's tenant",
    );
  });

  it("fails CLOSED on a legacy row with no stamped tenant", async () => {
    const session = await register("owner@acme.test");
    await db().prepare("UPDATE admin_user_refresh_tokens SET tenant_id = NULL").run();
    const result = await call("POST", "/v1/admin/refresh", {
      body: { refresh_token: session.refresh_token },
    });
    expect(result.status).toBe(401);
    expect(errorOf(result.body).message).toContain("predates tenant-scoped sessions");
  });

  it("refuses an EXPIRED refresh token", async () => {
    const session = await register("owner@acme.test");
    await db().prepare("UPDATE admin_user_refresh_tokens SET expires_at_unix = 1").run();
    const result = await call("POST", "/v1/admin/refresh", {
      body: { refresh_token: session.refresh_token },
    });
    expect(result.status).toBe(401);
  });

  it("refuses an unknown refresh token", async () => {
    await register("owner@acme.test");
    const result = await call("POST", "/v1/admin/refresh", {
      body: { refresh_token: "not-a-token" },
    });
    expect(result.status).toBe(401);
    expect(errorOf(result.body).message).toBe("invalid refresh token");
  });

  it("is gated by the tenancy lifecycle too — refresh must not outlive suspension (#514)", async () => {
    const session = await register("owner@acme.test");
    await db()
      .prepare(
        `UPDATE control_plane_resources
           SET document_json = json_set(document_json, '$.status', 'suspended')
         WHERE resource_kind = 'tenant-accounts' AND resource_id = ?`,
      )
      .bind(session.tenant.id)
      .run();
    const result = await call("POST", "/v1/admin/refresh", {
      body: { refresh_token: session.refresh_token },
    });
    expect(result.status).toBe(403);
    expect(errorOf(result.body).code).toBe("tenancy_suspended");
  });
});

// ---------------------------------------------------------------------------
// POST /v1/admin/logout
// ---------------------------------------------------------------------------

describe("POST /v1/admin/logout", () => {
  it("revokes the refresh token SERVER-SIDE, so it can never be redeemed again", async () => {
    const session = await register("owner@acme.test");
    const result = await call("POST", "/v1/admin/logout", {
      body: { refresh_token: session.refresh_token },
    });
    expect(result.status).toBe(200);
    expect(result.body).toEqual({ object: "logout", revoked: true });

    // The row is marked, not deleted (Rust: revocation marks a row).
    const rows = await refreshTokenRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]?.revoked_at_unix).not.toBeNull();

    const replay = await call("POST", "/v1/admin/refresh", {
      body: { refresh_token: session.refresh_token },
    });
    expect(replay.status).toBe(401);
  });

  it("answers 200 revoked:false for a token it does not know — no enumeration", async () => {
    await register("owner@acme.test");
    const result = await call("POST", "/v1/admin/logout", {
      body: { refresh_token: "nothing-like-a-real-token" },
    });
    expect(result.status).toBe(200);
    expect(result.body).toEqual({ object: "logout", revoked: false });
  });

  it("is idempotent", async () => {
    const session = await register("owner@acme.test");
    const first = await call("POST", "/v1/admin/logout", {
      body: { refresh_token: session.refresh_token },
    });
    const second = await call("POST", "/v1/admin/logout", {
      body: { refresh_token: session.refresh_token },
    });
    expect(first.body).toEqual({ object: "logout", revoked: true });
    expect(second.body).toEqual({ object: "logout", revoked: true });
  });
});

// ---------------------------------------------------------------------------
// The team surface  (#162 / #517)
// ---------------------------------------------------------------------------

describe("/v1/admin/team", () => {
  it("lists the roster with RESOLVED tiers", async () => {
    const owner = await register("owner@acme.test");
    await register("mate@other.test", "correct horse battery", "Other");
    await call("POST", "/v1/admin/team/invite", {
      token: owner.access_token,
      body: { email: "mate@other.test", role: "viewer" },
    });
    const { status, body } = await call("GET", "/v1/admin/team", { token: owner.access_token });
    expect(status).toBe(200);
    const members = body.members as { email: string; role: string }[];
    expect(members.map((member) => member.email).sort()).toEqual([
      "mate@other.test",
      "owner@acme.test",
    ]);
    expect(members.find((member) => member.email === "mate@other.test")?.role).toBe("viewer");
  });

  it("lets only an OWNER invite — 403 for anyone else", async () => {
    const owner = await register("owner@acme.test");
    const mate = await register("mate@other.test", "correct horse battery", "Other");
    await call("POST", "/v1/admin/team/invite", {
      token: owner.access_token,
      body: { email: "mate@other.test", role: "member" },
    });
    // The invitee's OWN session in the owner's tenant.
    const mateInAcme = await signAdminAccessToken(JWT_SECRET, {
      sub: mate.user.id,
      email: mate.user.email,
      tenant_id: owner.tenant.id,
      role: "member",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const result = await call("POST", "/v1/admin/team/invite", {
      token: mateInAcme,
      body: { email: "owner@acme.test", role: "owner" },
    });
    expect(result.status).toBe(403);
    expect(errorOf(result.body).code).toBe("forbidden");
  });

  it("refuses an unknown role with 422 rather than storing it", async () => {
    const owner = await register("owner@acme.test");
    await register("mate@other.test", "correct horse battery", "Other");
    const result = await call("POST", "/v1/admin/team/invite", {
      token: owner.access_token,
      body: { email: "mate@other.test", role: "superuser" },
    });
    expect(result.status).toBe(422);
    expect(errorOf(result.body).message).toContain("owner, admin, member, viewer");
    const roles = (await membershipRows()).map((row) => row.role);
    expect(roles).not.toContain("superuser");
  });

  it("404s user_not_found for an email with no account", async () => {
    const owner = await register("owner@acme.test");
    const result = await call("POST", "/v1/admin/team/invite", {
      token: owner.access_token,
      body: { email: "ghost@nowhere.test", role: "member" },
    });
    expect(result.status).toBe(404);
    expect(errorOf(result.body).code).toBe("user_not_found");
  });

  it("revokes the demoted teammate's gateway session key (#517)", async () => {
    const owner = await register("owner@acme.test");
    const mate = await register("mate@other.test", "correct horse battery", "Other");
    await call("POST", "/v1/admin/team/invite", {
      token: owner.access_token,
      body: { email: "mate@other.test", role: "admin" },
    });

    // The teammate logs in AGAINST THIS TENANT and gets an admin.write key.
    // (Login picks the oldest membership, so drop their own tenant's row.)
    await db()
      .prepare("DELETE FROM admin_user_tenant_memberships WHERE user_id = ? AND tenant_id = ?")
      .bind(mate.user.id, mate.tenant.id)
      .run();
    await provisionTenantDatabase(owner.tenant.id);
    const login = await call("POST", "/v1/admin/login", {
      body: { email: "mate@other.test", password: "correct horse battery" },
    });
    expect(login.status).toBe(200);
    const mateKey = (login.body as unknown as Session).gateway_api_key;
    const before = await SELF.fetch(`${BASE}/admin/v1/status`, {
      headers: { authorization: `Bearer ${mateKey}` },
    });
    expect(before.status).toBe(200);

    const demote = await call("POST", `/v1/admin/team/members/${mate.user.id}`, {
      token: owner.access_token,
      body: { role: "viewer" },
    });
    expect(demote.status, JSON.stringify(demote.body)).toBe(200);
    expect(demote.body).toMatchObject({ object: "membership", role: "viewer" });

    // A tier is only real if DEMOTION takes effect.
    const after = await SELF.fetch(`${BASE}/admin/v1/status`, {
      headers: { authorization: `Bearer ${mateKey}` },
    });
    expect(after.status).toBe(401);
  });

  it("refuses to demote or remove the LAST owner", async () => {
    const owner = await register("owner@acme.test");
    const demote = await call("POST", `/v1/admin/team/members/${owner.user.id}`, {
      token: owner.access_token,
      body: { role: "viewer" },
    });
    expect(demote.status).toBe(409);
    expect(errorOf(demote.body).message).toBe("cannot demote the last owner of a tenant");

    const remove = await call("DELETE", `/v1/admin/team/members/${owner.user.id}`, {
      token: owner.access_token,
    });
    expect(remove.status).toBe(409);
    expect(errorOf(remove.body).message).toBe("cannot remove the last owner of a tenant");
  });

  it("removes a teammate AND revokes the key that membership granted (#517)", async () => {
    const owner = await register("owner@acme.test");
    const mate = await register("mate@other.test", "correct horse battery", "Other");
    await call("POST", "/v1/admin/team/invite", {
      token: owner.access_token,
      body: { email: "mate@other.test", role: "admin" },
    });
    await db()
      .prepare("DELETE FROM admin_user_tenant_memberships WHERE user_id = ? AND tenant_id = ?")
      .bind(mate.user.id, mate.tenant.id)
      .run();
    await provisionTenantDatabase(owner.tenant.id);
    const login = await call("POST", "/v1/admin/login", {
      body: { email: "mate@other.test", password: "correct horse battery" },
    });
    const mateKey = (login.body as unknown as Session).gateway_api_key;

    const removed = await call("DELETE", `/v1/admin/team/members/${mate.user.id}`, {
      token: owner.access_token,
    });
    expect(removed.status).toBe(200);
    expect(removed.body).toEqual({ object: "membership", removed: true });

    const after = await SELF.fetch(`${BASE}/admin/v1/status`, {
      headers: { authorization: `Bearer ${mateKey}` },
    });
    expect(after.status).toBe(401);
  });

  it("404s removing a user who is not in this tenant", async () => {
    const owner = await register("owner@acme.test");
    const result = await call("DELETE", "/v1/admin/team/members/user-nobody", {
      token: owner.access_token,
    });
    expect(result.status).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// Fail-closed posture when the surface is not configured
// ---------------------------------------------------------------------------

describe("an unconfigured deployment", () => {
  it("answers 503 (never a session) when no console signing secret is bound", async () => {
    (env as unknown as Record<string, string | undefined>).ADMIN_CONSOLE_JWT_SECRET = undefined;
    const result = await call("POST", "/v1/admin/login", {
      body: { email: "owner@acme.test", password: "correct horse battery" },
    });
    expect(result.status).toBe(503);
    expect(errorOf(result.body).code).toBe("admin_console_unconfigured");
  });
});
