// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: FerroGate brokered per-operation git credential route (issue #475). The
//   container's git credential helper calls back here per git operation; the Worker
//   authorizes it, mints a repo-scoped GitHub App installation token from a Secrets
//   Store-bound App private key, answers git, and revokes on run close. Nothing
//   GitHub-shaped ever rests inside the container.

import { json, requireBearer } from "./auth";
import type { Env } from "./index";

/**
 * Why this route exists on the WORKER and not in the container.
 *
 * Cloudflare Secrets Store values are write-only over REST (decision #423);
 * the only read path is a Workers binding, and `env.<BINDING>.get()` takes no
 * arguments — the secret NAME is fixed at deploy time. That makes a Worker the
 * only place a Secrets Store value can be read at all, and it makes a
 * per-user secret unreadable by construction. Both facts point at the same
 * design: store ONE platform credential (the GitHub App private key), and
 * express per-user authorization as a non-secret installation id.
 *
 * The App private key is a ~1.7 KB RSA PEM and therefore CANNOT live in
 * Secrets Store (1024-byte per-value cap). It is a Worker secret
 * (`wrangler secret put GITHUB_APP_PRIVATE_KEY`, 5 KB limit). The Secrets
 * Store binding below is kept for the short values that do fit and for the
 * GA migration, and the route works with either — see
 * docs/cloudflare-git-credential-broker.md.
 */

/** GitHub's fixed installation-token lifetime. Not configurable by the caller. */
const GITHUB_TOKEN_TTL_SECS = 3600;

/** Username git must present alongside an installation token over HTTPS. */
const INSTALLATION_TOKEN_USERNAME = "x-access-token";

/** Ceiling on the App JWT's own lifetime (GitHub rejects > 10 minutes). */
const APP_JWT_TTL_SECS = 540;

/** Per-run cap on credential callbacks; mirrors the Rust broker's default. */
const OPERATION_BUDGET = 32;

/**
 * A grant, as the control plane registered it before the run started.
 * Authoritative copy lives in the control plane; the Worker holds it in the
 * run's Durable Object so the hot path needs no round trip.
 */
export interface BrokerGrantRecord {
  runId: string;
  grantId: string;
  /** `provider:host/namespace/name`. */
  repoId: string;
  host: string;
  namespace: string;
  name: string;
  /** GitHub App installation authorizing this run. NOT a secret. */
  installationId: number;
  /** `contents`/`pull_requests` → `read`/`write`, derived from the Rust scope. */
  permissions: Record<string, "read" | "write">;
  writeCapable: boolean;
  expiresAtUnix: number;
  /** Callbacks already served, for the operation budget. */
  operationsUsed: number;
}

/** The credential-helper callback body. Note: no password field, ever. */
interface CredentialCallback {
  runId: string;
  grantId: string;
  operation: "fetch" | "push";
  query: {
    protocol: string;
    host: string;
    path?: string;
    username?: string;
  };
}

/** Stable denial codes; mirror `broker_deny_codes` in the Rust module. */
const DENY = {
  RUN_MISMATCH: "run_mismatch",
  GRANT_MISMATCH: "grant_mismatch",
  GRANT_EXPIRED: "grant_expired",
  PROTOCOL_NOT_HTTPS: "protocol_not_https",
  HOST_NOT_GRANTED: "host_not_granted",
  PATH_MISSING: "path_missing",
  REPO_NOT_GRANTED: "repo_not_granted",
  WRITE_NOT_GRANTED: "write_not_granted",
  OPERATION_BUDGET_EXHAUSTED: "operation_budget_exhausted",
} as const;

type DenyCode = (typeof DENY)[keyof typeof DENY];

/**
 * Authorize one callback against the grant. Pure and side-effect free so it is
 * testable without a GitHub round trip; it is the TypeScript twin of
 * `GitCredentialBroker::decide` and MUST stay in step with it.
 */
export function authorizeCallback(
  grant: BrokerGrantRecord,
  callback: CredentialCallback,
  nowUnix: number,
): { ok: true } | { ok: false; code: DenyCode; detail: string } {
  const deny = (code: DenyCode, detail: string) => ({ ok: false as const, code, detail });

  if (grant.operationsUsed >= OPERATION_BUDGET) {
    return deny(DENY.OPERATION_BUDGET_EXHAUSTED, `run used its ${OPERATION_BUDGET} operations`);
  }
  if (callback.runId !== grant.runId) return deny(DENY.RUN_MISMATCH, "callback names another run");
  if (callback.grantId !== grant.grantId) {
    return deny(DENY.GRANT_MISMATCH, "callback names an unknown grant");
  }
  if (nowUnix >= grant.expiresAtUnix) {
    return deny(DENY.GRANT_EXPIRED, `grant expired at ${grant.expiresAtUnix}`);
  }
  if (callback.query.protocol?.toLowerCase() !== "https") {
    return deny(DENY.PROTOCOL_NOT_HTTPS, "credentials are brokered over TLS only");
  }
  const host = (callback.query.host ?? "").toLowerCase().split(":")[0];
  if (host !== grant.host.toLowerCase()) {
    return deny(DENY.HOST_NOT_GRANTED, `host ${host} is not the granted host`);
  }
  // `credential.useHttpPath=true` is what makes this field present. Without it
  // the answer could not be scoped to one repo, so a pathless callback fails
  // closed rather than degrading to host scoping.
  const rawPath = (callback.query.path ?? "").trim().replace(/^\/+|\/+$/g, "");
  const path = rawPath.replace(/\.git$/, "");
  if (!path) {
    return deny(DENY.PATH_MISSING, "set credential.useHttpPath=true on the container's git");
  }
  if (path.toLowerCase() !== `${grant.namespace}/${grant.name}`.toLowerCase()) {
    return deny(DENY.REPO_NOT_GRANTED, `repo ${path} is not the granted repo`);
  }
  if (callback.operation === "push" && !grant.writeCapable) {
    return deny(DENY.WRITE_NOT_GRANTED, "push requires a write-back-backed grant");
  }
  return { ok: true };
}

/** Base64url without padding, for JWT segments. */
function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Strip a PEM's armour and decode the DER body. */
function pemToDer(pem: string): ArrayBuffer {
  const body = pem
    .replace(/-----BEGIN [A-Z ]+-----/g, "")
    .replace(/-----END [A-Z ]+-----/g, "")
    .replace(/\s+/g, "");
  const raw = atob(body);
  const der = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) der[i] = raw.charCodeAt(i);
  return der.buffer;
}

/**
 * Sign the short-lived App JWT that authenticates the token mint.
 *
 * NOTE: WebCrypto imports PKCS#8 only. GitHub hands out PKCS#1 ("BEGIN RSA
 * PRIVATE KEY"); convert once at onboarding with
 * `openssl pkcs8 -topk8 -nocrypt -in app.pem -out app.pkcs8.pem`, and store the
 * PKCS#8 form. This throws rather than guessing if the wrong form is supplied.
 */
async function appJwt(appId: string, privateKeyPem: string, nowUnix: number): Promise<string> {
  if (!privateKeyPem.includes("BEGIN PRIVATE KEY")) {
    throw new Error("GitHub App key must be PKCS#8 ('BEGIN PRIVATE KEY'); convert with openssl");
  }
  const key = await crypto.subtle.importKey(
    "pkcs8",
    pemToDer(privateKeyPem),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const encoder = new TextEncoder();
  const header = base64url(encoder.encode(JSON.stringify({ alg: "RS256", typ: "JWT" })));
  const payload = base64url(
    encoder.encode(
      // 60s of backdate absorbs clock skew, per GitHub's own guidance.
      JSON.stringify({ iat: nowUnix - 60, exp: nowUnix + APP_JWT_TTL_SECS, iss: appId }),
    ),
  );
  const signingInput = `${header}.${payload}`;
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    encoder.encode(signingInput),
  );
  return `${signingInput}.${base64url(new Uint8Array(signature))}`;
}

/** Read the App private key: Secrets Store binding first, Worker secret second. */
async function appPrivateKey(env: Env): Promise<string | null> {
  if (env.GITHUB_APP_PRIVATE_KEY_STORE) {
    // Secrets Store binding: `get()` takes NO arguments — the secret name is
    // fixed in wrangler config at deploy time. This is exactly why a per-user
    // secret cannot be read this way.
    const value = await env.GITHUB_APP_PRIVATE_KEY_STORE.get();
    if (value) return value;
  }
  return env.GITHUB_APP_PRIVATE_KEY ?? null;
}

/**
 * Mint a repo-scoped installation token.
 * `POST /app/installations/{id}/access_tokens` with a single-element
 * `repositories` array. GitHub fixes the expiry at one hour.
 */
async function mintInstallationToken(
  env: Env,
  grant: BrokerGrantRecord,
  nowUnix: number,
): Promise<{ token: string; expiresAt: string }> {
  const appId = env.GITHUB_APP_ID;
  const privateKey = await appPrivateKey(env);
  if (!appId || !privateKey) throw new Error("github_app_unbound");
  const apiBase = (env.GITHUB_API_BASE_URL ?? "https://api.github.com").replace(/\/+$/, "");
  const jwt = await appJwt(appId, privateKey, nowUnix);
  const response = await fetch(`${apiBase}/app/installations/${grant.installationId}/access_tokens`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${jwt}`,
      accept: "application/vnd.github+json",
      "x-github-api-version": "2022-11-28",
      "content-type": "application/json",
      "user-agent": "ferrogate-agent-gateway",
    },
    body: JSON.stringify({ repositories: [grant.name], permissions: grant.permissions }),
  });
  if (!response.ok) {
    // The body can echo request detail; status only, never the response text.
    throw new Error(`installation_token_mint_failed_${response.status}`);
  }
  const body = (await response.json()) as { token: string; expires_at: string };
  return { token: body.token, expiresAt: body.expires_at };
}

/**
 * `POST /git-credential/get` — the credential-helper callback.
 *
 * Response on approval:
 *   { "username": "x-access-token", "password": "<token>",
 *     "expiresAtUnix": ..., "operationId": "sha256:..." }
 * Response on refusal (HTTP 403):
 *   { "error": "<deny code>", "detail": "..." }
 * The helper turns a refusal into an EMPTY credential block on stdout, so git
 * fails the operation instead of prompting or retrying.
 *
 * The token is written to the response and nowhere else: it is never logged,
 * never persisted in the DO, and never placed on a run event. What IS recorded
 * is the material-free audit row (`GitCredentialAuditEvent` in Rust).
 */
export async function handleGitCredential(request: Request, env: Env, url: URL): Promise<Response> {
  // The helper authenticates with the run-scoped callback capability. It is a
  // GATEWAY capability, not a GitHub credential: presenting it to github.com
  // achieves nothing, and it stops working the moment the run is finalized.
  const denied = requireBearer(request, env.GATEWAY_CONTROL_TOKEN);
  if (denied) return denied;

  const verb = url.pathname.slice("/git-credential/".length);
  if (request.method !== "POST") return json({ error: "method not allowed" }, 405);

  // Fail closed: an unbound GitHub App means NO credential path exists, which
  // must never degrade into "run without one" or "fall back to an env token".
  if (!env.GITHUB_APP_ID || !(env.GITHUB_APP_PRIVATE_KEY_STORE || env.GITHUB_APP_PRIVATE_KEY)) {
    return json({ error: "github_app_unbound" }, 501);
  }

  switch (verb) {
    case "get": {
      const body = (await request.json()) as CredentialCallback & { grant?: BrokerGrantRecord };
      const grant = body.grant;
      if (!grant) return json({ error: "grant_mismatch", detail: "no grant registered" }, 403);
      const nowUnix = Math.floor(Date.now() / 1000);
      const decision = authorizeCallback(grant, body, nowUnix);
      if (!decision.ok) return json({ error: decision.code, detail: decision.detail }, 403);
      try {
        const minted = await mintInstallationToken(env, grant, nowUnix);
        const expiresAtUnix = Math.min(
          grant.expiresAtUnix,
          nowUnix + GITHUB_TOKEN_TTL_SECS,
          Math.floor(Date.parse(minted.expiresAt) / 1000) || nowUnix + GITHUB_TOKEN_TTL_SECS,
        );
        return json({
          username: INSTALLATION_TOKEN_USERNAME,
          password: minted.token,
          expiresAtUnix,
        });
      } catch (err) {
        // `(err as Error).message` is one of our own fixed strings — never a
        // GitHub response body, which could echo request material.
        return json({ error: (err as Error).message }, 502);
      }
    }
    case "revoke": {
      // `DELETE /installation/token` revokes the token used to authenticate the
      // call. Driven at run finalize on BOTH the success and failure paths; a
      // failure here is the incident, so it is reported, never swallowed.
      const body = (await request.json()) as { token?: string };
      if (!body.token) return json({ error: "no token presented" }, 400);
      const apiBase = (env.GITHUB_API_BASE_URL ?? "https://api.github.com").replace(/\/+$/, "");
      const response = await fetch(`${apiBase}/installation/token`, {
        method: "DELETE",
        headers: {
          authorization: `Bearer ${body.token}`,
          accept: "application/vnd.github+json",
          "x-github-api-version": "2022-11-28",
          "user-agent": "ferrogate-agent-gateway",
        },
      });
      // 401 means the token was already dead — the credential IS neutralized,
      // which is the outcome that matters, so it is not reported as a failure.
      if (response.status === 204) return json({ outcome: "revoked" });
      if (response.status === 401) return json({ outcome: "already_expired" });
      return json({ outcome: "failed", code: `http_${response.status}` }, 502);
    }
    default:
      return json({ error: `unknown git-credential verb: ${verb}` }, 404);
  }
}
