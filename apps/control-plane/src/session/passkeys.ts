import {
  type AuthenticationResponseJSON,
  type AuthenticatorTransport,
  type RegistrationResponseJSON,
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { isoBase64URL } from "@simplewebauthn/server/helpers";
import type { Context } from "hono";
import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import type { ControlPlaneEnv } from "../ports.js";
import { constantTimeEqual } from "./credentials.js";
import { PasskeyStore } from "./passkey-store.js";
import { bearerToken, consoleOf, currentAdminSession, mintPasskeySession } from "./routes.js";

type Ctx = Context<ControlPlaneEnv>;
const refusal = () =>
  new HttpError(401, "passkey_invalid", "Passkey verification failed; please try again");
const identifier = z
  .string()
  .min(1)
  .max(2048)
  .regex(/^[A-Za-z0-9_-]+$/);
const beginSchema = z.object({ binding: identifier, client: identifier });
const finishSchema = z.object({
  binding: identifier,
  challengeId: z.string().uuid(),
  response: z.object({
    id: identifier,
    rawId: identifier,
    type: z.literal("public-key"),
    response: z.record(z.unknown()),
    clientExtensionResults: z.record(z.unknown()),
    authenticatorAttachment: z.enum(["platform", "cross-platform"]).optional(),
  }),
  name: z.string().trim().min(1).max(60).optional(),
});

async function body<T>(c: Ctx, schema: z.ZodType<T>): Promise<T> {
  const text = await c.req.text();
  if (text.length > 32_768)
    throw new HttpError(413, "body_too_large", "Passkey response too large");
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new HttpError(400, "invalid_json", "Invalid JSON");
  }
  const result = schema.safeParse(raw);
  if (!result.success) throw new HttpError(400, "invalid_request", "Invalid passkey request");
  return result.data;
}

async function proofBody(c: Ctx) {
  const proof = await body(c, finishSchema);
  try {
    const clientData = JSON.parse(
      isoBase64URL.toUTF8String(String(proof.response.response.clientDataJSON)),
    );
    if (clientData.crossOrigin === true || clientData.topOrigin !== undefined) throw refusal();
  } catch {
    throw refusal();
  }
  return proof;
}

function context(c: Ctx) {
  c.header("cache-control", "no-store");
  // BFF verifies Origin, browser binding and fresh email OTP for enrollment. No public bypass.
  const env = c.env as unknown as Record<string, unknown>;
  const secret =
    typeof env.OAUTH_BRIDGE_LOGIN_SECRET === "string" ? env.OAUTH_BRIDGE_LOGIN_SECRET.trim() : "";
  const origin = typeof env.VEGA_PASSKEY_ORIGIN === "string" ? env.VEGA_PASSKEY_ORIGIN : "";
  if (!secret || !origin)
    throw new HttpError(503, "passkey_unconfigured", "Passkey login is not configured");
  if (!constantTimeEqual(c.req.header("x-ferrogate-oauth-bridge-secret") ?? "", secret))
    throw refusal();
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    throw new HttpError(503, "passkey_unconfigured", "Invalid Passkey origin");
  }
  if (
    url.origin !== origin ||
    (url.protocol !== "https:" && !(url.protocol === "http:" && url.hostname === "localhost"))
  ) {
    throw new HttpError(503, "passkey_unconfigured", "Invalid Passkey origin");
  }
  const console_ = consoleOf(c);
  return {
    console_,
    store: new PasskeyStore(console_.deps.controlDatabase as D1Database),
    origin,
    rpID: url.hostname,
  };
}

async function identity(c: Ctx, ctx: ReturnType<typeof context>) {
  const result = await currentAdminSession(ctx.console_, bearerToken(c));
  if (result.user.disabledAtUnix !== null) throw refusal();
  return result;
}

async function userHandle(userId: string, tenantId: string) {
  return new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(JSON.stringify([userId, tenantId])),
    ),
  );
}

async function throttle(store: PasskeyStore, client: string) {
  try {
    await store.throttle(client);
  } catch (err) {
    if (err instanceof Error && err.message === "rate_limit")
      throw new HttpError(429, "rate_limited", "Too many Passkey attempts; try again later");
    throw err;
  }
}

export const passkeyHandlers: Record<string, (c: Ctx) => Promise<Response>> = {
  "POST /v1/admin/passkeys/login/options": async (c) => {
    const ctx = context(c);
    const input = await body(c, beginSchema);
    await throttle(ctx.store, input.client);
    const options = await generateAuthenticationOptions({
      rpID: ctx.rpID,
      userVerification: "required",
    });
    const challengeId = await ctx.store.challenge("login", input.binding, options.challenge);
    return c.json({ options, challengeId });
  },
  "POST /v1/admin/passkeys/login/verify": async (c) => {
    const ctx = context(c);
    const input = await proofBody(c);
    const challenge = await ctx.store.consume(input.challengeId, "login", input.binding);
    if (!challenge) throw refusal();
    const row = await ctx.store.get(input.response.id);
    if (!row || input.response.response.userHandle !== row.user_handle) throw refusal();
    let verified: Awaited<ReturnType<typeof verifyAuthenticationResponse>>;
    try {
      verified = await verifyAuthenticationResponse({
        response: input.response as unknown as AuthenticationResponseJSON,
        expectedChallenge: challenge.challenge,
        expectedOrigin: ctx.origin,
        expectedRPID: ctx.rpID,
        requireUserVerification: true,
        credential: {
          id: row.id,
          publicKey: isoBase64URL.toBuffer(row.public_key),
          counter: row.counter,
        },
      });
    } catch {
      throw refusal();
    }
    if (!verified.verified || !(await ctx.store.used(row, verified.authenticationInfo.newCounter)))
      throw refusal();
    // Resolve immutable user+tenant IDs from the verified credential, never an email or browser input.
    return mintPasskeySession(c, ctx.console_, row.user_id, row.tenant_id);
  },
  "POST /v1/admin/passkeys/register/options": async (c) => {
    const ctx = context(c);
    const { user, membership } = await identity(c, ctx);
    const input = await body(c, beginSchema);
    await throttle(ctx.store, input.client);
    const rows = await ctx.store.list(user.id, membership.tenantId);
    if (rows.length >= 10)
      throw new HttpError(409, "passkey_limit", "Remove an existing Passkey before adding another");
    const options = await generateRegistrationOptions({
      rpName: "Token4AI",
      rpID: ctx.rpID,
      userName: user.email,
      userID: await userHandle(user.id, membership.tenantId),
      attestationType: "none",
      supportedAlgorithmIDs: [-7, -257],
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "required",
        authenticatorAttachment: "platform",
      },
      excludeCredentials: rows.map((row) => ({
        id: row.id,
        transports: JSON.parse(row.transports) as AuthenticatorTransport[],
      })),
    });
    const challengeId = await ctx.store.challenge(
      "register",
      input.binding,
      options.challenge,
      user.id,
      membership.tenantId,
    );
    return c.json({ options, challengeId });
  },
  "POST /v1/admin/passkeys/register/verify": async (c) => {
    const ctx = context(c);
    const { user, membership } = await identity(c, ctx);
    const input = await proofBody(c);
    const challenge = await ctx.store.consume(
      input.challengeId,
      "register",
      input.binding,
      user.id,
      membership.tenantId,
    );
    if (!challenge) throw refusal();
    let verified: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
    try {
      verified = await verifyRegistrationResponse({
        response: input.response as unknown as RegistrationResponseJSON,
        expectedChallenge: challenge.challenge,
        expectedOrigin: ctx.origin,
        expectedRPID: ctx.rpID,
        requireUserVerification: true,
        supportedAlgorithmIDs: [-7, -257],
      });
    } catch {
      throw refusal();
    }
    if (!verified.verified) throw refusal();
    const { credential } = verified.registrationInfo;
    const inserted = await ctx.store.insert({
      id: credential.id,
      user_id: user.id,
      tenant_id: membership.tenantId,
      user_handle: isoBase64URL.fromBuffer(await userHandle(user.id, membership.tenantId)),
      public_key: isoBase64URL.fromBuffer(credential.publicKey),
      counter: credential.counter,
      transports: JSON.stringify(credential.transports ?? []),
      name: input.name ?? "Passkey",
    });
    if (!inserted)
      throw new HttpError(409, "passkey_conflict", "Passkey already registered or limit reached");
    return c.json({ ok: true }, 201);
  },
  "GET /v1/admin/passkeys": async (c) => {
    const ctx = context(c);
    const { user, membership } = await identity(c, ctx);
    const rows = await ctx.store.list(user.id, membership.tenantId);
    return c.json({
      passkeys: rows.map((row) => ({
        id: row.id,
        name: row.name,
        createdAt: row.created_at,
        lastUsedAt: row.last_used_at,
      })),
    });
  },
  "DELETE /v1/admin/passkeys/:id": async (c) => {
    const ctx = context(c);
    const { user, membership } = await identity(c, ctx);
    await ctx.store.remove(c.req.param("id") ?? "", user.id, membership.tenantId);
    return c.json({ ok: true });
  },
};
