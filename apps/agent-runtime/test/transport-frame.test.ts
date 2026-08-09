/**
 * The self-hosted worker TRANSPORT layer: the sealed AEAD frame and the
 * verified-mutual-TLS channel.
 *
 * Two things are asserted here, and they are different in kind.
 *
 * 1. **PARITY.** Rust's own `SelfHostedWorkerTransportFrame` — XChaCha20-Poly1305
 *    over a `\n`-joined AAD under an HKDF-SHA256 key — is opened by this gateway
 *    byte for byte, so an unmodified Rust worker binary interoperates. That is
 *    the marker that was closed, and the gate for it drives a Rust-shaped frame
 *    through the REAL Worker via `SELF`.
 * 2. **APPROXIMATION BOUNDARY.** An in-process mTLS server still cannot exist on
 *    Workers, so the sharpened PORT-TODO on `middleware/auth.ts` stays, and the
 *    boundary it names is pinned: an absent `request.cf` fails CLOSED.
 */
import { SELF, env } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  admitTransport,
  resolveTransportChannel,
  transportChannel,
  verifiedMutualTls,
} from "../src/middleware/auth.js";
import {
  AES_GCM_NONCE_BYTES,
  RUST_FRAME_ALGORITHM,
  RUST_FRAME_ENCODING,
  RUST_FRAME_HKDF_INFO,
  RUST_FRAME_HKDF_SALT,
  RUST_FRAME_SECRET_MIN_LEN,
  type WorkerFrameHeader,
  XCHACHA20_NONCE_BYTES,
  deriveFrameKey,
  deriveRustFrameKey,
  frameAssociatedData,
  frameIdentityMismatch,
  openWorkerFrame,
  readRustTransportFrame,
  readSealedFrame,
  rustFrameAssociatedData,
  sealRustWorkerFrame,
  sealWorkerFrame,
  toRustTransportFrame,
} from "../src/workers/frame.js";
import { xchacha20poly1305Open } from "../src/workers/xchacha20poly1305.js";
import {
  BASE,
  TENANT_A_KEY,
  WORKER_A,
  WORKER_B,
  bearer,
  getEnvVar,
  setEnvVar,
  workerEnvelopeFor,
  workerHeaders,
} from "./fixtures.js";

const HEARTBEAT = "/v1/self-hosted-workers/heartbeat";

interface WorkerIdentityFixture {
  readonly tenant_id: string;
  readonly workspace_id: string;
  readonly worker_id: string;
  readonly token_id: string;
  readonly token_secret: string;
}

function headerFor(identity: WorkerIdentityFixture): WorkerFrameHeader {
  return {
    protocol_version: 1,
    tenant_id: identity.tenant_id,
    workspace_id: identity.workspace_id,
    worker_id: identity.worker_id,
    token_id: identity.token_id,
  };
}

async function postRaw(body: unknown, headers: Record<string, string>): Promise<Response> {
  return await SELF.fetch(`${BASE}${HEARTBEAT}`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}

/** A request carrying an edge-supplied `cf.tlsClientAuth` blob. */
function requestWithTls(tls: Record<string, string> | undefined, marker = "mutual_tls"): Request {
  const request = new Request(`${BASE}${HEARTBEAT}`, {
    method: "POST",
    headers: { "x-ferrogate-transport-security": marker },
  });
  // `cf` is populated by the EDGE, never by application code, so there is no
  // constructor path for it. Defining it here is the test standing in for the
  // edge — the production code still only ever READS it.
  Object.defineProperty(request, "cf", {
    value: tls === undefined ? undefined : { tlsClientAuth: tls },
    configurable: true,
  });
  return request;
}

// ---------------------------------------------------------------------------
// The frame, as pure crypto
// ---------------------------------------------------------------------------

describe("sealed transport frame — crypto", () => {
  const header = headerFor(WORKER_A);

  it("seals and opens a document round trip", async () => {
    const frame = await sealWorkerFrame(header, WORKER_A.token_secret, { hello: "world" });
    const opened = await openWorkerFrame(frame, WORKER_A.token_secret);
    expect(opened.outcome).toBe("opened");
    expect(opened.outcome === "opened" && opened.envelope).toEqual({ hello: "world" });
  });

  it("uses a 12-byte AES-GCM nonce, freshly random per seal", async () => {
    const first = await sealWorkerFrame(header, WORKER_A.token_secret, { n: 1 });
    const second = await sealWorkerFrame(header, WORKER_A.token_secret, { n: 1 });
    expect(atob(first.nonce).length).toBe(AES_GCM_NONCE_BYTES);
    expect(first.nonce).not.toBe(second.nonce);
    // Same plaintext, same key, different nonce ⇒ different ciphertext.
    expect(first.ciphertext).not.toBe(second.ciphertext);
  });

  it("REFUSES a frame sealed under a different worker's secret", async () => {
    const frame = await sealWorkerFrame(header, WORKER_A.token_secret, { hello: "world" });
    const opened = await openWorkerFrame(frame, WORKER_B.token_secret);
    expect(opened.outcome).toBe("rejected");
    expect(opened.outcome === "rejected" && opened.failure.reason).toBe("unopenable");
  });

  it("binds the header as associated data — a swapped header breaks the tag", async () => {
    const frame = await sealWorkerFrame(header, WORKER_A.token_secret, { hello: "world" });
    const tampered = { ...frame, header: { ...header, worker_id: "worker-z" } };
    const opened = await openWorkerFrame(tampered, WORKER_A.token_secret);
    expect(opened.outcome).toBe("rejected");
  });

  it("binds EVERY header field, not just one", async () => {
    const frame = await sealWorkerFrame(header, WORKER_A.token_secret, { hello: "world" });
    for (const field of ["tenant_id", "workspace_id", "worker_id", "token_id"] as const) {
      const tampered = { ...frame, header: { ...header, [field]: "mutated" } };
      expect((await openWorkerFrame(tampered, WORKER_A.token_secret)).outcome).toBe("rejected");
    }
    const versionTampered = { ...frame, header: { ...header, protocol_version: 2 } };
    expect((await openWorkerFrame(versionTampered, WORKER_A.token_secret)).outcome).toBe(
      "rejected",
    );
  });

  it("REFUSES a flipped ciphertext bit", async () => {
    const frame = await sealWorkerFrame(header, WORKER_A.token_secret, { hello: "world" });
    const raw = atob(frame.ciphertext);
    const flipped = String.fromCharCode(raw.charCodeAt(0) ^ 0x01) + raw.slice(1);
    const opened = await openWorkerFrame(
      { ...frame, ciphertext: btoa(flipped) },
      WORKER_A.token_secret,
    );
    expect(opened.outcome).toBe("rejected");
  });

  it("REFUSES a 24-byte XChaCha20 nonce with the platform reason, never truncating it", async () => {
    const frame = await sealWorkerFrame(header, WORKER_A.token_secret, { hello: "world" });
    // `\0` as the ESCAPE, never the raw byte: a literal NUL makes this file
    // binary to git and grep and drops it out of every diff and search
    // (`apps/gateway/test/source-nul-bytes.test.ts`, issue #736).
    const wide = btoa("\0".repeat(XCHACHA20_NONCE_BYTES));
    const opened = await openWorkerFrame({ ...frame, nonce: wide }, WORKER_A.token_secret);
    expect(opened.outcome).toBe("rejected");
    expect(opened.outcome === "rejected" && opened.failure.reason).toBe("invalid_shape");
    expect(opened.outcome === "rejected" && opened.failure.detail).toContain("XChaCha20");
  });

  it("REFUSES any other nonce length", async () => {
    const frame = await sealWorkerFrame(header, WORKER_A.token_secret, { hello: "world" });
    const opened = await openWorkerFrame({ ...frame, nonce: btoa("short") }, WORKER_A.token_secret);
    expect(opened.outcome === "rejected" && opened.failure.reason).toBe("invalid_shape");
  });

  it("REFUSES non-base64 fields before touching a key", async () => {
    const opened = await openWorkerFrame(
      { header, nonce: "!!!not base64!!!", ciphertext: "also not" },
      WORKER_A.token_secret,
    );
    expect(opened.outcome === "rejected" && opened.failure.reason).toBe("invalid_shape");
  });

  it("gives every unopenable frame the SAME opaque detail — no oracle", async () => {
    const frame = await sealWorkerFrame(header, WORKER_A.token_secret, { hello: "world" });
    const wrongKey = await openWorkerFrame(frame, WORKER_B.token_secret);
    const tampered = await openWorkerFrame(
      { ...frame, header: { ...header, token_id: "other" } },
      WORKER_A.token_secret,
    );
    expect(wrongKey.outcome === "rejected" && wrongKey.failure.detail).toBe(
      tampered.outcome === "rejected" ? tampered.failure.detail : "different",
    );
  });

  it("REFUSES a sealed non-object payload", async () => {
    const frame = await sealWorkerFrame(header, WORKER_A.token_secret, ["not", "an", "object"]);
    expect((await openWorkerFrame(frame, WORKER_A.token_secret)).outcome).toBe("rejected");
  });

  it("derives a DIFFERENT key per transport secret", async () => {
    const a = await deriveFrameKey(WORKER_A.token_secret);
    const b = await deriveFrameKey(WORKER_B.token_secret);
    const nonce = new Uint8Array(AES_GCM_NONCE_BYTES);
    const aad = frameAssociatedData(header);
    const sealed = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aad },
      a,
      new TextEncoder().encode("x"),
    );
    await expect(
      crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, b, sealed),
    ).rejects.toThrow();
  });

  it("length-prefixes the AAD so field boundaries cannot be shifted", () => {
    const left = frameAssociatedData({ ...header, tenant_id: "a|b", workspace_id: "c" });
    const right = frameAssociatedData({ ...header, tenant_id: "a", workspace_id: "b|c" });
    expect(new TextDecoder().decode(left)).not.toBe(new TextDecoder().decode(right));
  });
});

describe("sealed frame recognition", () => {
  it("recognizes a well-formed frame", async () => {
    const frame = await sealWorkerFrame(headerFor(WORKER_A), WORKER_A.token_secret, { a: 1 });
    expect(readSealedFrame({ sealed: frame })).toBeDefined();
  });

  it("does NOT reinterpret a cleartext identity body as a frame", () => {
    expect(readSealedFrame(workerEnvelopeFor(HEARTBEAT))).toBeUndefined();
  });

  it("refuses a partial frame rather than half-decoding it", async () => {
    const frame = await sealWorkerFrame(headerFor(WORKER_A), WORKER_A.token_secret, { a: 1 });
    expect(readSealedFrame({ sealed: { ...frame, nonce: undefined } })).toBeUndefined();
    expect(readSealedFrame({ sealed: { ...frame, header: undefined } })).toBeUndefined();
    expect(
      readSealedFrame({ sealed: { ...frame, header: { ...frame.header, token_id: "  " } } }),
    ).toBeUndefined();
    expect(
      readSealedFrame({
        sealed: { ...frame, header: { ...frame.header, protocol_version: "1" } },
      }),
    ).toBeUndefined();
    expect(readSealedFrame({ sealed: [frame] })).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// The frame, end to end through the real Worker
// ---------------------------------------------------------------------------

describe("sealed frame — through SELF", () => {
  it("ADMITS a correctly sealed heartbeat and reads the unsealed payload", async () => {
    const document = workerEnvelopeFor(HEARTBEAT, WORKER_A);
    const frame = await sealWorkerFrame(headerFor(WORKER_A), WORKER_A.token_secret, document);

    const response = await postRaw({ sealed: frame }, workerHeaders("symmetric_aead"));
    expect(response.status).toBe(201);
    const json = (await response.json()) as Record<string, unknown>;
    const heartbeat = json.heartbeat as Record<string, unknown>;
    // The fields under assertion existed ONLY inside the ciphertext.
    expect(heartbeat.status).toBe("idle");
    expect(heartbeat.reported_at_unix).toBe(1_800_000_000);
    expect(heartbeat.worker_id).toBe(WORKER_A.worker_id);
  });

  it("REFUSES a frame sealed with the wrong secret — 401, not 400", async () => {
    const document = workerEnvelopeFor(HEARTBEAT, WORKER_A);
    // Header claims worker A; the seal used worker B's secret.
    const frame = await sealWorkerFrame(headerFor(WORKER_A), WORKER_B.token_secret, document);
    const response = await postRaw({ sealed: frame }, workerHeaders("symmetric_aead"));
    expect(response.status).toBe(401);
    const json = (await response.json()) as { error?: { code?: string } };
    expect(json.error?.code).toBe("invalid_self_hosted_worker_identity");
  });

  it("REFUSES a frame whose header names an unregistered worker, with the same 401", async () => {
    const ghost = { ...WORKER_A, worker_id: "worker-ghost" };
    const frame = await sealWorkerFrame(headerFor(ghost), WORKER_A.token_secret, {});
    const response = await postRaw({ sealed: frame }, workerHeaders("symmetric_aead"));
    expect(response.status).toBe(401);
  });

  it("REFUSES a frame whose header carries the wrong token_id", async () => {
    const frame = await sealWorkerFrame(
      { ...headerFor(WORKER_A), token_id: "tok-wrong" },
      WORKER_A.token_secret,
      workerEnvelopeFor(HEARTBEAT, WORKER_A),
    );
    expect((await postRaw({ sealed: frame }, workerHeaders("symmetric_aead"))).status).toBe(401);
  });

  it("REFUSES an opened frame whose INNER identity does not match the registry", async () => {
    // The seal is valid for worker A, but the payload claims a bad secret —
    // opening a frame is not an authorization, so validate() still refuses.
    const document = {
      protocol_version: 1,
      identity: { ...WORKER_A, token_secret: "0".repeat(64) },
      status: "idle",
      reported_at_unix: 1_800_000_000,
    };
    const frame = await sealWorkerFrame(headerFor(WORKER_A), WORKER_A.token_secret, document);
    const response = await postRaw({ sealed: frame }, workerHeaders("symmetric_aead"));
    expect(response.status).toBe(401);
  });

  it("REFUSES a sealed frame presented on the mutual_tls marker channel", async () => {
    const frame = await sealWorkerFrame(
      headerFor(WORKER_A),
      WORKER_A.token_secret,
      workerEnvelopeFor(HEARTBEAT, WORKER_A),
    );
    const response = await postRaw({ sealed: frame }, workerHeaders("mutual_tls"));
    expect(response.status).toBe(400);
    const json = (await response.json()) as { error?: { code?: string } };
    expect(json.error?.code).toBe("invalid_self_hosted_worker_transport");
  });

  it("keeps the CLEARTEXT marker path working (Rust supports both)", async () => {
    const response = await postRaw(
      workerEnvelopeFor(HEARTBEAT, WORKER_A),
      workerHeaders("symmetric_aead"),
    );
    expect(response.status).toBe(201);
  });

  it("a TENANT bearer key still cannot reach the sealed path", async () => {
    const frame = await sealWorkerFrame(
      headerFor(WORKER_A),
      WORKER_A.token_secret,
      workerEnvelopeFor(HEARTBEAT, WORKER_A),
    );
    // No transport-security marker — a tenant key never has one.
    const response = await postRaw({ sealed: frame }, bearer(TENANT_A_KEY));
    expect(response.status).toBe(401);
    const json = (await response.json()) as { error?: { code?: string } };
    expect(json.error?.code).toBe("invalid_self_hosted_worker_transport_security");
  });
});

// ---------------------------------------------------------------------------
// Rust's own wire format — the closed marker
// ---------------------------------------------------------------------------

describe("Rust SelfHostedWorkerTransportFrame — wire parity", () => {
  const header = headerFor(WORKER_A);

  it("pins the Rust constants that the two peers must agree on byte for byte", () => {
    // Quoted from `crates/ferrogate-runtime/src/self_hosted_worker.rs`. Every
    // one of these is a value where a single differing character means every
    // Rust-emitted frame silently fails to open, so each is asserted literally
    // rather than left to a round-trip that would agree with itself.
    expect(RUST_FRAME_ALGORITHM).toBe("xchacha20poly1305");
    expect(RUST_FRAME_ENCODING).toBe("encrypted_json");
    expect(RUST_FRAME_HKDF_SALT).toBe("ferrogate/self-hosted-worker/transport-aead");
    expect(RUST_FRAME_HKDF_INFO).toBe("ferrogate-self-hosted-worker-transport-v1");
    expect(RUST_FRAME_SECRET_MIN_LEN).toBe(32);
  });

  it("computes Rust's associated data — the five routing fields joined by \\n", () => {
    expect(new TextDecoder().decode(rustFrameAssociatedData(header))).toBe(
      `1\n${WORKER_A.tenant_id}\n${WORKER_A.workspace_id}\n${WORKER_A.worker_id}\n${WORKER_A.token_id}`,
    );
    // And it is NOT this port's own AAD: using the wrong one is precisely the
    // bug that would make every real Rust frame look like a bad credential.
    expect(new TextDecoder().decode(rustFrameAssociatedData(header))).not.toBe(
      new TextDecoder().decode(frameAssociatedData(header)),
    );
  });

  it("emits Rust's document shape, and reads back exactly what it emitted", async () => {
    const frame = await sealRustWorkerFrame(header, WORKER_A.token_secret, { hello: "world" });
    const wire = toRustTransportFrame(frame);
    expect(wire).toMatchObject({
      protocol_version: 1,
      tenant_id: WORKER_A.tenant_id,
      workspace_id: WORKER_A.workspace_id,
      worker_id: WORKER_A.worker_id,
      token_id: WORKER_A.token_id,
      encoding: "encrypted_json",
      encrypted_payload: { algorithm: "xchacha20poly1305" },
    });
    const read = readRustTransportFrame(wire);
    expect(read?.format).toBe("xchacha20poly1305");
    expect(atob((read as NonNullable<typeof read>).nonce).length).toBe(XCHACHA20_NONCE_BYTES);
    const opened = await openWorkerFrame(read as NonNullable<typeof read>, WORKER_A.token_secret);
    expect(opened.outcome === "opened" && opened.envelope).toEqual({ hello: "world" });
  });

  it("opens under the RAW XChaCha20-Poly1305 primitive with Rust's key schedule", async () => {
    // Decrypt the frame WITHOUT going through `openWorkerFrame` at all: derive
    // the key from the documented HKDF inputs and call the cipher directly. If
    // the frame codec ever quietly changed cipher, AAD or key schedule, this
    // independent path stops producing the plaintext.
    const frame = await sealRustWorkerFrame(header, WORKER_A.token_secret, { n: 7 });
    const key = await deriveRustFrameKey(WORKER_A.token_secret);
    const nonce = Uint8Array.from(atob(frame.nonce), (ch) => ch.charCodeAt(0));
    const sealed = Uint8Array.from(atob(frame.ciphertext), (ch) => ch.charCodeAt(0));
    const plaintext = xchacha20poly1305Open(key, nonce, sealed, rustFrameAssociatedData(header));
    expect(JSON.parse(new TextDecoder().decode(plaintext))).toEqual({ n: 7 });
  });

  it("derives the key from the transport secret ALONE — a wrong secret opens nothing", async () => {
    const frame = await sealRustWorkerFrame(header, WORKER_A.token_secret, { hello: "world" });
    const opened = await openWorkerFrame(frame, WORKER_B.token_secret);
    expect(opened.outcome === "rejected" && opened.failure.reason).toBe("unopenable");
  });

  it("binds EVERY routing field as associated data", async () => {
    const frame = await sealRustWorkerFrame(header, WORKER_A.token_secret, { hello: "world" });
    for (const field of ["tenant_id", "workspace_id", "worker_id", "token_id"] as const) {
      const tampered = { ...frame, header: { ...header, [field]: "mutated" } };
      expect((await openWorkerFrame(tampered, WORKER_A.token_secret)).outcome).toBe("rejected");
    }
    const version = { ...frame, header: { ...header, protocol_version: 2 } };
    expect((await openWorkerFrame(version, WORKER_A.token_secret)).outcome).toBe("rejected");
  });

  it("REFUSES a flipped ciphertext bit", async () => {
    const frame = await sealRustWorkerFrame(header, WORKER_A.token_secret, { hello: "world" });
    const raw = atob(frame.ciphertext);
    const flipped = String.fromCharCode(raw.charCodeAt(0) ^ 0x01) + raw.slice(1);
    const opened = await openWorkerFrame(
      { ...frame, ciphertext: btoa(flipped) },
      WORKER_A.token_secret,
    );
    expect(opened.outcome === "rejected" && opened.failure.reason).toBe("unopenable");
  });

  it("REFUSES a nonce that is not 24 bytes under this format", async () => {
    const frame = await sealRustWorkerFrame(header, WORKER_A.token_secret, { hello: "world" });
    const opened = await openWorkerFrame(
      { ...frame, nonce: btoa("x".repeat(12)) },
      WORKER_A.token_secret,
    );
    expect(opened.outcome === "rejected" && opened.failure.reason).toBe("invalid_shape");
    expect(opened.outcome === "rejected" && opened.failure.detail).toContain("24 bytes");
  });

  it("REFUSES to key the cipher with a secret below Rust's 32-character floor", async () => {
    await expect(sealRustWorkerFrame(header, "short", {})).rejects.toThrow(/at least 32/);
    // ...and on the OPEN side the refusal is opaque, because the length of a
    // registered secret is registry state the caller must not be able to probe.
    const frame = await sealRustWorkerFrame(header, WORKER_A.token_secret, {});
    const opened = await openWorkerFrame(frame, "short");
    expect(opened.outcome === "rejected" && opened.failure.reason).toBe("unopenable");
  });

  it("does NOT accept an unknown algorithm or encoding tag as this format", async () => {
    const frame = await sealRustWorkerFrame(header, WORKER_A.token_secret, { hello: "world" });
    const wire = toRustTransportFrame(frame) as Record<string, unknown>;
    expect(
      readRustTransportFrame({
        ...wire,
        encrypted_payload: { ...(wire.encrypted_payload as object), algorithm: "aes256gcm" },
      }),
    ).toBeUndefined();
    expect(readRustTransportFrame({ ...wire, encoding: "cleartext_json" })).toBeUndefined();
    expect(readRustTransportFrame({ ...wire, encrypted_payload: undefined })).toBeUndefined();
  });

  it("does NOT reinterpret a CLEARTEXT identity body as a Rust frame", () => {
    expect(readRustTransportFrame(workerEnvelopeFor(HEARTBEAT))).toBeUndefined();
    expect(readSealedFrame(workerEnvelopeFor(HEARTBEAT))).toBeUndefined();
  });

  it("keeps the two formats non-interchangeable — a relabelled frame opens nothing", async () => {
    const gcm = await sealWorkerFrame(header, WORKER_A.token_secret, { hello: "world" });
    const asRust = { ...gcm, format: "xchacha20poly1305" as const };
    expect((await openWorkerFrame(asRust, WORKER_A.token_secret)).outcome).toBe("rejected");

    const xchacha = await sealRustWorkerFrame(header, WORKER_A.token_secret, { hello: "world" });
    const asGcm = { ...xchacha, format: "aes_gcm" as const };
    expect((await openWorkerFrame(asGcm, WORKER_A.token_secret)).outcome).toBe("rejected");
  });

  it("Rust's `validate_identity`: the header must equal the enclosed identity", () => {
    expect(frameIdentityMismatch(header, { ...WORKER_A })).toBeNull();
    expect(frameIdentityMismatch(header, { ...WORKER_A, worker_id: "worker-z" })).toBe("worker_id");
    expect(frameIdentityMismatch(header, { ...WORKER_A, token_id: "tok-z" })).toBe("token_id");
    expect(frameIdentityMismatch(header, {})).toBe("tenant_id");
  });
});

describe("MOUNT GATE — a Rust-format frame through the REAL Worker", () => {
  it("ADMITS a Rust XChaCha20-Poly1305 heartbeat and reads the ciphertext-only payload", async () => {
    // The ONLY thing on the wire is Rust's document. If `readSealedFrame` stops
    // recognizing that shape, this body has no top-level `identity` and the
    // request becomes a 400 — there is no fallback that could keep it green.
    const document = workerEnvelopeFor(HEARTBEAT, WORKER_A);
    const frame = await sealRustWorkerFrame(headerFor(WORKER_A), WORKER_A.token_secret, document);

    const response = await postRaw(toRustTransportFrame(frame), workerHeaders("symmetric_aead"));
    expect(response.status).toBe(201);
    const json = (await response.json()) as Record<string, unknown>;
    const heartbeat = json.heartbeat as Record<string, unknown>;
    // These fields existed ONLY inside the XChaCha20 ciphertext.
    expect(heartbeat.status).toBe("idle");
    expect(heartbeat.reported_at_unix).toBe(1_800_000_000);
    expect(heartbeat.worker_id).toBe(WORKER_A.worker_id);
  });

  it("REFUSES a Rust frame sealed with the wrong worker's secret — 401", async () => {
    const document = workerEnvelopeFor(HEARTBEAT, WORKER_A);
    const frame = await sealRustWorkerFrame(headerFor(WORKER_A), WORKER_B.token_secret, document);
    const response = await postRaw(toRustTransportFrame(frame), workerHeaders("symmetric_aead"));
    expect(response.status).toBe(401);
    const json = (await response.json()) as { error?: { code?: string } };
    expect(json.error?.code).toBe("invalid_self_hosted_worker_identity");
  });

  it("REFUSES a Rust frame whose header disagrees with the enclosed identity — 400", async () => {
    // Header and seal are worker A's; the enclosed identity claims worker B's
    // worker_id. Rust `validate_identity` refuses this as a transport error, so
    // a frame can never be authorized by one row and attributed to another.
    const document = {
      ...workerEnvelopeFor(HEARTBEAT, WORKER_A),
      identity: { ...WORKER_A, worker_id: "worker-b" },
    };
    const frame = await sealRustWorkerFrame(headerFor(WORKER_A), WORKER_A.token_secret, document);
    const response = await postRaw(toRustTransportFrame(frame), workerHeaders("symmetric_aead"));
    expect(response.status).toBe(400);
    const json = (await response.json()) as { error?: { code?: string; message?: string } };
    expect(json.error?.code).toBe("invalid_self_hosted_worker_transport");
    expect(json.error?.message).toContain("does not match enclosed request");
  });

  it("REFUSES a Rust frame on the mutual_tls marker channel", async () => {
    const frame = await sealRustWorkerFrame(
      headerFor(WORKER_A),
      WORKER_A.token_secret,
      workerEnvelopeFor(HEARTBEAT, WORKER_A),
    );
    const response = await postRaw(toRustTransportFrame(frame), workerHeaders("mutual_tls"));
    expect(response.status).toBe(400);
  });

  it("a TENANT bearer key cannot reach the Rust sealed path either", async () => {
    const frame = await sealRustWorkerFrame(
      headerFor(WORKER_A),
      WORKER_A.token_secret,
      workerEnvelopeFor(HEARTBEAT, WORKER_A),
    );
    const response = await postRaw(toRustTransportFrame(frame), bearer(TENANT_A_KEY));
    expect(response.status).toBe(401);
    const json = (await response.json()) as { error?: { code?: string } };
    expect(json.error?.code).toBe("invalid_self_hosted_worker_transport_security");
  });
});

// ---------------------------------------------------------------------------
// Verified mutual TLS
// ---------------------------------------------------------------------------

describe("verified mutual TLS (request.cf.tlsClientAuth)", () => {
  it("is TRUE only for a presented, verified, unrevoked certificate", () => {
    expect(
      verifiedMutualTls(
        requestWithTls({ certPresented: "1", certVerified: "SUCCESS", certRevoked: "0" }),
      ),
    ).toBe(true);
  });

  it("is FALSE when no certificate was presented", () => {
    expect(
      verifiedMutualTls(
        requestWithTls({ certPresented: "0", certVerified: "NONE", certRevoked: "0" }),
      ),
    ).toBe(false);
  });

  it("is FALSE when the chain did not verify", () => {
    for (const verdict of ["FAILED", "NONE", "CERT_EXPIRED", "CERT_NOT_YET_VALID"]) {
      expect(
        verifiedMutualTls(
          requestWithTls({ certPresented: "1", certVerified: verdict, certRevoked: "0" }),
        ),
      ).toBe(false);
    }
  });

  it("is FALSE for a REVOKED certificate even though certVerified says SUCCESS", () => {
    // Cloudflare reports SUCCESS + certRevoked=1 for a revoked-but-valid chain.
    // Checking only certVerified would admit it.
    expect(
      verifiedMutualTls(
        requestWithTls({ certPresented: "1", certVerified: "SUCCESS", certRevoked: "1" }),
      ),
    ).toBe(false);
  });

  it("is FALSE when the edge supplied no tlsClientAuth at all — the local case", () => {
    expect(verifiedMutualTls(requestWithTls(undefined))).toBe(false);
    expect(verifiedMutualTls(new Request(`${BASE}${HEARTBEAT}`))).toBe(false);
  });

  it("upgrades the mutual_tls MARKER to the verified channel, and nothing else", () => {
    const verified = { certPresented: "1", certVerified: "SUCCESS", certRevoked: "0" };
    expect(resolveTransportChannel(requestWithTls(verified, "mutual_tls"))).toBe(
      "verified_mutual_tls",
    );
    // A declared downgrade is NEVER promoted, even over real mTLS.
    expect(resolveTransportChannel(requestWithTls(verified, "symmetric_aead"))).toBe(
      "symmetric_aead",
    );
    // No marker at all is still no channel.
    expect(resolveTransportChannel(requestWithTls(verified, "nonsense"))).toBeNull();
  });

  it("leaves the marker unverified when the edge did not verify", () => {
    expect(
      resolveTransportChannel(
        requestWithTls({ certPresented: "1", certVerified: "FAILED", certRevoked: "0" }),
      ),
    ).toBe("unverified_mutual_tls_marker");
    expect(transportChannel(new Headers({ "x-ferrogate-transport-security": "mutual_tls" }))).toBe(
      "unverified_mutual_tls_marker",
    );
  });

  it("ADMITS the verified channel under the production posture", () => {
    expect(admitTransport("require_production_mtls", "verified_mutual_tls")).toBeNull();
    // ...while the two claims it replaces stay refused.
    expect(admitTransport("require_production_mtls", "unverified_mutual_tls_marker")?.status).toBe(
      501,
    );
    expect(admitTransport("require_production_mtls", "symmetric_aead")?.status).toBe(403);
  });
});

describe("production posture, end to end", () => {
  let previous: string | undefined;

  beforeEach(() => {
    previous = getEnvVar("FG_REQUIRE_PRODUCTION_MTLS");
    setEnvVar("FG_REQUIRE_PRODUCTION_MTLS", "1");
  });

  afterEach(() => {
    setEnvVar("FG_REQUIRE_PRODUCTION_MTLS", previous);
  });

  it("fails CLOSED locally — no edge mTLS means no verified channel", async () => {
    // `request.cf` is absent under the offline pool and `wrangler dev --local`,
    // which is precisely the boundary the sharpened marker records.
    const marker = await postRaw(
      workerEnvelopeFor(HEARTBEAT, WORKER_A),
      workerHeaders("mutual_tls"),
    );
    expect(marker.status).toBe(501);

    const aead = await postRaw(
      workerEnvelopeFor(HEARTBEAT, WORKER_A),
      workerHeaders("symmetric_aead"),
    );
    expect(aead.status).toBe(403);
  });

  it("the sealed frame is ALSO refused under the production posture", async () => {
    const frame = await sealWorkerFrame(
      headerFor(WORKER_A),
      WORKER_A.token_secret,
      workerEnvelopeFor(HEARTBEAT, WORKER_A),
    );
    // The seal is confidentiality, not a transport upgrade: `symmetric_aead`
    // remains a declared downgrade and is refused before the frame is opened.
    expect((await postRaw({ sealed: frame }, workerHeaders("symmetric_aead"))).status).toBe(403);
  });

  it("restores the marker contract when the posture is turned back off", async () => {
    setEnvVar("FG_REQUIRE_PRODUCTION_MTLS", "0");
    expect(env).toBeDefined();
    const response = await postRaw(
      workerEnvelopeFor(HEARTBEAT, WORKER_A),
      workerHeaders("mutual_tls"),
    );
    expect(response.status).toBe(201);
  });
});
