/**
 * The audio surface — `POST /v1/audio/{transcriptions,translations,speech}`
 * (issue #703).
 *
 * ## Why the deployed Worker, and not a handler unit test alone
 *
 * The premise of the issue is a GOVERNANCE hole: a voice application cannot use
 * FerroGate at all, so it dials the vendor directly and a whole workload class
 * leaves metering, guardrails and audit. Closing that means the three
 * operations have to be reachable on the SAME path a production request takes —
 * contract row, `contractAuth` guard, guardrail middleware, drain gate,
 * metering sink — not merely present in a router a test constructs by hand.
 * So the guard and transport legs below go through `SELF.fetch` →
 * `src/worker.ts` → `createGatewayApp`, against the committed `wrangler.toml`,
 * exactly as `test/inference/rerank.test.ts` does for the ninth operation.
 *
 * The `env.AI` double is the same device and for the same reason: the pool DOES
 * bind the real thing, but calling `.run()` on it offline throws `Binding AI
 * needs to be run remotely`. What the double cannot prove is Cloudflare's own
 * Whisper/MeloTTS wire behaviour; that is stated in the PR body rather than
 * papered over.
 *
 * ## Why the estimate/metering legs use the inner router instead
 *
 * Metering on the deployed Worker lands in D1 through `MeteringUsageSink`, and
 * asserting a duration there would be asserting the billing writer, not this
 * operation. `harness()` supplies the shipped `InMemoryUsageSink` on the same
 * `UsageSink` port the deployed sink implements.
 */
import { SELF, env } from "cloudflare:test";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  MAX_AUDIO_UPLOAD_BYTES,
  fetchDispatcher,
  setInferenceRequestScope,
  type PhysicalRoute,
  type TokenAdmissionHandle,
  type TokenGovernor,
} from "../../src/inference/index.js";
import { GUARDRAIL_OPERATIONS } from "../../src/guardrails/middleware.js";
import { CACHEABLE_OPERATION_IDS } from "../../src/middleware/response-cache.js";
import { DRAIN_GUARDED_OPERATION_IDS } from "../../src/routes/drain.js";
import { INFERENCE_OPERATION_IDS } from "../../src/routes/index.js";
import { FINGERPRINT_SECRET_REF, secretScanPolicy } from "../guardrails/fixtures.js";
import { ALL_ROUTES, errorBody, harness } from "./fixtures.js";
import { interceptProviderFetch, providerJson } from "./provider-mock.js";

const BASE = "https://gw.test";

const PROVIDERS = JSON.stringify([
  {
    name: "cf-ai",
    kind: "workers-ai",
    base_url: "https://api.cloudflare.com/client/v4/accounts/acct_placeholder/ai",
  },
]);

const MODELS = JSON.stringify([
  {
    name: "edge-whisper",
    provider: "cf-ai",
    provider_model: "@cf/openai/whisper-large-v3-turbo",
    capabilities: ["transcription"],
  },
  {
    name: "edge-tts",
    provider: "cf-ai",
    provider_model: "@cf/myshell-ai/melotts",
    capabilities: ["speech"],
  },
  // A CHAT model, declared with chat capabilities only. It exists so the
  // eligibility gate has something to refuse: an audio request must never be
  // quietly served by a text-generation model, which would answer prose where
  // the caller asked for a transcript or for audio bytes.
  {
    name: "edge-chat",
    provider: "cf-ai",
    provider_model: "@cf/meta/llama-3.1-8b-instruct",
    capabilities: ["chat", "streaming"],
  },
]);

const KEYS = JSON.stringify([
  // Empty scope set: every data-plane scope, no admin one.
  { key: "fg_audio", id: "key_audio", tenant_id: "tenant_a", scopes: [] },
  // Authenticated but holding an unrelated scope — must be 403 `scope_denied`.
  { key: "fg_audio_readonly", id: "key_ar", tenant_id: "tenant_a", scopes: ["skills.read"] },
]);

interface RecordedRun {
  readonly model: string;
  readonly input: Record<string, unknown>;
}

/** The recording double for `env.AI` (the slice the dispatcher uses). */
class RecordingAi {
  readonly runs: RecordedRun[] = [];
  #next: (model: string, input: Record<string, unknown>) => unknown = () => ({});

  answerWith(fn: (model: string, input: Record<string, unknown>) => unknown): void {
    this.#next = fn;
  }

  async run(model: string, input: Record<string, unknown>): Promise<unknown> {
    this.runs.push({ model, input });
    return this.#next(model, input);
  }
}

const ai = new RecordingAi();

const ORIGINAL: Record<string, unknown> = {};
const OVERRIDES: Record<string, unknown> = {
  GATEWAY_PROVIDERS: PROVIDERS,
  GATEWAY_MODELS: MODELS,
  GATEWAY_NATIVE_API_KEYS: KEYS,
  AI: ai,
  GATEWAY_GUARDRAIL_POLICIES: JSON.stringify([secretScanPolicy()]),
  [FINGERPRINT_SECRET_REF]: "test-fingerprint-key",
};

const mutable = env as unknown as Record<string, unknown>;

beforeAll(() => {
  for (const [name, value] of Object.entries(OVERRIDES)) {
    ORIGINAL[name] = mutable[name];
    mutable[name] = value;
  }
});

afterAll(() => {
  for (const [name, value] of Object.entries(ORIGINAL)) {
    mutable[name] = value;
  }
});

/** Count every outbound `fetch`, so "the binding served it" is provable. */
function countEgress(): { calls: () => number; restore: () => void } {
  const original = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls += 1;
    return await original(input as RequestInfo, init);
  }) as typeof fetch;
  return { calls: () => calls, restore: () => void (globalThis.fetch = original) };
}

let egress: ReturnType<typeof countEgress> | undefined;

afterEach(() => {
  egress?.restore();
  egress = undefined;
});

/** A tiny, deterministic "audio" payload. Whisper never sees it — the double does. */
function audioBytes(size = 8): Uint8Array {
  const bytes = new Uint8Array(size);
  for (let i = 0; i < size; i += 1) bytes[i] = i % 251;
  return bytes;
}

function upload(
  path: string,
  fields: Record<string, string>,
  file: Uint8Array | undefined = audioBytes(),
  key = "fg_audio",
): Promise<Response> {
  const form = new FormData();
  for (const [name, value] of Object.entries(fields)) form.append(name, value);
  if (file !== undefined) {
    form.append("file", new Blob([file as BlobPart], { type: "audio/wav" }), "clip.wav");
  }
  return SELF.fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { authorization: `Bearer ${key}` },
    body: form,
  });
}

function speech(body: unknown, key = "fg_audio"): Promise<Response> {
  return SELF.fetch(`${BASE}/v1/audio/speech`, {
    method: "POST",
    headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

// ---------------------------------------------------------------------------
// The three operations exist, are guarded, and sit on every shared control
// ---------------------------------------------------------------------------

describe("the audio surface is three guarded contract operations", () => {
  it("registers all three as inference operations", () => {
    expect([...INFERENCE_OPERATION_IDS]).toContain("createTranscription");
    expect([...INFERENCE_OPERATION_IDS]).toContain("createTranslation");
    expect([...INFERENCE_OPERATION_IDS]).toContain("createSpeech");
  });

  it("puts all three behind the drain gate — they dispatch, and they cost money", () => {
    for (const id of ["createTranscription", "createTranslation", "createSpeech"]) {
      expect(DRAIN_GUARDED_OPERATION_IDS).toContain(id);
    }
  });

  it("401s an unauthenticated caller on every one of them", async () => {
    for (const path of ["/v1/audio/transcriptions", "/v1/audio/translations"]) {
      const form = new FormData();
      form.append("model", "edge-whisper");
      form.append("file", new Blob([audioBytes() as BlobPart]), "clip.wav");
      const res = await SELF.fetch(`${BASE}${path}`, { method: "POST", body: form });
      expect(res.status, path).toBe(401);
      expect((await errorBody(res)).error.code).toBe("missing_api_key");
    }
    const res = await SELF.fetch(`${BASE}/v1/audio/speech`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "edge-tts", input: "hello" }),
    });
    expect(res.status).toBe(401);
  });

  it("403s a key holding an unrelated scope", async () => {
    const res = await upload(
      "/v1/audio/transcriptions",
      { model: "edge-whisper" },
      audioBytes(),
      "fg_audio_readonly",
    );
    expect(res.status).toBe(403);
    expect((await errorBody(res)).error.code).toBe("scope_denied");
  });

  it("400s an upload with no file part", async () => {
    const res = await upload("/v1/audio/transcriptions", { model: "edge-whisper" }, undefined);
    expect(res.status).toBe(400);
    expect((await errorBody(res)).error.code).toBe("invalid_request");
  });
});

// ---------------------------------------------------------------------------
// The size ceiling — the denial-of-service this surface would otherwise be
// ---------------------------------------------------------------------------

describe("an oversized upload is REFUSED, not buffered", () => {
  it("413s on the declared Content-Length before a single body byte is read", async () => {
    // A `ReadableStream` body that would hand over far more than the ceiling if
    // anything ever pulled from it. Nothing may: the declared length alone is
    // enough to refuse, and reading first is the denial-of-service.
    let pulled = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulled += 1;
        controller.enqueue(new Uint8Array(1024));
      },
    });
    const res = await SELF.fetch(`${BASE}/v1/audio/transcriptions`, {
      method: "POST",
      headers: {
        authorization: "Bearer fg_audio",
        "content-type": "multipart/form-data; boundary=x",
        "content-length": String(MAX_AUDIO_UPLOAD_BYTES + 1),
      },
      body,
      duplex: "half",
    } as RequestInit);

    expect(res.status).toBe(413);
    expect((await errorBody(res)).error.code).toBe("payload_too_large");
    expect(pulled).toBe(0);
  });

  it("413s a chunked upload that lies about its size, without buffering it whole", async () => {
    // No `content-length` at all — the case a hostile client actually uses. The
    // reader has to stop ON ITS OWN, so this counts the bytes the gateway was
    // willing to accept before refusing. `MAX_AUDIO_UPLOAD_BYTES` is the budget;
    // anything materially past it means the whole upload was materialized.
    const chunk = new Uint8Array(1024 * 1024);
    let served = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        served += chunk.byteLength;
        if (served > MAX_AUDIO_UPLOAD_BYTES * 4) {
          controller.close();
          return;
        }
        controller.enqueue(chunk);
      },
    });
    const res = await SELF.fetch(`${BASE}/v1/audio/transcriptions`, {
      method: "POST",
      headers: {
        authorization: "Bearer fg_audio",
        "content-type": "multipart/form-data; boundary=x",
      },
      body,
      duplex: "half",
    } as RequestInit);

    expect(res.status).toBe(413);
    expect((await errorBody(res)).error.code).toBe("payload_too_large");
    // The reader stopped near the ceiling instead of draining the stream. One
    // chunk of slack: the cap is checked after each chunk lands.
    expect(served).toBeLessThanOrEqual(MAX_AUDIO_UPLOAD_BYTES + chunk.byteLength);
  });
});

// ---------------------------------------------------------------------------
// Transport: Workers AI Whisper and MeloTTS, on the binding
// ---------------------------------------------------------------------------

describe("transcription is served by Workers AI Whisper", () => {
  it("runs Whisper on the binding and answers the OpenAI transcription shape", async () => {
    egress = countEgress();
    ai.answerWith(() => ({
      text: "hello from the edge",
      word_count: 4,
      segments: [
        { start: 0, end: 1.5, text: "hello from" },
        { start: 1.5, end: 3.25, text: "the edge" },
      ],
    }));

    const res = await upload("/v1/audio/transcriptions", { model: "edge-whisper" });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ text: "hello from the edge" });
    expect(ai.runs.at(-1)?.model).toBe("@cf/openai/whisper-large-v3-turbo");
    // Whisper's native run grammar: base64 audio, not a multipart part.
    expect(typeof ai.runs.at(-1)?.input["audio"]).toBe("string");
    expect(egress.calls()).toBe(0);
  });

  it("passes `translate` to the binding for /v1/audio/translations, and only there", async () => {
    ai.answerWith(() => ({ text: "hola" }));
    await upload("/v1/audio/translations", { model: "edge-whisper" });
    expect(ai.runs.at(-1)?.input["task"]).toBe("translate");

    await upload("/v1/audio/transcriptions", { model: "edge-whisper" });
    expect(ai.runs.at(-1)?.input["task"]).toBe("transcribe");
  });

  it("refuses to transcribe on a model that declares no transcription capability", async () => {
    egress = countEgress();
    const before = ai.runs.length;
    const res = await upload("/v1/audio/transcriptions", { model: "edge-chat" });
    expect(res.status).toBe(400);
    expect(ai.runs.length).toBe(before);
    expect(egress.calls()).toBe(0);
  });
});

describe("speech is served by Workers AI and returns BYTES", () => {
  const MP3 = new Uint8Array([0x49, 0x44, 0x33, 0x04, 0x00, 0xff, 0xfb, 0x90]);

  it("answers audio/mpeg bytes byte-for-byte, not a JSON envelope", async () => {
    egress = countEgress();
    // MeloTTS answers `{ audio: "<base64 mp3>" }`.
    ai.answerWith(() => ({ audio: btoa(String.fromCharCode(...MP3)) }));

    const res = await speech({ model: "edge-tts", input: "hello there" });

    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("audio/mpeg");
    expect(new Uint8Array(await res.arrayBuffer())).toEqual(MP3);
    expect(egress.calls()).toBe(0);
  });

  it("still answers an ERROR as the FerroGate envelope, not as bytes", async () => {
    // #733's line: a successful audio body passes through untouched, an error is
    // always the documented envelope. A binary surface that relayed an upstream
    // HTML error page as `audio/mpeg` would hand an SDK undecodable bytes at
    // exactly the moment it needs a code.
    ai.answerWith(() => {
      throw new Error("upstream exploded");
    });
    const res = await speech({ model: "edge-tts", input: "hello there" });
    expect(res.status).toBeGreaterThanOrEqual(500);
    expect(res.headers.get("content-type")).toContain("application/json");
    const body = await errorBody(res);
    expect(body.error.type).toBe("ferrogate_error");
    // The thrown message never reaches the client.
    expect(JSON.stringify(body)).not.toContain("exploded");
  });

  it("400s a speech request with no input to speak", async () => {
    const res = await speech({ model: "edge-tts", input: "" });
    expect(res.status).toBe(400);
    expect((await errorBody(res)).error.code).toBe("invalid_request");
  });
});

// ---------------------------------------------------------------------------
// Guardrails — stated honestly
// ---------------------------------------------------------------------------

describe("guardrails on the audio surface", () => {
  it("screens the TEXT a caller asks to be spoken", async () => {
    egress = countEgress();
    const before = ai.runs.length;
    const res = await speech({
      model: "edge-tts",
      input: "please read out FERROGATE-GUARDRAIL-PROBE",
    });
    expect(res.status).toBe(403);
    expect((await errorBody(res)).error.code).toBe("guardrail_blocked");
    // Refused BEFORE the provider was reached.
    expect(ai.runs.length).toBe(before);
    expect(egress.calls()).toBe(0);
  });

  it("does not block clean speech — the screening is the detector's, not the mount's", async () => {
    ai.answerWith(() => ({ audio: btoa("ok") }));
    const res = await speech({ model: "edge-tts", input: "the weather is fine" });
    expect(res.status).toBe(200);
  });

  /**
   * The honest half. An upload's body is opaque audio bytes and nothing in this
   * tree can read them, so `createTranscription`/`createTranslation` are
   * deliberately ABSENT from the binding table: a binding there would emit an
   * evidence row and a `guardrail_verdict` of `allowed` for content no detector
   * ever looked at — screening that is green and enforces nothing, which is the
   * exact shape of hole the table exists to make impossible.
   */
  it("claims NOTHING for the two upload operations", () => {
    expect(GUARDRAIL_OPERATIONS["createTranscription"]).toBeUndefined();
    expect(GUARDRAIL_OPERATIONS["createTranslation"]).toBeUndefined();
    expect(GUARDRAIL_OPERATIONS["createSpeech"]).toMatchObject({ protocol: "audio_speech" });
  });
});

// ---------------------------------------------------------------------------
// Metering — the units are seconds and characters, never invented tokens
// ---------------------------------------------------------------------------

const WHISPER_ROUTE: PhysicalRoute = {
  logicalModel: "whisper-model",
  provider: "cf-ai",
  providerModel: "@cf/openai/whisper-large-v3-turbo",
  providerKind: "workers-ai",
  baseUrl: "https://api.cloudflare.com/client/v4/accounts/acct_placeholder/ai",
  enabled: true,
  capabilities: ["transcription"],
  audioSecondPricePer1m: 100,
};

const TTS_ROUTE: PhysicalRoute = {
  logicalModel: "tts-model",
  provider: "cf-ai",
  providerModel: "@cf/myshell-ai/melotts",
  providerKind: "workers-ai",
  baseUrl: "https://api.cloudflare.com/client/v4/accounts/acct_placeholder/ai",
  enabled: true,
  capabilities: ["speech"],
  audioCharacterPricePer1m: 15,
};

const ROUTES: readonly PhysicalRoute[] = [...ALL_ROUTES, WHISPER_ROUTE, TTS_ROUTE];

function audioHarness(): ReturnType<typeof harness> {
  return harness({ dispatcher: fetchDispatcher }, ROUTES);
}

/** Cloudflare's REST envelope around Whisper's native answer. */
const REST_TRANSCRIPT = {
  result: {
    text: "hello",
    segments: [{ start: 0, end: 12.5, text: "hello" }],
  },
  success: true,
  errors: [],
  messages: [],
};

describe("the audio surface is metered on its own units", () => {
  it("records the DURATION the provider reported, and the route's audio price", async () => {
    const provider = interceptProviderFetch(() => providerJson(REST_TRANSCRIPT));
    try {
      const h = audioHarness();
      const form = new FormData();
      form.append("model", "whisper-model");
      form.append("file", new Blob([audioBytes(64) as BlobPart]), "clip.wav");
      const res = await h.router.request(`${BASE}/v1/audio/transcriptions`, {
        method: "POST",
        body: form,
      });

      expect(res.status).toBe(200);
      expect(h.usage.last).toMatchObject({
        route: "openai.audio.transcriptions",
        logicalModel: "whisper-model",
        provider: "cf-ai",
        providerModel: "@cf/openai/whisper-large-v3-turbo",
        status: 200,
        audioSeconds: 12.5,
        audioSecondPricePer1m: 100,
      });
      // NOT tokens. A token count on an operation that produced none would be a
      // number nobody measured, priced against a rate card that never saw it.
      expect(h.usage.last?.promptTokens).toBeUndefined();
      expect(h.usage.last?.totalTokens).toBeUndefined();
    } finally {
      provider.restore();
    }
  });

  it("leaves the duration ABSENT when the provider reported none", async () => {
    const provider = interceptProviderFetch(() =>
      providerJson({ result: { text: "hello" }, success: true, errors: [], messages: [] }),
    );
    try {
      const h = audioHarness();
      const form = new FormData();
      form.append("model", "whisper-model");
      form.append("file", new Blob([audioBytes(64) as BlobPart]), "clip.wav");
      const res = await h.router.request(`${BASE}/v1/audio/transcriptions`, {
        method: "POST",
        body: form,
      });
      expect(res.status).toBe(200);
      // Absent, never back-filled from the estimate: a number the provider did
      // not report must not be recorded as if it had been.
      expect(h.usage.last?.audioSeconds).toBeUndefined();
    } finally {
      provider.restore();
    }
  });

  it("records speech on CHARACTERS of input", async () => {
    const provider = interceptProviderFetch(() =>
      providerJson({
        result: { audio: btoa("mp3") },
        success: true,
        errors: [],
        messages: [],
      }),
    );
    try {
      const h = audioHarness();
      const res = await h.post("/v1/audio/speech", {
        model: "tts-model",
        input: "0123456789",
      });
      expect(res.status).toBe(200);
      expect(h.usage.last).toMatchObject({
        route: "openai.audio.speech",
        audioCharacters: 10,
        audioCharacterPricePer1m: 15,
      });
    } finally {
      provider.restore();
    }
  });
});

describe("the audio surface is rate-limited", () => {
  function spyGovernor(): { readonly admitted: number[]; readonly governor: TokenGovernor } {
    const admitted: number[] = [];
    return {
      admitted,
      governor: {
        admit: async (estimatedTokens: number): Promise<TokenAdmissionHandle | null> => {
          admitted.push(estimatedTokens);
          return null;
        },
        settle: async (): Promise<void> => {},
      },
    };
  }

  it("reserves the spoken characters against the TPM window", async () => {
    const spy = spyGovernor();
    const provider = interceptProviderFetch(() =>
      providerJson({ result: { audio: btoa("x") }, success: true, errors: [], messages: [] }),
    );
    try {
      const h = audioHarness();
      const request = new Request(`${BASE}/v1/audio/speech`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          model: "tts-model",
          input: "0123456789012345678901234567890123456789",
        }),
      });
      setInferenceRequestScope(request, { tokens: spy.governor });
      const res = await h.router.fetch(request);
      expect(res.status).toBe(200);
      // 40 characters at the tree's `chars/4` estimator. A reservation of 0
      // would let a caller drive unbounded synthesis past the window.
      expect(spy.admitted).toEqual([10]);
    } finally {
      provider.restore();
    }
  });

  it("refuses with the governor's status when the window is exhausted", async () => {
    const refusing: TokenGovernor = {
      admit: async () => ({
        status: 429,
        code: "tpm_limit_exceeded",
        message: "tokens-per-minute limit exceeded",
      }),
      settle: async (): Promise<void> => {},
    };
    const provider = interceptProviderFetch(() =>
      providerJson({ result: { audio: btoa("x") }, success: true, errors: [], messages: [] }),
    );
    try {
      const h = audioHarness();
      const request = new Request(`${BASE}/v1/audio/speech`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "tts-model", input: "hello" }),
      });
      setInferenceRequestScope(request, { tokens: refusing });
      const res = await h.router.fetch(request);
      expect(res.status).toBe(429);
      expect((await errorBody(res)).error.code).toBe("tpm_limit_exceeded");
      // Refused BEFORE the upstream was dialled.
      expect(provider.requests).toHaveLength(0);
    } finally {
      provider.restore();
    }
  });
});

describe("the response cache", () => {
  /**
   * Speech is cacheable; the two uploads are not, and the asymmetry is the
   * argument. Synthesizing the same sentence twice is the single most
   * repeat-prone AI call there is and its key is a small JSON body. A
   * transcription's key would be the AUDIO — up to `MAX_AUDIO_UPLOAD_BYTES`
   * hashed on every request, for a corpus of one-shot uploads that essentially
   * never repeat.
   */
  it("caches speech and never the uploads", () => {
    expect(CACHEABLE_OPERATION_IDS.has("createSpeech")).toBe(true);
    expect(CACHEABLE_OPERATION_IDS.has("createTranscription")).toBe(false);
    expect(CACHEABLE_OPERATION_IDS.has("createTranslation")).toBe(false);
  });
});
